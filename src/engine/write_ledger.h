// Write ledger: page-granular dirty
// tracking over the snapshot's memory regions. The mem-write hook feeds
// on_write; the exit-time dump pipeline reads the dirty regions back for
// the original-bytes export. Construct-injected, hot path allocation-free.

#ifndef SHELLER_ENGINE_WRITE_LEDGER_H
#define SHELLER_ENGINE_WRITE_LEDGER_H

#include "mem_region_map.h" // mem_region::RegionRecord

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace sheller::engine {

inline constexpr std::uint64_t kLedgerPageSize = 0x1000;

// The winnt.h PAGE_* / MEM_* facts and the protection predicates live in
// mem_region_map.h (included above): the attribution map is their canonical
// home since the region classification joined.

// True when the captured page protection allows guest writes - the same
// classification map_regions maps to a write-permitted unicorn region.
// Only such regions join the fault-based dirty tracking (The
// write ledger is first-touch per page; the region stays write-protected in
// the emulator until the guest's first write faults it in).
inline constexpr bool snapshot_protection_writable(const std::uint32_t protection)
{
    if ((protection & 0x100u) != 0) { // PAGE_GUARD: never guest-writable
        return false;
    }
    switch (protection & 0xFFu) {
    case 0x04: // PAGE_READWRITE
    case 0x08: // PAGE_WRITECOPY
    case 0x40: // PAGE_EXECUTE_READWRITE
    case 0x80: // PAGE_EXECUTE_WRITECOPY
        return true;
    default:
        return false;
    }
}

// One tracked region with its dirty-page bitmap and write summary.
struct LedgerRegion {
    std::uint64_t base{};
    std::uint64_t size{};
    std::uint32_t protection{};
    std::uint32_t type{};
    std::size_t source_index{};
    bool writable{}; // guest writes allowed by the capture
    std::vector<std::uint8_t> page_dirty;
    std::uint64_t dirty_pages{};
    bool written{};
    std::uint64_t first_dirty_page{}; // guest address of the first dirty page
};

// Page-granular write ledger over the snapshot's regions. Fault-based dirty
// tracking: writable regions are mapped without write
// permission and the write-prot hook reports each page's FIRST guest write
// here; on_write marks the page bits and the hook re-grants write so the
// access retries natively. on_write is per first-touch page, no allocation
// Writes outside writable tracked regions are ignored
// (read-only regions take the invalid-write path instead).
class MemWriteLedger {
  public:
    // sample_image_size is the sample's SizeOfImage: a capture splits the
    // image into several regions by page protection, so membership is
    // decided per span, not per region base equality.
    explicit MemWriteLedger(std::span<const mem_region::RegionRecord> regions,
                            std::uint64_t sample_image_base = 0,
                            std::uint64_t sample_image_size = 0);

    void on_write(std::uint64_t address, std::uint32_t size);

    // True when the address falls inside a writable tracked region (a
    // first-touch write there belongs to the ledger).
    [[nodiscard]] bool tracks_writable(std::uint64_t address) const;

    // Writer attribution: the faulting PC counts as sample
    // code when it executes in the sample's own image or in private
    // executable memory (shellcode, unpacked code). Writes from system
    // modules (dispatch, heap machinery) are infrastructure and stay out of
    // the ledger.
    [[nodiscard]] bool writer_is_sample_code(std::uint64_t pc) const;

    // The captured protection of the writable region containing the address,
    // or 0 when none (the caller re-derives the re-grant permissions).
    [[nodiscard]] std::uint32_t writable_protection_at(std::uint64_t address) const;

    // Marks the regions covering [base, base + size) guest-writable - an
    // NtProtectVirtualMemory request: subsequent first-touch
    // writes on those pages join the ledger.
    void set_writable(std::uint64_t base, std::uint64_t size);

    // Crash diagnostics: the tracked region covering the address, or an empty
    // span-like answer when untracked. Callers only read the fields.
    struct RegionView {
        std::uint64_t base{};
        std::uint64_t size{};
        std::uint32_t protection{};
        bool writable{};
    };
    [[nodiscard]] std::optional<RegionView> find_region(std::uint64_t address) const;

    // Registers a region the guest allocated at run time
    // (newly-written and newly-allocated regions both join the dump).
    // Inserted in base order so the on_write binary search stays valid;
    // this runs at allocation time, not on the hook hot path.
    void add_region(std::uint64_t base, std::uint64_t size, std::uint32_t protection,
                    std::uint32_t type);

    [[nodiscard]] std::size_t region_count() const
    {
        return regions_.size();
    }

    [[nodiscard]] const LedgerRegion& region(std::size_t index) const
    {
        return regions_[index];
    }

    // Indices of regions with at least one tracked write, in base order.
    [[nodiscard]] std::vector<std::size_t> dirty_region_indices() const;

  private:
    std::vector<LedgerRegion> regions_;
    std::uint64_t sample_image_base_{};
    std::uint64_t sample_image_size_{};
};

} // namespace sheller::engine

#endif // SHELLER_ENGINE_WRITE_LEDGER_H
