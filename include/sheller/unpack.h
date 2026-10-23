// IAT repair over a dump directory: probe image
// regions, resolve bound import thunks against the snapshot modules'
// exports, rewrite them as name imports and write repaired copies. The
// verdicts ride the returned summary and the diagnostics log; no report file
// exists. The original dump bytes are never modified. The pipeline is
// engine-native and portable: repair_dump runs on every host (the CLI unpack
// reaches it through the analysis facade's loader route on non-Windows hosts).

#ifndef SHELLER_UNPACK_H
#define SHELLER_UNPACK_H

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <vector>

namespace sheller::unpack {

enum class RepairVerdict : std::uint8_t {
    kComplete,
    kPartial,
    kFailed,
    kNotImage,
};

struct UncoveredThunk {
    std::uint32_t rva{};
    std::uint64_t va{};
};

struct RegionRepairReport {
    std::uint64_t base{};
    std::uint64_t size{};
    RepairVerdict verdict{};
    bool truncated{};
    std::uint64_t expected_bytes{};
    std::uint64_t actual_bytes{};
    std::uint64_t first_dirty_page{}; // 0 when the guest never wrote here
    std::vector<UncoveredThunk> uncovered;
    // Post-repair residual audit: thunks in the covered tables that are not
    // name-record form after the repair. complete verdicts MUST have this
    // empty; partial verdicts carry exactly the uncovered set.
    std::vector<UncoveredThunk> residual_abs_va;
    std::string detail; // failure reason when verdict is kFailed
};

enum class RepairError : std::uint8_t {
    kNone = 0,
    kIoFailure,   // snapshot or dump files could not be read
    kBadSnapshot, // the snapshot could not be rebuilt
    kBadDump,     // the dump directory has no usable manifest
};

struct RepairSummary {
    std::vector<RegionRepairReport> regions;
    // OEP stamp: when an identified OEP candidate fell inside a
    // repaired image region, its guest VA and the RVA written into that
    // copy's AddressOfEntryPoint. oep_found=false = no candidate applied.
    bool oep_found{false};
    std::uint64_t oep_va{};
    std::uint32_t oep_rva{};
};

// Repairs image regions found in dump_dir (manifest format), using the
// snapshot's rebuilt module exports for thunk resolution. Writes
// repaired_<base-hex>.exe copies into out_dir; the dump directory is only ever
// read. Verdicts are returned structurally and delivered through the
// diagnostics log (one info per region, one debug per uncovered thunk, warning
// for failures) - no report file exists. With oep_candidates (guest VAs, in
// first-occurrence order from the oep-candidate judgment events), the first
// candidate inside a repaired region is stamped into that copy's
// AddressOfEntryPoint and reported in the summary.
std::expected<RepairSummary, RepairError> repair_dump(const std::filesystem::path& snapshot,
                                                      const std::filesystem::path& dump_dir,
                                                      const std::filesystem::path& out_dir);
std::expected<RepairSummary, RepairError>
repair_dump(const std::filesystem::path& snapshot, const std::filesystem::path& dump_dir,
            const std::filesystem::path& out_dir, const std::vector<std::uint64_t>& oep_candidates);

// Same repair from in-memory snapshot bytes (the one-shot unpack flow keeps
// the capture out of the filesystem).
std::expected<RepairSummary, RepairError> repair_dump(const std::vector<std::uint8_t>& snapshot,
                                                      const std::filesystem::path& dump_dir,
                                                      const std::filesystem::path& out_dir);
std::expected<RepairSummary, RepairError>
repair_dump(const std::vector<std::uint8_t>& snapshot, const std::filesystem::path& dump_dir,
            const std::filesystem::path& out_dir, const std::vector<std::uint64_t>& oep_candidates);

} // namespace sheller::unpack

#endif // SHELLER_UNPACK_H
