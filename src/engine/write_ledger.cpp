#include "write_ledger.h"

#include <algorithm>

namespace sheller::engine {

MemWriteLedger::MemWriteLedger(const std::span<const mem_region::RegionRecord> regions,
                               const std::uint64_t sample_image_base,
                               const std::uint64_t sample_image_size)
    : sample_image_base_(sample_image_base), sample_image_size_(sample_image_size)
{
    regions_.reserve(regions.size());
    std::size_t index = 0;
    for (const auto& region : regions) {
        LedgerRegion entry;
        entry.base = region.base;
        entry.size = region.size;
        entry.protection = region.protection;
        entry.type = region.type;
        entry.source_index = index++;
        entry.writable = snapshot_protection_writable(region.protection);
        entry.page_dirty.assign(
            static_cast<std::size_t>((region.size + kLedgerPageSize - 1) / kLedgerPageSize), 0);
        regions_.push_back(std::move(entry));
    }
}

void MemWriteLedger::add_region(const std::uint64_t base, const std::uint64_t size,
                                const std::uint32_t protection, const std::uint32_t type)
{
    LedgerRegion entry;
    entry.base = base;
    entry.size = size;
    entry.protection = protection;
    entry.type = type;
    entry.writable = true; // run-time allocations are read-write by contract
    entry.page_dirty.assign(
        static_cast<std::size_t>((size + kLedgerPageSize - 1) / kLedgerPageSize), 0);
    const auto at = std::lower_bound(
        regions_.begin(), regions_.end(), base,
        [](const LedgerRegion& region, std::uint64_t value) { return region.base < value; });
    regions_.insert(at, std::move(entry));
}

void MemWriteLedger::set_writable(const std::uint64_t base, const std::uint64_t size)
{
    for (auto& region : regions_) {
        if (region.base < base + size && base < region.base + region.size) {
            region.writable = true;
        }
    }
}

void MemWriteLedger::remove_region(const std::uint64_t base)
{
    std::erase_if(regions_, [base](const LedgerRegion& region) { return region.base == base; });
}

std::optional<MemWriteLedger::RegionView>
MemWriteLedger::find_region(const std::uint64_t address) const
{
    std::size_t lo = 0;
    std::size_t hi = regions_.size();
    while (lo < hi) {
        const auto mid = lo + (hi - lo) / 2;
        if (regions_[mid].base <= address) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return std::nullopt;
    }
    const auto& region = regions_[lo - 1];
    if (address >= region.base + region.size) {
        return std::nullopt;
    }
    return RegionView{region.base, region.size, region.protection, region.writable};
}

bool MemWriteLedger::writer_is_sample_code(const std::uint64_t pc) const
{
    // Same binary search as tracks_writable, over all regions.
    std::size_t lo = 0;
    std::size_t hi = regions_.size();
    while (lo < hi) {
        const auto mid = lo + (hi - lo) / 2;
        if (regions_[mid].base <= pc) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return false;
    }
    const auto& region = regions_[lo - 1];
    if (pc >= region.base + region.size) {
        return false;
    }
    if (region.type == kMemImage) {
        // The sample's own image is sample code; other loaded modules are
        // system infrastructure. A capture splits one image into several
        // regions (per-page protection), so the verdict is span membership,
        // not region.base equality with the image base.
        return region.base >= sample_image_base_ &&
               region.base < sample_image_base_ + sample_image_size_;
    }
    if (region.type == kMemPrivate) {
        // Dynamically mapped executable memory: shellcode / unpacked code.
        return protection_executable(region.protection);
    }
    return false;
}

bool MemWriteLedger::tracks_writable(const std::uint64_t address) const
{
    // Same binary search as on_write: the last region whose base is at or
    // below the address.
    std::size_t lo = 0;
    std::size_t hi = regions_.size();
    while (lo < hi) {
        const auto mid = lo + (hi - lo) / 2;
        if (regions_[mid].base <= address) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return false;
    }
    const auto& region = regions_[lo - 1];
    return region.writable && address < region.base + region.size;
}

std::uint32_t MemWriteLedger::writable_protection_at(const std::uint64_t address) const
{
    // Same binary search as tracks_writable.
    std::size_t lo = 0;
    std::size_t hi = regions_.size();
    while (lo < hi) {
        const auto mid = lo + (hi - lo) / 2;
        if (regions_[mid].base <= address) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return 0;
    }
    const auto& region = regions_[lo - 1];
    if (!region.writable || address >= region.base + region.size) {
        return 0;
    }
    return region.protection;
}

void MemWriteLedger::on_write(const std::uint64_t address, const std::uint32_t size)
{
    if (size == 0 || regions_.empty()) {
        return;
    }
    // Binary search: the last region whose base is at or below the write.
    std::size_t lo = 0;
    std::size_t hi = regions_.size();
    while (lo < hi) {
        const auto mid = lo + (hi - lo) / 2;
        if (regions_[mid].base <= address) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    if (lo == 0) {
        return; // below the first tracked region
    }
    auto& region = regions_[lo - 1];
    if (address >= region.base + region.size) {
        return; // in a gap between regions
    }

    const auto first_page = (address - region.base) / kLedgerPageSize;
    const auto last_byte = (std::min)(address + size - 1, region.base + region.size - 1);
    const auto last_page = (last_byte - region.base) / kLedgerPageSize;
    for (auto page = first_page; page <= last_page; ++page) {
        auto& page_flag = region.page_dirty[page];
        if (page_flag == 0) {
            page_flag = 1;
            ++region.dirty_pages;
            if (region.first_dirty_page == 0) {
                region.first_dirty_page = region.base + page * kLedgerPageSize;
            }
        }
    }
    region.written = true;
}

std::vector<std::size_t> MemWriteLedger::dirty_region_indices() const
{
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < regions_.size(); ++i) {
        if (regions_[i].written) {
            out.push_back(i);
        }
    }
    return out;
}

} // namespace sheller::engine
