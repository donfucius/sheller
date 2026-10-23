#include "dump_writer.h"

#include <unicorn/unicorn.h>

#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

namespace sheller::engine {
namespace {

std::string hex64(const std::uint64_t value)
{
    char buf[17] = {};
    std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(value));
    return buf;
}

} // namespace

bool write_dump(const std::filesystem::path& directory, const MemWriteLedger& ledger,
                uc_engine* const uc)
{
    std::error_code fs_err;
    std::filesystem::create_directories(directory, fs_err);
    if (fs_err) {
        return false;
    }

    // Contiguous region spans (aggregate ledger intervals by
    // allocation base so an image header sits complete at the span head).
    // A span containing any dirty region dumps in FULL - clean pages
    // included - read straight from the live guest memory.
    struct Span {
        std::uint64_t base{};
        std::size_t size{};
        bool dirty{};
        std::uint32_t type{};
        std::uint32_t protection{};
        std::uint64_t first_dirty_page{};
    };
    std::vector<Span> spans;
    for (std::size_t i = 0; i < ledger.region_count(); ++i) {
        const auto& region = ledger.region(i);
        if (!spans.empty() && spans.back().base + spans.back().size == region.base) {
            auto& span = spans.back();
            span.size += region.size;
            span.dirty = span.dirty || region.written;
            if (region.written && span.first_dirty_page == 0) {
                span.first_dirty_page = region.first_dirty_page;
            }
            continue;
        }
        spans.push_back({region.base, static_cast<std::size_t>(region.size), region.written,
                         region.type, region.protection, region.first_dirty_page});
    }

    std::string manifest;
    for (const auto& span : spans) {
        if (!span.dirty) {
            continue; // nothing written here: not part of the dump
        }
        const auto bin_path = directory / (hex64(span.base) + ".bin");

        // Raw bytes, exactly as they sit in guest memory: no header, no
        // wrapper (the original-bytes stream).
        std::vector<std::uint8_t> bytes(span.size);
        if (uc_mem_read(uc, span.base, bytes.data(), bytes.size()) != UC_ERR_OK) {
            return false;
        }
        std::ofstream bin(bin_path, std::ios::binary | std::ios::trunc);
        if (!bin) {
            return false;
        }
        bin.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        if (!bin) {
            return false;
        }

        char line[160] = {};
        // Five fixed-width hex fields: base, size, type, protection,
        // first dirty page.
        std::snprintf(line, sizeof line, "%016llx %016llx %016llx %016llx %016llx\n",
                      static_cast<unsigned long long>(span.base),
                      static_cast<unsigned long long>(span.size),
                      static_cast<unsigned long long>(span.type),
                      static_cast<unsigned long long>(span.protection),
                      static_cast<unsigned long long>(span.first_dirty_page));
        manifest += line;
    }

    std::ofstream manifest_file(directory / "manifest.txt", std::ios::trunc);
    if (!manifest_file) {
        return false;
    }
    manifest_file << manifest;
    return static_cast<bool>(manifest_file);
}

} // namespace sheller::engine
