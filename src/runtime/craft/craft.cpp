// Hand-built guest environment path: serializes the loader-constructed guest
// (loader, PEB/TEB/Ldr, KUSER_SHARED_DATA, sample image and synthetic system
// module pages) into a v1 snapshot container. The replay route executes this
// container, and the unpack pipeline sources its clean pages from the same
// bytes - the world described and the world executed are one artifact.

#include "../../engine/craft.h"
#include "../../engine/loader_route.h"

#include <sheller/snapshot.h>

#include <algorithm>
#include <cstdint>
#include <expected>
#include <sstream>
#include <string>
#include <vector>

namespace sheller::engine {
namespace {

bool all_zero(const std::vector<std::uint8_t>& bytes)
{
    return std::all_of(bytes.begin(), bytes.end(),
                       [](const std::uint8_t byte) { return byte == 0; });
}

std::expected<std::vector<std::uint8_t>, RebuildFailure> serialize_guest(const PreparedGuest& guest)
{
    if (guest.guest_mode != GuestMode::kX64) {
        // The delivered container surface is 64-bit; the non-Windows sample
        // route refuses PE32 before this point (D9).
        return std::unexpected(failure(RebuildError::kBitnessUnsupported));
    }
    if (guest.metadata.peb_address == 0 || guest.metadata.teb_address == 0 ||
        guest.metadata.image_base == 0 || guest.metadata.entry_address == 0) {
        return std::unexpected(failure(RebuildError::kBadSnapshot));
    }

    std::vector<mem_region::RegionRecord> regions = guest.regions;
    std::sort(regions.begin(), regions.end(),
              [](const mem_region::RegionRecord& a, const mem_region::RegionRecord& b) {
                  return a.base < b.base;
              });

    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(
            snapshot::Header{.version = snapshot::kVersion, .bitness = snapshot::kBitness64})) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }

    snapshot::Registers registers{};
    const auto uc = guest.unicorn.get();
    for (std::size_t i = 0; i < snapshot::kGprCount; ++i) {
        if (uc_reg_read(uc, kGprRegisters64[i], &registers.gpr[i]) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
    }
    if (uc_reg_read(uc, UC_X86_REG_EFLAGS, &registers.rflags) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    // The construction leaves RIP at zero ("written by the run start"); the
    // container's register block must name the entry the replay starts at -
    // the reader rejects a container whose RIP disagrees with metadata.
    registers.rip = guest.metadata.entry_address;
    if (!writer.write_registers(registers) || !writer.write_metadata(guest.metadata)) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }

    for (const auto& region : regions) {
        if (region.size == 0) {
            continue;
        }
        if (region.base % kMapAlignment != 0 || region.size % kMapAlignment != 0) {
            return std::unexpected(failure(RebuildError::kUnalignedRegion));
        }
        std::vector<std::uint8_t> payload(static_cast<std::size_t>(region.size), std::uint8_t{0});
        if (uc_mem_read(uc, region.base, payload.data(), payload.size()) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        // Zero-filled mappings (the deterministic heap, an untouched stack)
        // carry no information; recording them content-absent keeps the
        // container at the module+environment scale and the replay maps the
        // same zeros back. Deterministic: the omission is a pure function of
        // the bytes.
        const bool present = !all_zero(payload);
        const snapshot::RegionHeader header{
            .base_address = region.base,
            .size = region.size,
            .protection = region.protection,
            .type = region.type,
            .content = present ? snapshot::kContentPresent : snapshot::kContentAbsent,
        };
        if (!writer.write_region(header, present ? payload.data() : nullptr)) {
            return std::unexpected(failure(RebuildError::kIoFailure));
        }
    }
    if (!writer.finalize_region_count()) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }
    const std::string bytes = out.str();
    return std::vector<std::uint8_t>{bytes.begin(), bytes.end()};
}

} // namespace

std::expected<std::vector<std::uint8_t>, RebuildFailure>
craft_container_from_guest(const PreparedGuest& guest)
{
    return serialize_guest(guest);
}

std::expected<std::vector<std::uint8_t>, RebuildFailure>
craft_sample_container(const std::filesystem::path& pe_path, const bool fidelity_seams,
                       const std::filesystem::path& synthetic_module_dir)
{
    if (synthetic_module_dir.empty()) {
        return std::unexpected(failure(RebuildError::kSyntheticModulesMissing));
    }
    auto guest = prepare_pe_file(pe_path, fidelity_seams, synthetic_module_dir);
    if (!guest) {
        return std::unexpected(guest.error());
    }
    return serialize_guest(*guest);
}

} // namespace sheller::engine
