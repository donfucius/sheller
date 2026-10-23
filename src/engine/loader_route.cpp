#include "loader_route.h"

#include "../loader/env.h"
#include "../loader/imports.h"
#include "../loader/loader.h"
#include "intercept.h"

#include <algorithm>
#include <cstring>
#include <fstream>

namespace sheller::engine {
namespace {

// The system-module set stage's product: the resident modules, their
// guest-side map bytes (fixed base -> image), and the intercepted
// (VA, handler id) pairs the import resolution registered.
struct LoadedSystemModules {
    std::vector<loader::LoadedModule> modules;
    std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> maps;
    std::vector<std::pair<std::uint64_t, std::uint32_t>> intercepts;
};

// The resident core modules, in load order. The fixed bases come from
// kBases64/kBases86 by index.
struct SystemModuleSpec {
    const char* file_name;
    const char* folded_name;
};
inline constexpr SystemModuleSpec kSystemModules[] = {
    {"ntdll.dll", "ntdll.dll"},
    {"kernel32.dll", "kernel32.dll"},
    {"kernelbase.dll", "kernelbase.dll"},
    // Tier 2 behavior surface: advapi32 hosts the registry-family
    // interceptions. No frozen advapi32 manifest exists yet - a missing file
    // is skipped (fail-soft).
    {"advapi32.dll", "advapi32.dll"},
};

std::string module_stem(std::string_view folded_name)
{
    constexpr std::string_view kDllSuffix = ".dll";
    std::string stem{folded_name};
    if (stem.size() > kDllSuffix.size() &&
        stem.compare(stem.size() - kDllSuffix.size(), kDllSuffix.size(), kDllSuffix) == 0) {
        stem.resize(stem.size() - kDllSuffix.size());
    }
    return stem;
}

std::filesystem::path synthetic_module_path(const std::filesystem::path& dir,
                                            std::string_view folded_name, GuestMode mode)
{
    return dir / (module_stem(folded_name) + (mode == GuestMode::kX86 ? ".x86.dll" : ".x64.dll"));
}

// Extras continue the core trio's series: x64 upward from the third base in
// 0x100000000 steps, x86 downward from it in 0x1000000 steps.
std::uint64_t extra_module_base(const GuestMode mode, const std::size_t index)
{
    return mode == GuestMode::kX86
               ? kBases86[2] - 0x1000000ULL * static_cast<std::uint64_t>(index + 1)
               : kBases64[2] + 0x100000000ULL * static_cast<std::uint64_t>(index + 1);
}

// The synthetic module files present in the directory, split into the core
// specs (in their fixed order) and the sorted extras. Mirrors the
// construction's discovery exactly.
struct SyntheticDirectoryPlan {
    std::vector<std::size_t> core_indices;
    std::vector<std::filesystem::path> extras;
};

SyntheticDirectoryPlan plan_synthetic_directory(const GuestMode mode,
                                                const std::filesystem::path& dir)
{
    SyntheticDirectoryPlan plan;
    std::error_code ec;
    for (std::size_t i = 0; i < std::size(kSystemModules); ++i) {
        const auto module_path = synthetic_module_path(dir, kSystemModules[i].folded_name, mode);
        if (std::filesystem::exists(module_path, ec) && !ec) {
            plan.core_indices.push_back(i);
        }
    }
    const std::string suffix = mode == GuestMode::kX86 ? ".x86.dll" : ".x64.dll";
    for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
        auto name = entry.path().filename().string();
        if (name.size() <= suffix.size() ||
            name.compare(name.size() - suffix.size(), suffix.size(), suffix) != 0) {
            continue;
        }
        name.resize(name.size() - suffix.size());
        name += ".dll";
        const bool core =
            std::any_of(std::begin(kSystemModules), std::end(kSystemModules),
                        [&name](const SystemModuleSpec& spec) { return name == spec.folded_name; });
        if (!core) {
            plan.extras.push_back(entry.path());
        }
    }
    std::sort(plan.extras.begin(), plan.extras.end());
    return plan;
}

// The world-building stage's product: the export index, the attribution
// records, and the TEB/PEB/Ldr environment the finish section assembles the
// PreparedGuest from.
struct LoaderWorld {
    std::vector<LoaderExportEntry> exports;
    std::vector<mem_region::ModuleImage> images;
    std::vector<mem_region::RegionRecord> regions;
    std::uint64_t teb_va;
    std::uint64_t peb_va;
    std::vector<std::uint64_t> module_entry_vas;
};

std::expected<LoadedSnapshot, RebuildFailure> load_snapshot_stream(std::istream& in)
{
    snapshot::Reader reader{in};
    LoadedSnapshot loaded;
    auto header = reader.read_header();
    if (!header) {
        return std::unexpected(header.error() == snapshot::Error::kBitnessMismatch
                                   ? failure(RebuildError::kBitnessUnsupported)
                                   : failure(RebuildError::kBadSnapshot));
    }
    loaded.header = *header;
    auto registers = reader.read_registers();
    if (!registers) {
        return std::unexpected(failure(RebuildError::kBadSnapshot));
    }
    loaded.registers = *registers;
    auto metadata = reader.read_metadata();
    if (!metadata) {
        return std::unexpected(failure(RebuildError::kBadSnapshot));
    }
    loaded.metadata = *metadata;
    for (std::uint32_t i = 0; i < loaded.header.region_count; ++i) {
        auto region = reader.read_region();
        if (!region) {
            return std::unexpected(failure(RebuildError::kBadSnapshot));
        }
        loaded.regions.push_back(std::move(*region));
    }
    if (loaded.registers.rip != loaded.metadata.entry_address) {
        return std::unexpected(failure(RebuildError::kInconsistent));
    }
    return loaded;
}

// Per-region rebuild order: validate alignment, map with the interpreted
// permissions, then write the content bytes the capture actually read.
std::expected<void, RebuildFailure> map_regions(UnicornEngine& unicorn,
                                                const std::vector<snapshot::Region>& regions)
{
    for (const auto& region : regions) {
        if (region.header.size == 0) {
            continue; // degenerate entry, nothing to rebuild
        }
        if (region.header.base_address % kMapAlignment != 0 ||
            region.header.size % kMapAlignment != 0) {
            return std::unexpected(failure(RebuildError::kUnalignedRegion));
        }
        auto perms = protection_to_perms(region.header.protection);
        // Fault-based dirty tracking: writable regions lose
        // their write permission at map time; the write-prot hook re-grants
        // it page by page on the guest's first write.
        if (snapshot_protection_writable(region.header.protection)) {
            perms &= ~static_cast<std::uint32_t>(UC_PROT_WRITE);
        }
        if (uc_mem_map(unicorn.get(), region.header.base_address,
                       static_cast<std::size_t>(region.header.size),
                       static_cast<std::uint32_t>(perms)) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        if (region.header.content == snapshot::kContentPresent && !region.content.empty() &&
            uc_mem_write(unicorn.get(), region.header.base_address, region.content.data(),
                         region.content.size()) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
    }
    return {};
}

std::expected<void, RebuildFailure> write_registers_gdt(UnicornEngine& unicorn,
                                                        const snapshot::Registers& registers,
                                                        const snapshot::Metadata& metadata,
                                                        std::uint64_t gdt_base);

std::expected<void, RebuildFailure> write_registers(UnicornEngine& unicorn,
                                                    const snapshot::Registers& registers,
                                                    const snapshot::Metadata& metadata,
                                                    const GuestMode mode,
                                                    const std::uint64_t gdt_base = kX86GdtBase)
{
    for (std::size_t i = 0; i < gpr_count_for(mode); ++i) {
        if (uc_reg_write(unicorn.get(), gpr_register_for(mode, i), &registers.gpr[i]) !=
            UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
    }
    if (uc_reg_write(unicorn.get(), UC_X86_REG_EFLAGS, &registers.rflags) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    if (mode == GuestMode::kX86) {
        return write_registers_gdt(unicorn, registers, metadata, gdt_base);
    }
    if (uc_reg_write(unicorn.get(), UC_X86_REG_RIP, &registers.rip) != UC_ERR_OK ||
        uc_reg_write(unicorn.get(), UC_X86_REG_GS_BASE, &metadata.teb_address) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    return {};
}

// x86 segment setup for a snapshot-route rebuild: same contract as
// write_registers but the GDT page sits at a caller-chosen free slot of
// the captured address space.
std::expected<void, RebuildFailure> write_registers_gdt(UnicornEngine& unicorn,
                                                        const snapshot::Registers& registers,
                                                        const snapshot::Metadata& metadata,
                                                        const std::uint64_t gdt_base)
{
    {
        // unicorn2 UC_MODE_32 no-ops FS_BASE, and the default SS/DS
        // descriptors are 16-bit (a push truncates ESP to SP): the segment
        // bases must come from a GDT over the pinned GDT page - entry 1
        // = TEB for FS, entry 2 = flat 4GB data for SS/DS.
        std::array<std::uint8_t, 24> gdt{};
        const auto teb = metadata.teb_address;
        auto write_data_desc = [&](const std::size_t at, const std::uint64_t base) {
            gdt[at + 0] = 0xFF; // limit low word 0xFFFF
            gdt[at + 1] = 0xFF;
            gdt[at + 2] = static_cast<std::uint8_t>(base & 0xFF);
            gdt[at + 3] = static_cast<std::uint8_t>((base >> 8) & 0xFF);
            gdt[at + 4] = static_cast<std::uint8_t>((base >> 16) & 0xFF);
            gdt[at + 5] = 0x92; // data segment, writable, present
            gdt[at + 6] = 0xCF; // 4K granularity, 32-bit (B), limit high 0xF
            gdt[at + 7] = static_cast<std::uint8_t>((base >> 24) & 0xFF);
        };
        write_data_desc(8, teb); // selector 0x08: FS -> TEB
        write_data_desc(16, 0);  // selector 0x10: SS/DS -> flat 4GB
        if (uc_mem_write(unicorn.get(), gdt_base, gdt.data(), gdt.size()) != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        uc_x86_mmr gdtr{};
        gdtr.base = gdt_base;
        gdtr.limit = 0xFFF;
        uc_reg_write(unicorn.get(), UC_X86_REG_GDTR, &gdtr);
        const std::uint16_t fs_selector = 0x08;
        uc_reg_write(unicorn.get(), UC_X86_REG_FS, &fs_selector);
        const std::uint16_t data_selector = 0x10;
        uc_reg_write(unicorn.get(), UC_X86_REG_SS, &data_selector);
        uc_reg_write(unicorn.get(), UC_X86_REG_DS, &data_selector);
        uc_reg_write(unicorn.get(), UC_X86_REG_ES, &data_selector);
        const auto eip = static_cast<std::uint32_t>(registers.rip);
        uc_reg_write(unicorn.get(), UC_X86_REG_EIP, &eip);
        return {};
    }
}

} // namespace

std::expected<PreparedGuest, RebuildFailure> prepare_guest_stream(std::istream& in)
{
    const auto loaded = load_snapshot_stream(in);
    if (!loaded) {
        return std::unexpected(loaded.error());
    }

    const auto mode =
        loaded->metadata.bitness == snapshot::kBitness32 ? GuestMode::kX86 : GuestMode::kX64;
    uc_engine* handle = nullptr;
    if (uc_open(UC_ARCH_X86, mode == GuestMode::kX86 ? UC_MODE_32 : UC_MODE_64, &handle) !=
        UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    UnicornEngine unicorn{handle};

    if (const auto mapped = map_regions(unicorn, loaded->regions); !mapped) {
        return std::unexpected(mapped.error());
    }
    if (mode == GuestMode::kX86) {
        // the 32-bit segment contract needs a GDT page; park it high in
        // the captured space at the first free 4KB page below 0xFFFE0000
        // (deterministic scan, skipping captured regions)
        std::uint64_t gdt_page = 0xFFFE0000ULL;
        while (gdt_page > 0x1000) {
            std::uint8_t probe = 0;
            if (uc_mem_read(handle, gdt_page, &probe, sizeof probe) != UC_ERR_OK) {
                break; // unmapped: free
            }
            gdt_page -= 0x100000;
        }
        const auto gdt_map_err = uc_mem_map(handle, gdt_page, 0x1000, UC_PROT_ALL);
        if (gdt_map_err != UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        if (const auto written =
                write_registers(unicorn, loaded->registers, loaded->metadata, mode, gdt_page);
            !written) {
            return std::unexpected(written.error());
        }
    } else if (const auto written =
                   write_registers(unicorn, loaded->registers, loaded->metadata, mode);
               !written) {
        return std::unexpected(written.error());
    }
    // Attribute the whole address space once, at rebuild time: module
    // images from the Ldr walk, region records from the snapshot. Regions
    // double as synthesis candidates: contiguous MEM_IMAGE chains that no
    // Ldr module spans become unknown-image module records, appended after
    // the Ldr set (the sample-ordinal / arming alignment depends on that
    // order) so hand-mapped payloads get section-level attribution.
    auto images = mem_region::enumerate_guest_images(handle, mode == GuestMode::kX86,
                                                     loaded->metadata.teb_address);
    std::vector<mem_region::RegionRecord> region_records;
    region_records.reserve(loaded->regions.size());
    std::vector<mem_region::UnknownImageCandidate> candidates;
    candidates.reserve(loaded->regions.size());
    for (const auto& region : loaded->regions) {
        region_records.push_back(
            mem_region::RegionRecord{region.header.base_address, region.header.size,
                                     region.header.protection, region.header.type});
        candidates.push_back({region.header.base_address, region.header.size, region.header.type,
                              std::span<const std::uint8_t>{region.content}});
    }
    const auto unknown_images =
        mem_region::synthesize_unknown_images(images, {candidates.data(), candidates.size()});
    images.insert(images.end(), unknown_images.begin(), unknown_images.end());
    mem_region::MemRegionMap map(images, region_records);
    return PreparedGuest{std::move(unicorn),          mode,
                         std::move(loaded->metadata), std::move(map),
                         std::move(images),           std::move(region_records)};
}

// Loader-route API interception:
// intercepted kernel32/Rtl entries are replaced wholesale by these built-in
// implementations - args from the x64 call registers, result in rax, return
// address popped off the stack. The uc_emu_stop + api_resume hands the leg
// back to the run loop, which re-enters at the return address.

// Loader route: build the address space
// from a PE file instead of a snapshot. Layout: bottom 64KB reserved with
// NULL-page semantics, the image at its declared base (fully RWX - section
// protections ride the metadata, never page permissions, or a shell's
// self-modification trips over them), KUSER at the fixed page, and a
// deterministic stack. The loader module does the byte work; this function
// maps it and produces the same PreparedGuest the snapshot path runs.
// Loads the resident system modules for the loader route: the core
// ntdll/kernel32/kernelbase/advapi32 set (synthetic dir first, host
// System32/SysWOW64 fallback) plus the synthetic extras, then resolves
// the sample's imports against them and registers the intercepted
// entries. Returns the module set with its guest-side map bytes and
// the intercepted (VA, handler id) pairs.
std::expected<LoadedSystemModules, RebuildFailure>
load_system_modules(const GuestMode mode, const std::filesystem::path& synthetic_module_dir,
                    std::vector<std::uint8_t>& image)
{
    LoadedSystemModules loaded;
    // one resident module: map its bytes at the fixed base, relocate by the
    // base delta, and index the exports (resolve_imports below and the
    // interception layer's GetProcAddress/LoadLibrary both read module.exports)
    auto& system_modules = loaded.modules;
    auto& system_maps = loaded.maps;
    auto& intercepts = loaded.intercepts;
    // system modules: real host system images
    // at fixed high addresses, RWX, relocated by their own delta. Their
    // bytes are retained host-side for import resolution and the
    // GetProcAddress index. Absent files fail the run loudly.
    // Windows-host-only: reads System32 (x64) or SysWOW64 (x86); on other
    // hosts the loader route runs import-free samples only (imports stay
    // unresolved by design).
    // system modules come from either the synthetic module dir (
    // portable - deterministic stub bodies + frozen export tables) or, on
    // Windows hosts, the real host DLLs. Without either, imports resolve to
    // nothing by design.
    const auto& bases = mode == GuestMode::kX64 ? kBases64 : kBases86;
    // one resident module: map its bytes at the fixed base, relocate by the
    // base delta, and index the exports (resolve_imports below and the
    // interception layer's GetProcAddress/LoadLibrary both read module.exports)
    const auto load_system_module =
        [&](const std::filesystem::path& dll_path, std::string_view folded_name,
            std::uint64_t fixed_base) -> std::expected<void, RebuildFailure> {
        std::ifstream dll_in(dll_path, std::ios::binary);
        if (!dll_in) {
            return std::unexpected(failure(RebuildError::kIoFailure));
        }
        std::vector<std::uint8_t> dll_bytes{std::istreambuf_iterator<char>(dll_in),
                                            std::istreambuf_iterator<char>()};
        auto module_info = loader::parse_pe(dll_bytes);
        if (!module_info) {
            return std::unexpected(failure(RebuildError::kBadSnapshot));
        }
        auto module_image = loader::build_image(dll_bytes, *module_info);
        if (!module_image) {
            return std::unexpected(failure(RebuildError::kBadSnapshot));
        }
        const auto delta = fixed_base - module_info->image_base;
        if (delta != 0) {
            static_cast<void>(loader::apply_relocations(*module_image, *module_info, delta));
        }
        loader::LoadedModule loaded;
        loaded.base = fixed_base;
        loaded.image = std::move(*module_image);
        std::memcpy(loaded.name.data(), folded_name.data(), folded_name.size());
        static_cast<void>(loader::index_exports(loaded));
        system_modules.push_back(std::move(loaded));
        system_maps.emplace_back(fixed_base, system_modules.back().image);
        return {};
    };
    for (std::size_t i = 0; i < std::size(kSystemModules); ++i) {
        const auto& spec = kSystemModules[i];
        // synthetic system modules take precedence: deterministic
        // stub bodies + frozen export tables replace the host's real DLLs
        std::filesystem::path dll_path;
        if (!synthetic_module_dir.empty()) {
            dll_path = synthetic_module_path(synthetic_module_dir, spec.folded_name, mode);
        } else {
#ifdef _WIN32
            char system_root[MAX_PATH] = {};
            const auto len = mode == GuestMode::kX86
                                 ? GetSystemWow64DirectoryA(system_root, sizeof system_root)
                                 : GetSystemDirectoryA(system_root, sizeof system_root);
            if (len == 0) {
                return std::unexpected(failure(RebuildError::kIoFailure));
            }
            dll_path = std::filesystem::path(system_root) / spec.file_name;
#else
            continue; // non-Windows host without synth dir: no system modules
#endif
        }
        // Tier 2 fail-soft: the synthetic route has no frozen advapi32
        // manifest yet - a missing module file there is a skip, not a run
        // failure (the route simply runs without that module and its
        // interception surface). The real-DLL route keeps its loud failure.
        // The error_code overload, not the throwing one: an engine frame
        // reports a probe failure through this same skip channel instead of
        // letting a filesystem error escape as an exception (see the no-throw
        // discipline in the root CMakeLists). A probe that fails for a reason
        // other than "absent" is indistinguishable here and takes the same
        // branch - the module stays unloaded either way.
        std::error_code probe_ec;
        const bool present = std::filesystem::exists(dll_path, probe_ec);
        if (!synthetic_module_dir.empty() && (!present || probe_ec)) {
            continue;
        }
        auto loaded_module = load_system_module(dll_path, spec.folded_name, bases[i]);
        if (!loaded_module) {
            return std::unexpected(loaded_module.error());
        }
    }

    // additional synthetic modules (the CRT / vcruntime sets): the packed
    // corpus's unpack stubs LoadLibraryA them at runtime, and their exports
    // answer both import resolution and the interception layer. Resident
    // beside the core trio at extended fixed bases, sorted-name order for
    // determinism.
    if (!synthetic_module_dir.empty()) {
        std::error_code dir_ec;
        if (!std::filesystem::is_directory(synthetic_module_dir, dir_ec) || dir_ec) {
            return std::unexpected(failure(RebuildError::kIoFailure));
        }
        const std::string suffix = mode == GuestMode::kX86 ? ".x86.dll" : ".x64.dll";
        auto plan = plan_synthetic_directory(mode, synthetic_module_dir);
        for (std::size_t i = 0; i < plan.extras.size(); ++i) {
            auto stem = plan.extras[i].filename().string();
            stem.resize(stem.size() - suffix.size());
            const auto folded = stem + ".dll";
            auto loaded_module =
                load_system_module(plan.extras[i], folded, extra_module_base(mode, i));
            if (!loaded_module) {
                return std::unexpected(loaded_module.error());
            }
        }
    }

    // resolve the sample's imports against the system modules (sample bytes
    // are host-side here, so IAT fixups land before the mapping)
    std::vector<loader::UnresolvedImport> unresolved_imports;
    const auto fixups = loader::resolve_imports(image, system_modules, &unresolved_imports);
    // intercepted-API bookkeeping: a resolved import whose final name is in
    // the intercept set hooks that function entry (VA + stable handler id)
    if (fixups.has_value()) {
        for (const auto& fixup : *fixups) {
            for (const auto& system : system_modules) {
                for (const auto& [name, va] : system.exports) {
                    if (va == fixup.resolved) {
                        if (const auto id = intercept_id_for(name)) {
                            intercepts.emplace_back(fixup.resolved, *id);
                        }
                    }
                }
            }
        }
    }
    return loaded;
}

// Opens the unicorn instance and builds the loader route's address space:
// the NULL guard, the sample image (write-protected for the fault-based
// dirty tracking), KUSER, the deterministic stack/heap/env regions, the
// x86 GDT page, then the resident module bytes and the sample itself,
// and the KUSER semantic fields.
std::expected<UnicornEngine, RebuildFailure>
map_loader_address_space(const GuestMode mode, const std::uint64_t base,
                         const std::uint64_t image_size, const std::vector<std::uint8_t>& image,
                         const LoadedSystemModules& loaded)
{
    const auto& layout = layout_for(mode);
    const auto& system_maps = loaded.maps;

    uc_engine* handle = nullptr;
    const auto uc_mode_selected = mode == GuestMode::kX86 ? UC_MODE_32 : UC_MODE_64;
    if (uc_open(UC_ARCH_X86, uc_mode_selected, &handle) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    UnicornEngine unicorn{handle};

    const auto image_span = static_cast<std::size_t>(image_size);
    // Fault-based dirty tracking: the
    // guest-writable loader regions map without write permission - the
    // write-prot hook re-grants it page by page on the guest's first write,
    // so the dump ledger sees exactly the pages the sample touched.
    constexpr auto kNoWrite = static_cast<std::uint32_t>(UC_PROT_READ | UC_PROT_EXEC);
    if (uc_mem_map(unicorn.get(), 0, kLoaderNullBytes, UC_PROT_NONE) != UC_ERR_OK ||
        uc_mem_map(unicorn.get(), base, image_span, kNoWrite) != UC_ERR_OK ||
        uc_mem_map(unicorn.get(), kLoaderKUser, 0x1000, UC_PROT_READ) != UC_ERR_OK ||
        uc_mem_map(unicorn.get(), layout.stack_base, layout.stack_size, kNoWrite) != UC_ERR_OK ||
        uc_mem_map(unicorn.get(), layout.heap_base, layout.heap_size, kNoWrite) != UC_ERR_OK ||
        uc_mem_map(unicorn.get(), layout.env_base, layout.env_block_size, kNoWrite) != UC_ERR_OK ||
        (mode == GuestMode::kX86 &&
         uc_mem_map(unicorn.get(), kX86GdtBase, kX86GdtSize, UC_PROT_ALL) != UC_ERR_OK)) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    // system module images land at their fixed bases:
    // relocated host-side above, written guest-side RWX
    for (const auto& [map_base, map_bytes] : system_maps) {
        if (uc_mem_map(unicorn.get(), map_base, map_bytes.size(), UC_PROT_ALL) != UC_ERR_OK ||
            uc_mem_write(unicorn.get(), map_base, map_bytes.data(), map_bytes.size()) !=
                UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
    }
    if (uc_mem_write(unicorn.get(), base, image.data(), image.size()) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    return unicorn;
}

// Seeds the fidelity-mode ntdll runtime globals: the process-init gate
// and the inverted function table over the resident module set plus the
// sample, version-pinned to the Windows 11 ntdll. Engine dispatch never
// consumes these - the seeding only wires up in fidelity mode.
std::expected<void, RebuildFailure>
seed_ntdll_ifnt(UnicornEngine& unicorn, const GuestMode mode, const bool fidelity_seams,
                const LoadedSystemModules& loaded, const std::vector<std::uint8_t>& image,
                const std::uint64_t base, const std::uint64_t image_size)
{
    const auto& system_modules = loaded.modules;

    // ntdll runtime globals: the disk image carries
    // pre-init process state that LdrpInitialize would fill. x64 SEH
    // dispatch needs two of those globals. The process-init gate at
    // +0x1d23c8: RtlLookupFunctionEntry only consults the inverted
    // function table when it reads 3 there, and its fallback otherwise
    // (NtQueryVirtualMemory probing) cannot produce a working unwind. The
    // inverted function table itself: DWORD count at +0x1e7430, DWORD
    // max-count at +0x1e7438, then 24-byte entries at +0x1e7440
    // ({exception directory, image base, size of image, directory size}).
    // Entry 0 is ntdll's own descriptor (excluded from the reader's binary
    // search, which instead matches it against the dedicated descriptor
    // globals); entries 1.. are searched by image base and must be sorted.
    // RVAs verified against the Windows 11 ntdll this host ships; a much
    // smaller ntdll skips the seeding and stays on the fallback path.
    // The seeding is a Windows-fidelity seam (exception dispatch via
    // real ntdll); the engine-side dispatcher never consumes it, so it only
    // wires up in fidelity mode.
    if (fidelity_seams && mode == GuestMode::kX64 && image.size() > 0x1000) {
        constexpr std::uint64_t kInitGateRva = 0x1d23c8;
        constexpr std::uint64_t kIfntCountRva = 0x1e7430;
        constexpr std::uint64_t kIfntEntriesRva = 0x1e7440;
        const auto exception_directory =
            [](const std::vector<std::uint8_t>& img) -> std::pair<std::uint32_t, std::uint32_t> {
            if (img.size() < 0x200) {
                return {};
            }
            std::uint32_t e_lfanew = 0;
            std::memcpy(&e_lfanew, img.data() + 0x3c, sizeof e_lfanew);
            if (e_lfanew + 0xa8 > img.size() ||
                std::memcmp(img.data() + e_lfanew, "PE\0\0", 4) != 0) {
                return {};
            }
            std::uint16_t magic = 0;
            std::memcpy(&magic, img.data() + e_lfanew + 0x18, sizeof magic);
            const auto dir_rva =
                magic == 0x20b ? e_lfanew + 0x18 + 0x70 + 0x18 : e_lfanew + 0x18 + 0x60 + 0x18;
            std::pair<std::uint32_t, std::uint32_t> out{};
            std::memcpy(&out.first, img.data() + dir_rva, sizeof out.first);
            std::memcpy(&out.second, img.data() + dir_rva + 4, sizeof out.second);
            return out;
        };
        const auto ntdll = std::find_if(system_modules.begin(), system_modules.end(),
                                        [](const loader::LoadedModule& m) {
                                            return std::string_view(m.name.data()) == "ntdll.dll";
                                        });
        if (ntdll != system_modules.end() && ntdll->image.size() > kIfntEntriesRva + 0x100) {
            struct IfntEntry {
                std::uint64_t directory;
                std::uint64_t image_base;
                std::uint32_t size_of_image;
                std::uint32_t directory_size;
            };
            std::vector<IfntEntry> entries;
            for (const auto& system : system_modules) {
                const auto dir = exception_directory(system.image);
                entries.push_back({system.base + dir.first, system.base,
                                   static_cast<std::uint32_t>(system.image.size()), dir.second});
            }
            const auto sample_dir = exception_directory(image);
            entries.push_back({base + sample_dir.first, base,
                               static_cast<std::uint32_t>(image_size), sample_dir.second});
            // entry 0 must be ntdll's own descriptor: the reader excludes it
            // from the search and matches ControlPc against it via the
            // descriptor globals; the rest are binary-searched by image base
            const auto ntdll_idx = std::find_if(entries.begin(), entries.end(),
                                                [ntdll_base = ntdll->base](const IfntEntry& e) {
                                                    return e.image_base == ntdll_base;
                                                }) -
                                   entries.begin();
            std::swap(entries[0], entries[ntdll_idx]);
            std::sort(
                entries.begin() + 1, entries.end(),
                [](const IfntEntry& a, const IfntEntry& b) { return a.image_base < b.image_base; });
            const std::uint32_t gate = 3;
            const std::uint32_t count = static_cast<std::uint32_t>(entries.size());
            const std::uint32_t max_count = 0xa;
            std::vector<std::uint8_t> table(0x10 + entries.size() * sizeof(IfntEntry), 0);
            std::memcpy(table.data(), &count, sizeof count);
            std::memcpy(table.data() + 8, &max_count, sizeof max_count);
            std::memcpy(table.data() + 0x10, entries.data(), entries.size() * sizeof(IfntEntry));
            if (uc_mem_write(unicorn.get(), ntdll->base + kInitGateRva, &gate, sizeof gate) !=
                    UC_ERR_OK ||
                uc_mem_write(unicorn.get(), ntdll->base + kIfntCountRva, table.data(),
                             table.size()) != UC_ERR_OK) {
                return std::unexpected(failure(RebuildError::kUnicornFailure));
            }
        }
    }
    return {};
}

// Builds the loader route's world bookkeeping: the export index feeding
// GetProcAddress/LoadLibrary, the module images and region records for
// behavior attribution (ascending-base order for the binary-searching
// readers), and the deterministic TEB/PEB/Ldr environment block.
std::expected<LoaderWorld, RebuildFailure>
build_loader_world(UnicornEngine& unicorn, const GuestMode mode, const LoadedSystemModules& loaded,
                   const std::vector<std::uint8_t>& image, const std::uint64_t base,
                   const std::uint64_t image_size)
{
    LoaderWorld world;
    auto& loader_exports = world.exports;
    auto& images = world.images;
    auto& regions = world.regions;
    const auto& layout = layout_for(mode);
    const auto& system_modules = loaded.modules;

    // KUSER_SHARED_DATA semantic fields: fixed deterministic values
    {
        std::vector<std::uint8_t> kuser(0x1000, 0);
        loader::fill_kuser_shared_data(kuser);
        uc_mem_write(unicorn.get(), kLoaderKUser, kuser.data(), kuser.size());
    }

    // loader tables: the exports indexed at load time feed the
    // interception layer's GetProcAddress/LoadLibrary lookups

    for (const auto& system : system_modules) {
        for (const auto& [name, va] : system.exports) {
            loader_exports.push_back({system.base, va, name});
        }
    }

    // regions + attribution: the image, system modules, KUSER, stack, heap
    // and the environment block; the loader sample joins as its own module so
    // behavior attribution and monitored windows work unchanged

    for (const auto& system : system_modules) {
        mem_region::ModuleImage system_image;
        system_image.module.base = system.base;
        system_image.module.size = system.image.size();
        std::memcpy(system_image.module.name.data(), system.name.data(), system.name.size());
        system_image.header_bytes.assign(system.image.begin(), system.image.begin() + 0x1000);
        images.push_back(std::move(system_image));
    }
    mem_region::ModuleImage loader_image;
    loader_image.module.base = base;
    loader_image.module.size = image_size;
    const std::string module_name = "loader_image";
    std::copy(module_name.begin(), module_name.end(), loader_image.module.name.begin());
    loader_image.header_bytes.assign(image.begin(), image.begin() + 0x1000);
    images.push_back(loader_image);

    regions.push_back(mem_region::RegionRecord{base, image_size, 0x40, kMemImage});
    for (const auto& system : system_modules) {
        regions.push_back(
            mem_region::RegionRecord{system.base, system.image.size(), 0x40, kMemImage});
    }
    regions.push_back(mem_region::RegionRecord{kLoaderKUser, 0x1000, 0x02, kMemPrivate});
    regions.push_back(
        mem_region::RegionRecord{layout.stack_base, layout.stack_size, 0x04, kMemPrivate});
    regions.push_back(
        mem_region::RegionRecord{layout.heap_base, layout.heap_size, 0x04, kMemPrivate});
    regions.push_back(
        mem_region::RegionRecord{layout.env_base, layout.env_block_size, 0x04, kMemPrivate});
    // Region records are consumed by binary-searching readers (the write
    // ledger's find_region): canonical order is ascending by base. The
    // capture path produces sorted records; the loader build does not.
    std::sort(regions.begin(), regions.end(),
              [](const mem_region::RegionRecord& a, const mem_region::RegionRecord& b) {
                  return a.base < b.base;
              });

    // environment block: TEB/PEB/Ldr constructed from the module set;
    // x86 mode gets the 32-bit layout twin (wires build_environment_x86;
    // for now both modes use the x64 shape, which only x64 samples consume)
    std::vector<loader::EnvModule> env_modules;
    for (const auto& image_rec : images) {
        env_modules.push_back({image_rec.module.base,
                               static_cast<std::uint32_t>(image_rec.module.size),
                               std::string(image_rec.module.name.data())});
    }
    // the TEB stack pair must describe the mapped stack exactly: the entry
    // rsp sits kLoaderStackTop-0x1000, and RtlDispatchException validates
    // the dispatch Rsp against [TEB.StackLimit, TEB.StackBase) - a declared
    // top below the real top makes every early fault look like a bad stack
    const auto stack_top = layout.stack_base + layout.stack_size;
    const auto env =
        mode == GuestMode::kX86
            ? loader::build_environment_x86(layout.env_base, base, stack_top, layout.stack_base,
                                            layout.heap_base, env_modules)
            : loader::build_environment(layout.env_base, base, stack_top, layout.stack_base,
                                        layout.heap_base, env_modules);
    if (uc_mem_write(unicorn.get(), layout.env_base, env.env.data(), env.env.size()) != UC_ERR_OK) {
        return std::unexpected(failure(RebuildError::kUnicornFailure));
    }
    world.teb_va = env.teb_va;
    world.peb_va = env.peb_va;
    world.module_entry_vas = std::move(env.module_entry_vas);
    return world;
}

// x86 only: welds the three-byte int-2E transition stub over the
// Wow64Transition slot (real ntdll32 RVA, or the synthetic ntdll's own
// slot) and the TEB's fs:[0xC0] pointer, so every SysWOW64 service call
// lands in the engine's native int-2E answer.
std::expected<void, RebuildFailure>
seed_wow64_transition(UnicornEngine& unicorn, const GuestMode mode,
                      const LoadedSystemModules& loaded,
                      const std::filesystem::path& synthetic_module_dir, const std::uint64_t teb_va)
{
    const auto& system_modules = loaded.modules;

    // x86 wow64 transition: every SysWOW64 ntdll service stub
    // reaches the kernel through `call *fs:[0xC0]` / `jmp [Wow64Transition]`,
    // and ntdll's own dispatcher wraps its information queries in the same
    // shape. The real transition target is the wow64cpu layer, but its ABI - eax = number, edx =
    // argument block, call
    // - is exactly the int 0x2E convention the engine answers natively. A
    // three-byte stub turns every transition into an emulated service call;
    // both dispatch identifiers point at it. The Wow64Transition RVA matches
    // the Windows 11 ntdll this host ships (guarded like the x64 seeding).
    if (mode == GuestMode::kX86) {
        constexpr std::uint64_t kWow64StubBase = kLoaderWow64StubBase;
        // The Wow64Transition slot serves syscall transitions (not exception
        // dispatch): the real ntdll32's slot RVA is version-pinned, while the
        // synthetic ntdll welds its own slot at a known RVA.
        constexpr std::uint64_t kRealWow64TransitionRva = 0x13B014;
        constexpr std::uint64_t kSynthWow64TransitionRva = 0x41000;
        const std::uint64_t kWow64TransitionRva =
            synthetic_module_dir.empty() ? kRealWow64TransitionRva : kSynthWow64TransitionRva;
        constexpr std::uint64_t kWow64TransitionTeb = 0xC0;
        static const std::array<std::uint8_t, 3> kWow64Stub{0xCD, 0x2E, 0xC3}; // int 2Eh; ret
        if (uc_mem_map(unicorn.get(), kWow64StubBase, 0x1000, UC_PROT_ALL) != UC_ERR_OK ||
            uc_mem_write(unicorn.get(), kWow64StubBase, kWow64Stub.data(), kWow64Stub.size()) !=
                UC_ERR_OK) {
            return std::unexpected(failure(RebuildError::kUnicornFailure));
        }
        const auto ntdll = std::find_if(system_modules.begin(), system_modules.end(),
                                        [](const loader::LoadedModule& m) {
                                            return std::string_view(m.name.data()) == "ntdll.dll";
                                        });
        if (ntdll != system_modules.end() && ntdll->image.size() > kWow64TransitionRva + 4) {
            const auto stub = static_cast<std::uint32_t>(kWow64StubBase);
            if (uc_mem_write(unicorn.get(), ntdll->base + kWow64TransitionRva, &stub,
                             sizeof stub) != UC_ERR_OK ||
                uc_mem_write(unicorn.get(), teb_va + kWow64TransitionTeb, &stub, sizeof stub) !=
                    UC_ERR_OK) {
                return std::unexpected(failure(RebuildError::kUnicornFailure));
            }
        }
    }
    return {};
}

std::expected<PreparedGuest, RebuildFailure>
prepare_pe_file(const std::filesystem::path& path, bool fidelity_seams,
                const std::filesystem::path& synthetic_module_dir)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }
    std::vector<std::uint8_t> file{std::istreambuf_iterator<char>(in),
                                   std::istreambuf_iterator<char>()};
    const auto info = loader::parse_pe(file);
    if (!info) {
        return std::unexpected(failure(RebuildError::kBadSnapshot));
    }
    const auto mode = info->bitness == loader::kBitness32 ? GuestMode::kX86 : GuestMode::kX64;
    const auto& layout = layout_for(mode);
    auto image = loader::build_image(file, *info);
    if (!image) {
        return std::unexpected(failure(RebuildError::kBadSnapshot));
    }
    // The image is remapped when its declared base cannot survive a 32-bit
    // slot (see kLoaderSampleBase); the delta repairs every relocated pointer
    // and PEB.ImageBase / metadata follow the mapped base below.
    const auto mapped_base = (!synthetic_module_dir.empty() && info->image_base > 0xFFFFFFFFULL)
                                 ? kLoaderSampleBase
                                 : info->image_base;
    const auto base_delta = mapped_base - info->image_base;
    static_cast<void>(loader::apply_relocations(*image, *info, base_delta));
    auto callbacks = loader::tls_callbacks(*image, *info, base_delta);
    if (!callbacks.has_value()) {
        callbacks = std::vector<std::uint64_t>{};
    }

    auto system_loaded = load_system_modules(mode, synthetic_module_dir, *image);
    if (!system_loaded.has_value()) {
        return std::unexpected(system_loaded.error());
    }
    auto& intercepts = system_loaded->intercepts;
    auto unicorn_result =
        map_loader_address_space(mode, mapped_base, info->image_size, *image, *system_loaded);
    if (!unicorn_result.has_value()) {
        return std::unexpected(unicorn_result.error());
    }
    UnicornEngine& unicorn = *unicorn_result;
    const auto base = mapped_base;
    if (const auto seeded = seed_ntdll_ifnt(unicorn, mode, fidelity_seams, *system_loaded, *image,
                                            mapped_base, info->image_size);
        !seeded.has_value()) {
        return std::unexpected(seeded.error());
    }
    auto world =
        build_loader_world(unicorn, mode, *system_loaded, *image, mapped_base, info->image_size);
    if (!world.has_value()) {
        return std::unexpected(world.error());
    }
    const auto teb_va = world->teb_va;
    const auto peb_va = world->peb_va;
    if (const auto wow64 =
            seed_wow64_transition(unicorn, mode, *system_loaded, synthetic_module_dir, teb_va);
        !wow64.has_value()) {
        return std::unexpected(wow64.error());
    }
    snapshot::Metadata metadata;
    metadata.entry_address = base + info->entry_rva;
    metadata.image_base = base;
    metadata.teb_address = teb_va;
    metadata.peb_address = peb_va;
    const auto entry_offset = static_cast<std::size_t>(info->entry_rva);
    std::memcpy(metadata.original_entry_bytes.data(), image->data() + entry_offset,
                metadata.original_entry_bytes.size());

    // registers: natural entry state - zeroed GPRs, stack from the reserved
    // region, RIP written by the run start; GS_BASE points at the TEB
    const snapshot::Registers registers{}; // natural entry state: zeroed GPRs
    if (const auto written = write_registers(unicorn, registers, metadata, mode); !written) {
        return std::unexpected(written.error());
    }
    const std::uint64_t rsp = layout.stack_base + layout.stack_size - 0x1000;
    uc_reg_write(unicorn.get(), gpr_register_for(mode, 4), &rsp);

    std::vector<mem_region::ModuleRecord> loader_modules;
    for (const auto& image_rec : world->images) {
        loader_modules.push_back(image_rec.module);
    }

    PreparedGuest guest{std::move(unicorn),
                        mode,
                        std::move(metadata),
                        mem_region::MemRegionMap{world->images, world->regions},
                        std::move(world->images),
                        std::move(world->regions),
                        std::move(*callbacks),
                        std::move(loader_modules),
                        std::move(world->exports),
                        std::move(intercepts),
                        std::move(world->module_entry_vas)};
    guest.loader_route = true; // synthetic Ldr: LdrLoadDll misses stay answered
    return guest;
}

std::expected<PreparedGuest, RebuildFailure> prepare_guest(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return std::unexpected(failure(RebuildError::kIoFailure));
    }
    return prepare_guest_stream(in);
}

namespace {

std::uint64_t read_u64(uc_engine* const uc, const std::uint64_t address)
{
    std::uint64_t value = 0;
    static_cast<void>(uc_mem_read(uc, address, &value, sizeof value));
    return value;
}

std::uint32_t read_u32(uc_engine* const uc, const std::uint64_t address)
{
    std::uint32_t value = 0;
    static_cast<void>(uc_mem_read(uc, address, &value, sizeof value));
    return value;
}

// Walks PEB->Ldr.InLoadOrderModuleList and records (DllBase, entry VA) in
// chain order. The environment layout puts the entry base on the
// InLoadOrderLinks node itself (env.cpp), so the node address is the handle
// LdrLoadDll hands out.
std::vector<std::pair<std::uint64_t, std::uint64_t>>
read_ldr_entries(uc_engine* const uc, const snapshot::Metadata& metadata, const GuestMode mode)
{
    std::vector<std::pair<std::uint64_t, std::uint64_t>> entries;
    const auto peb = metadata.peb_address;
    if (peb == 0) {
        return entries;
    }
    constexpr std::size_t kMaxWalk = mem_region::kMaxModuleImages;
    if (mode == GuestMode::kX86) {
        const auto ldr = static_cast<std::uint64_t>(read_u32(uc, peb + 0x0C));
        if (ldr == 0) {
            return entries;
        }
        const auto head = ldr + 0x0C;
        auto node = static_cast<std::uint64_t>(read_u32(uc, head));
        for (std::size_t i = 0; i < kMaxWalk && node != 0 && node != head; ++i) {
            const auto base = static_cast<std::uint64_t>(read_u32(uc, node + 0x18));
            entries.emplace_back(base, node);
            node = static_cast<std::uint64_t>(read_u32(uc, node));
        }
        return entries;
    }
    const auto ldr = read_u64(uc, peb + 0x18);
    if (ldr == 0) {
        return entries;
    }
    const auto head = ldr + 0x10;
    auto node = read_u64(uc, head);
    for (std::size_t i = 0; i < kMaxWalk && node != 0 && node != head; ++i) {
        const auto base = read_u64(uc, node + 0x30);
        entries.emplace_back(base, node);
        node = read_u64(uc, node);
    }
    return entries;
}

// Reads the sample image's TLS callback array from guest memory: PE data
// directory 9 -> IMAGE_TLS_DIRECTORY64.AddressOfCallBacks -> NUL-terminated
// array of absolute VAs (the loader applied relocations before mapping).
std::vector<std::uint64_t> read_tls_callbacks(uc_engine* const uc, const std::uint64_t image_base)
{
    std::vector<std::uint64_t> callbacks;
    std::array<std::uint8_t, 0x1000> headers{};
    if (uc_mem_read(uc, image_base, headers.data(), headers.size()) != UC_ERR_OK) {
        return callbacks;
    }
    const auto read16 = [&](const std::size_t at) {
        return static_cast<std::uint16_t>(headers[at] | (headers[at + 1] << 8));
    };
    const auto read32 = [&](const std::size_t at) {
        return static_cast<std::uint32_t>(headers[at]) |
               (static_cast<std::uint32_t>(headers[at + 1]) << 8) |
               (static_cast<std::uint32_t>(headers[at + 2]) << 16) |
               (static_cast<std::uint32_t>(headers[at + 3]) << 24);
    };
    if (read16(0) != 0x5A4D) {
        return callbacks;
    }
    const auto pe = read32(0x3C);
    if (pe + 24 > headers.size() || read32(pe) != 0x00004550 || read16(pe + 24) != 0x20B) {
        return callbacks;
    }
    const auto optional = static_cast<std::size_t>(pe) + 24;
    const auto tls_rva = read32(optional + 0x70 + 9 * 8);
    if (tls_rva == 0) {
        return callbacks;
    }
    const auto directory = image_base + tls_rva;
    const auto callbacks_va = read_u64(uc, directory + 0x18);
    if (callbacks_va == 0) {
        return callbacks;
    }
    constexpr std::size_t kMaxCallbacks = 64;
    for (std::size_t i = 0; i < kMaxCallbacks; ++i) {
        const auto callback = read_u64(uc, callbacks_va + i * sizeof(std::uint64_t));
        if (callback == 0) {
            break;
        }
        callbacks.push_back(callback);
    }
    return callbacks;
}

} // namespace

std::vector<std::uint64_t> synthetic_world_bases(const GuestMode mode,
                                                 const std::filesystem::path& module_dir)
{
    const auto& core = mode == GuestMode::kX64 ? kBases64 : kBases86;
    // The three main bases always count: a container built with the
    // synthetic directory is recognizable even when the directory is not at
    // hand (the rebuild then reports the explicit missing-modules failure).
    std::vector<std::uint64_t> bases{core[0], core[1], core[2]};
    if (!module_dir.empty()) {
        const auto plan = plan_synthetic_directory(mode, module_dir);
        for (const auto index : plan.core_indices) {
            bases.push_back(core[index]);
        }
        for (std::size_t i = 0; i < plan.extras.size(); ++i) {
            bases.push_back(extra_module_base(mode, i));
        }
    }
    std::sort(bases.begin(), bases.end());
    bases.erase(std::unique(bases.begin(), bases.end()), bases.end());
    return bases;
}

std::size_t count_synthetic_module_pages(std::span<const mem_region::ModuleImage> images,
                                         std::span<const std::uint64_t> bases)
{
    // Exact equality only: real captures share the address bands and the
    // step, so interval or modulo membership would misfire (review P1).
    std::size_t hits = 0;
    for (const auto& image : images) {
        if (image.module.synthesized) {
            continue;
        }
        if (std::find(bases.begin(), bases.end(), image.module.base) != bases.end()) {
            ++hits;
        }
    }
    return hits;
}

std::expected<bool, SyscallRunError>
reattach_synthetic_world(PreparedGuest& guest, const std::filesystem::path& synthetic_module_dir)
{
    const auto bases = synthetic_world_bases(guest.guest_mode, synthetic_module_dir);
    // A single exact coincidence is not the synthetic world. Replay with a
    // directory present (the CLI locates one on every non-Windows run, so a
    // replayed capture container is judged against the full ~7-value set)
    // would silently graft the synthetic Ldr semantics onto a real capture
    // at roughly 1e-4 per module per replay; two distinct hits are either
    // the construction's resident core (every canonical-directory module
    // sits on the set) or a coincidence squared (~1e-8). A directory with
    // fewer than two set-resident modules has no CLI producer and cannot
    // produce a recognizable container - out of contract by construction.
    if (count_synthetic_module_pages(guest.images, bases) < 2) {
        return false;
    }
    if (synthetic_module_dir.empty()) {
        return std::unexpected(SyscallRunError::kSyntheticModulesMissing);
    }
    const auto uc = guest.unicorn.get();
    guest.loader_modules.clear();
    guest.loader_exports.clear();
    guest.intercepts.clear();
    guest.ldr_entry_vas.clear();
    guest.tls_callbacks.clear();
    for (const auto& image : guest.images) {
        if (image.module.synthesized) {
            continue;
        }
        loader::LoadedModule module;
        module.base = image.module.base;
        module.image.assign(static_cast<std::size_t>(image.module.size), std::uint8_t{0});
        if (uc_mem_read(uc, module.base, module.image.data(), module.image.size()) != UC_ERR_OK) {
            return std::unexpected(SyscallRunError::kUnicornFailure);
        }
        std::memcpy(module.name.data(), image.module.name.data(), module.name.size());
        if (!loader::index_exports(module).has_value()) {
            return std::unexpected(SyscallRunError::kUnicornFailure);
        }
        for (const auto& [name, va] : module.exports) {
            guest.loader_exports.push_back({module.base, va, name});
            // Forwarder entries carry the forwarder-string RVA, not a
            // callable VA; the construction never intercepts them either.
            if (va < module.base || va >= module.base + module.image.size()) {
                continue;
            }
            if (const auto id = intercept_id_for(name); id.has_value()) {
                guest.intercepts.emplace_back(va, *id);
            }
        }
        guest.loader_modules.push_back(image.module);
    }
    const auto entries = read_ldr_entries(uc, guest.metadata, guest.guest_mode);
    for (const auto& module : guest.loader_modules) {
        const auto found =
            std::find_if(entries.begin(), entries.end(),
                         [&module](const std::pair<std::uint64_t, std::uint64_t>& entry) {
                             return entry.first == module.base;
                         });
        if (found == entries.end()) {
            return std::unexpected(SyscallRunError::kBadSnapshot);
        }
        guest.ldr_entry_vas.push_back(found->second);
    }
    guest.tls_callbacks = read_tls_callbacks(uc, guest.metadata.image_base);
    guest.loader_route = true;
    return true;
}

} // namespace sheller::engine
