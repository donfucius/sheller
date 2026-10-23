#include "imports.h"

#include <algorithm>
#include <cstring>

namespace sheller::loader {
namespace {

constexpr std::uint32_t kDataDirectoryOffset64 = 112; // PE32+ optional+0x70
constexpr std::uint32_t kDataDirectoryOffset32 = 96;  // PE32  optional+0x60
constexpr std::size_t kMaxDescriptors = 256;          // import descriptors per image
constexpr std::size_t kMaxThunksPerDll = 8192;        // bounded walk
constexpr std::size_t kMaxForwardHops = 4;
constexpr std::size_t kMaxExportName = 255;

std::uint16_t read16(std::span<const std::uint8_t> bytes, std::size_t offset)
{
    if (offset + 2 > bytes.size()) {
        return 0;
    }
    return static_cast<std::uint16_t>(bytes[offset] |
                                      (static_cast<std::uint16_t>(bytes[offset + 1]) << 8));
}

std::uint32_t read32(std::span<const std::uint8_t> bytes, std::size_t offset)
{
    if (offset + 4 > bytes.size()) {
        return 0;
    }
    std::uint32_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

std::uint64_t read64(std::span<const std::uint8_t> bytes, std::size_t offset)
{
    if (offset + 8 > bytes.size()) {
        return 0;
    }
    std::uint64_t value = 0;
    std::memcpy(&value, bytes.data() + offset, sizeof value);
    return value;
}

void write32(std::span<std::uint8_t> bytes, std::size_t offset, std::uint32_t value)
{
    if (offset + 4 <= bytes.size()) {
        std::memcpy(bytes.data() + offset, &value, sizeof value);
    }
}

void write64(std::span<std::uint8_t> bytes, std::size_t offset, std::uint64_t value)
{
    if (offset + 8 <= bytes.size()) {
        std::memcpy(bytes.data() + offset, &value, sizeof value);
    }
}

// Thunk width and directory placement follow the optional header magic of
// the image being walked.
struct ImportLayout {
    std::size_t import_dir_offset{}; // file offset of DataDirectory[1].VA
    std::size_t thunk_size{};        // 8 (PE32+) or 4 (PE32)
    std::uint64_t ordinal_flag{};    // high bit of a thunk entry
};

ImportLayout detect_layout(std::span<const std::uint8_t> image)
{
    const auto pe = read32(image, 0x3C);
    // DataDirectory[1].VA is pe-relative: sig(4) + COFF(20) + the optional
    // header's pre-directory prefix, then one 8-byte directory slot. A fixed
    // offset only fits hand-built images with a minimal DOS header.
    const auto import_dir = [&](const std::uint32_t prefix) -> std::size_t {
        return static_cast<std::size_t>(pe) + 24 + prefix + 8;
    };
    ImportLayout pe32plus{import_dir(kDataDirectoryOffset64), 8, 1ULL << 63};
    if (pe == 0 || pe + 4 + 20 + 2 > image.size() || read32(image, pe) != 0x00004550) {
        return pe32plus;
    }
    if (read16(image, pe + 4 + 20) == 0x010B) {
        return ImportLayout{import_dir(kDataDirectoryOffset32), 4, 1ULL << 31};
    }
    return pe32plus;
}

// NUL-terminated ASCII string at an RVA, bounded.
std::string read_c_string(std::span<const std::uint8_t> bytes, std::size_t offset)
{
    if (offset >= bytes.size()) {
        return {};
    }
    const auto end = std::min(bytes.size(), offset + kMaxExportName + 1);
    std::string out;
    for (auto i = offset; i < end; ++i) {
        if (bytes[i] == 0) {
            break;
        }
        out.push_back(static_cast<char>(bytes[i]));
    }
    return out;
}

std::string fold(std::string_view name)
{
    std::string out;
    for (const char c : name) {
        out.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
    }
    return out;
}

// The export directory's span: DataDirectory[0] {VA, Size}. The size MUST
// come from the directory entry - the struct's own +4 field is
// TimeDateStamp (zero in freshly generated synthetic modules, which would
// fail a size guard and empty the index).
std::pair<std::uint32_t, std::uint32_t> export_dir_bounds(std::span<const std::uint8_t> image)
{
    const auto pe = read32(image, 0x3C);
    if (pe == 0 || pe + 4 + 20 + 128 > image.size() || read32(image, pe) != 0x00004550) {
        return {};
    }
    // DataDirectory placement follows the optional header magic (the export
    // directory itself is identically laid out for both magics)
    const auto dirs =
        read16(image, pe + 4 + 20) == 0x010B ? kDataDirectoryOffset32 : kDataDirectoryOffset64;
    return {read32(image, pe + 4 + 20 + dirs), read32(image, pe + 4 + 20 + dirs + 4)};
}

} // namespace

std::string_view api_set_host(const std::string_view folded_name)
{
    if (folded_name.rfind("api-ms-win-crt-", 0) == 0) {
        return "ucrtbase.dll";
    }
    if (folded_name.rfind("api-ms-win-", 0) == 0) {
        return "kernelbase.dll";
    }
    return {};
}

std::expected<void, LoadError> index_exports(LoadedModule& module)
{
    module.exports.clear();
    const auto d = std::span<const std::uint8_t>(module.image);
    const auto [export_rva, export_size] = export_dir_bounds(d);
    if (export_rva == 0 || export_size == 0 || export_rva >= d.size()) {
        return {}; // no exports: legal (data-only image)
    }
    const auto number_of_names = read32(d, export_rva + 0x18); // NumberOfNames
    const auto names_va = read32(d, export_rva + 0x20);        // AddressOfNames
    const auto ordinals_va = read32(d, export_rva + 0x24);     // AddressOfNameOrdinals
    const auto functions_va = read32(d, export_rva + 0x1C);    // AddressOfFunctions
    const auto bounded = std::min<std::uint32_t>(number_of_names, 8192);
    module.exports.reserve(bounded);
    for (std::uint32_t i = 0; i < bounded; ++i) {
        const auto name_rva = read32(d, names_va + 4 * i);
        if (name_rva == 0 || name_rva >= d.size()) {
            continue;
        }
        const auto ordinal = read16(d, ordinals_va + 2 * i);
        const auto function_rva = read32(d, functions_va + 4ULL * ordinal);
        if (function_rva == 0) {
            continue;
        }
        auto name = read_c_string(d, name_rva);
        if (name.empty()) {
            continue;
        }
        // forwarder entries keep the forwarder string as their "function"
        // address: resolve_export walks them at lookup time
        module.exports.emplace_back(std::move(name), module.base + function_rva);
    }
    std::ranges::sort(module.exports, std::ranges::less{}, [](const auto& e) { return e.first; });
    return {};
}

ResolvedExport resolve_export(const std::vector<LoadedModule>& modules,
                              std::string_view module_name, std::string_view function_name)
{
    const auto find_module = [&](std::string_view name) -> const LoadedModule* {
        // API-set names reduce to their host module before any module
        // lookup (the schema pre-pass): a set name itself never matches a
        // resident image, and forwarder chains name hosts deterministically
        // instead of searching.
        auto folded = fold(name);
        if (const auto host = api_set_host(folded); !host.empty()) {
            folded = std::string(host);
        }
        for (const auto& module : modules) {
            const auto module_folded = fold(std::string_view(module.name.data()));
            if (module_folded == folded || module_folded == folded + ".dll") {
                return &module;
            }
        }
        return nullptr;
    };
    const LoadedModule* current = find_module(module_name);
    if (current == nullptr) {
        return {};
    }
    std::string function{function_name};
    for (std::size_t hop = 0; hop <= kMaxForwardHops; ++hop) {
        const auto it = std::ranges::lower_bound(current->exports, function, std::ranges::less{},
                                                 [](const auto& e) { return e.first; });
        if (it == current->exports.end() || it->first != function) {
            return {};
        }
        const auto function_va = it->second;
        // forwarder detection: the function RVA points inside the export
        // directory, where the forwarder string ("dll.func") lives
        const auto d = std::span<const std::uint8_t>(current->image);
        const auto [export_rva, export_size] = export_dir_bounds(d);
        const auto function_rva = static_cast<std::uint32_t>(function_va - current->base);
        const bool forwarded = export_size != 0 && function_rva >= export_rva &&
                               function_rva < export_rva + export_size;
        if (!forwarded) {
            return ResolvedExport{.ok = true,
                                  .forwarded = hop != 0,
                                  .va = function_va,
                                  .module = current,
                                  .final_name = std::string(function_name)};
        }
        const auto forwarder = read_c_string(d, export_rva + (function_rva - export_rva));
        const auto dot = forwarder.find('.');
        if (dot == std::string::npos) {
            return {};
        }
        const auto next_module = std::string_view(forwarder).substr(0, dot);
        function = std::string(std::string_view(forwarder).substr(dot + 1));
        const LoadedModule* next = find_module(next_module);
        if (next == nullptr) {
            // host module not resident: the import fails, exactly like the
            // real loader when a forwarder's DLL cannot be loaded. api-ms
            // names reduce to their host in find_module, so every hop has a
            // concrete target and the walk cannot cycle.
            return {};
        }
        current = next;
    }
    return {};
}

std::expected<std::vector<ImportFixup>, LoadError>
resolve_imports(std::span<std::uint8_t> image, const std::vector<LoadedModule>& modules,
                std::vector<UnresolvedImport>* unresolved)
{
    std::vector<ImportFixup> fixups;
    const auto layout = detect_layout(image);
    const auto import_rva = read32(image, layout.import_dir_offset); // DataDirectory[1].VA
    if (import_rva == 0 || import_rva >= image.size()) {
        return fixups; // no imports: clean no-op
    }

    auto offset = static_cast<std::size_t>(import_rva);
    for (std::size_t d = 0; d < kMaxDescriptors; ++d, offset += 20) {
        const auto original_thunk = read32(image, offset);
        const auto name_rva = read32(image, offset + 12);
        const auto first_thunk = read32(image, offset + 16);
        if (original_thunk == 0 && name_rva == 0 && first_thunk == 0) {
            break; // terminating descriptor
        }
        if (name_rva == 0 || first_thunk == 0 || name_rva >= image.size()) {
            continue;
        }
        const auto dll_name = read_c_string(image, name_rva);
        const auto thunk_array = original_thunk != 0 ? original_thunk : first_thunk;
        for (std::size_t t = 0; t < kMaxThunksPerDll; ++t) {
            const auto thunk_rva = first_thunk + t * layout.thunk_size;
            const auto lookup_rva = thunk_array + t * layout.thunk_size;
            if (lookup_rva + layout.thunk_size > image.size()) {
                break;
            }
            const auto thunk =
                layout.thunk_size == 8 ? read64(image, lookup_rva) : read32(image, lookup_rva);
            if (thunk == 0) {
                break; // terminator
            }
            // import-by-name: low dword = hint/name RVA, ordinal flag set =
            // import-by-ordinal (recorded, skipped)
            if ((thunk & layout.ordinal_flag) != 0) {
                if (unresolved != nullptr) {
                    unresolved->push_back({fold(dll_name), "<ordinal>"});
                }
                continue;
            }
            const auto function_name =
                read_c_string(image, static_cast<std::size_t>(thunk & 0xFFFFFFFF) + 2);
            const auto resolved = resolve_export(modules, dll_name, function_name);
            if (!resolved.ok) {
                if (unresolved != nullptr) {
                    unresolved->push_back({fold(dll_name), std::string(function_name)});
                }
                continue;
            }
            if (layout.thunk_size == 8) {
                write64(image, thunk_rva, resolved.va);
            } else {
                write32(image, thunk_rva, static_cast<std::uint32_t>(resolved.va));
            }
            fixups.push_back({thunk_rva, resolved.va});
        }
    }
    return fixups;
}

} // namespace sheller::loader
