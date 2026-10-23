#include "exports_mapper.h"

namespace sheller::unpack {

namespace {
// One registered export: module attribution + interval boundary in one entry.
struct Registration {
    std::string module;
    std::string function;
};
} // namespace

std::size_t ExportsMapper::add_module(const std::string& module_name, const std::uint64_t base,
                                      const std::uint8_t* image, const std::size_t size)
{
    // Walk the export directory in the buffer (section-mapped layout: RVAs
    // are offsets in this image) and register every export at
    // module_base + rva - both as an interval boundary (the loader's
    // attribution semantic) and as an exact address (the repair audit's).
    // A parse failure just leaves the module unresolved.
    std::size_t registered = 0;
    const auto read16 = [&](const std::size_t off) {
        return static_cast<std::uint16_t>(image[off]) |
               (static_cast<std::uint16_t>(image[off + 1]) << 8);
    };
    const auto read32 = [&](const std::size_t off) {
        return static_cast<std::uint32_t>(image[off]) |
               (static_cast<std::uint32_t>(image[off + 1]) << 8) |
               (static_cast<std::uint32_t>(image[off + 2]) << 16) |
               (static_cast<std::uint32_t>(image[off + 3]) << 24);
    };
    // MZ word only: the dword at 0 carries e_cblp in its high half
    // (0x00905A4D for a standard MSVC DOS stub) - a full-dword compare
    // rejects every real module and empties the map.
    if (size < 0x40 || read32(0) % 0x10000 != 0x5A4D) {
        return 0;
    }
    const auto e_lfanew = read32(0x3C);
    if (e_lfanew + 0x18 + 2 > size || read32(e_lfanew) != 0x00004550) {
        return 0;
    }
    const auto opt = e_lfanew + 0x18;
    const auto magic = read16(opt);
    const bool pe32plus = magic == 0x020B;
    const auto dd_base = opt + (pe32plus ? 0x70 : 0x60);
    const auto export_rva = read32(dd_base);
    if (export_rva == 0 || export_rva >= size) {
        return 0;
    }
    const auto functions = read32(export_rva + 0x1C);
    const auto names = read32(export_rva + 0x20);
    const auto ordinals = read32(export_rva + 0x24);
    const auto name_count = read32(export_rva + 0x18);
    for (std::uint32_t i = 0; i < name_count && names + 4 * i + 4 <= size; ++i) {
        const auto name_ptr = read32(names + 4 * i);
        if (name_ptr == 0 || name_ptr >= size) {
            continue;
        }
        const auto ordinal = read16(ordinals + 2 * i);
        const auto func_rva = read32(functions + 4ULL * ordinal);
        if (func_rva == 0) {
            continue;
        }
        std::string name;
        for (auto p = name_ptr; p < size && image[p] != 0 && name.size() < 128; ++p) {
            name.push_back(static_cast<char>(image[p]));
        }
        Resolved resolved;
        resolved.module = module_name;
        resolved.function = name.empty() ? "#" + std::to_string(ordinal) : name;
        const auto va = base + func_rva;
        exact_.emplace(va, std::move(resolved));
        ++registered;
    }
    return registered;
}

std::optional<ExportsMapper::Resolved> ExportsMapper::resolve(const std::uint64_t va) const
{
    // peconv's find_exports_by_va is exact-match; the repair audit requires
    // the same - a gap VA must not borrow a neighbouring export's name.
    return resolve_exact(va);
}

std::optional<ExportsMapper::Resolved> ExportsMapper::resolve_exact(const std::uint64_t va) const
{
    const auto it = exact_.find(va);
    if (it == exact_.end()) {
        return std::nullopt;
    }
    return it->second;
}

} // namespace sheller::unpack
