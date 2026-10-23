// API parameter descriptions - implementation.
// The seed rows are generated; this file only wires the query structures.

#include "api_descriptions.h"

#include "../syscalls/win32_nt_equivalence.h"

namespace sheller::behavior {
namespace {

// One generated row: module ("" = Nt), name, and the positional parameter
// names as a comma-joined string (constexpr-friendly; split once at init).
struct SeedRow {
    std::string_view module;
    std::string_view name;
    std::string_view joined_params;
};

constexpr SeedRow kSeedDescriptions[] = {
#include "api_descriptions_seed.inc"
};

std::vector<std::string> split_params(const std::string_view joined)
{
    std::vector<std::string> params;
    std::size_t start = 0;
    while (start <= joined.size()) {
        const auto comma = joined.find(',', start);
        if (comma == std::string_view::npos) {
            if (start < joined.size()) {
                params.emplace_back(joined.substr(start));
            }
            break;
        }
        params.emplace_back(joined.substr(start, comma - start));
        start = comma + 1;
    }
    return params;
}

} // namespace

void ApiDescriptionTable::add(const ApiDescription& description)
{
    // ntdll = the Nt layer: name-keyed (call numbers drift across builds,
    // names do not). Every other module is Win32: (module, name)-keyed.
    if (description.module == "ntdll") {
        nt_.emplace(description.name, description.params);
        return;
    }
    win32_.emplace(std::pair<std::string, std::string>{description.module, description.name},
                   description.params);
}

const std::vector<std::string>* ApiDescriptionTable::find(const std::string_view module,
                                                          const std::string_view name) const
{
    const auto it = win32_.find({std::string{module}, std::string{name}});
    return it != win32_.end() ? &it->second : nullptr;
}

const std::vector<std::string>* ApiDescriptionTable::find_nt(const std::string_view name) const
{
    const auto it = nt_.find(std::string{name});
    return it != nt_.end() ? &it->second : nullptr;
}

void ApiDescriptionTable::fill_apicall_params(
    std::map<std::string, std::vector<std::string>>& out) const
{
    for (const auto& [key, params] : nt_) {
        out.insert_or_assign(key, params);
    }
    for (const auto& [key, params] : win32_) {
        out.insert_or_assign(key.first + "!" + key.second, params);
    }
}

const ApiDescriptionTable& default_descriptions()
{
    static ApiDescriptionTable table = [] {
        ApiDescriptionTable t;
        for (const auto& row : kSeedDescriptions) {
            t.add({row.module, row.name, split_params(row.joined_params)});
        }
        return t;
    }();
    return table;
}

std::map<std::string, std::string> win32_nt_equivalents()
{
    // Forwarding view over the engine-domain table:
    // the interception layer is the primary consumer; presentation keeps
    // the same pairs for the route-comparison view.
    std::map<std::string, std::string> out;
    for (const char* const win32 :
         {"VirtualAlloc", "VirtualProtect", "VirtualFree", "LoadLibraryA", "LoadLibraryW",
          "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "ExitProcess"}) {
        if (const auto nt = syscalls::win32_nt_equivalent(win32)) {
            out.emplace(win32, std::string{*nt});
        }
    }
    return out;
}

} // namespace sheller::behavior
