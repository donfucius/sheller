// API parameter descriptions (semantic layer):
// positional parameter-name tables for Win32 exports (keyed module+name)
// and Nt functions (keyed by name - call numbers drift across builds,
// names do not). Pure data + queries, engine-agnostic: no unicorn, no
// Windows headers. Absent entries degrade to positional argN names at the
// render - a missing description never fails a lookup.

#ifndef SHELLER_BEHAVIOR_API_DESCRIPTIONS_H
#define SHELLER_BEHAVIOR_API_DESCRIPTIONS_H

#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::behavior {

struct ApiDescription {
    std::string_view module;         // "ntdll" marks an Nt-layer (name-keyed) row;
                                     // anything else is a folded Win32 module name
    std::string_view name;           // export/function name ("LoadLibraryA")
    std::vector<std::string> params; // positional form-parameter names
};

class ApiDescriptionTable {
  public:
    void add(const ApiDescription& description);

    // Win32 lookup by folded module name + export name.
    const std::vector<std::string>* find(std::string_view module, std::string_view name) const;
    // Nt lookup by function name (second hop of the syscall join).
    const std::vector<std::string>* find_nt(std::string_view name) const;
    std::size_t size() const
    {
        return win32_.size() + nt_.size();
    }

    // Fills the render-side name map: Nt functions under their plain name
    // (syscall second hop), Win32 functions under "module!name" (apicall).
    void fill_apicall_params(std::map<std::string, std::vector<std::string>>& out) const;

  private:
    std::map<std::pair<std::string, std::string>, std::vector<std::string>> win32_{};
    std::map<std::string, std::vector<std::string>> nt_{};
};

// The seed table: generated from the apimonitor API definition corpus by
// tools/gen_api_descriptions.py (source manifest and regenerate command in
// the seed file header). Deterministic - regenerating from the pinned
// manifest reproduces the same bytes.
const ApiDescriptionTable& default_descriptions();

// Win32 -> Nt layer-name equivalents for the route-comparison view only;
// the fact layer never synthesizes Nt events from Win32 calls.
std::map<std::string, std::string> win32_nt_equivalents();

} // namespace sheller::behavior

#endif // SHELLER_BEHAVIOR_API_DESCRIPTIONS_H
