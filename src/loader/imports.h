// Loader import resolution: IAT walk and
// export lookup with bounded forwarder chaining, over host-side module
// images. Pure byte functions - no unicorn - so resolution is unit-testable
// and deterministic. Unresolvable thunks are recorded, never fatal (the
// IAT-repair "best effort" principle).

#ifndef SHELLER_LOADER_IMPORTS_H
#define SHELLER_LOADER_IMPORTS_H

#include "loader.h"

#include <array>

#include <string>
#include <vector>

namespace sheller::loader {

// One mapped module's host-side view: image bytes at SizeOfImage, folded
// lowercase name, and its export name->function-VA index.
struct LoadedModule {
    std::uint64_t base{};
    std::vector<std::uint8_t> image; // SizeOfImage bytes
    std::array<char, 64> name{};     // folded lowercase with extension
    // name-sorted export index (exact-match lookup)
    std::vector<std::pair<std::string, std::uint64_t>> exports;
};

// Parses the module's export directory into the name-sorted index. Forwarder
// entries are flagged: their "address" is the RVA of the forwarder string
// inside the export directory.
std::expected<void, LoadError> index_exports(LoadedModule& module);

// API Set Schema pre-pass (real loader: PEB.ApiSetMap): an api-ms-win-* set
// name reduces to its host DLL name before any module or export lookup - the
// set name itself is never a module. Static prefix rules cover the real
// schema (the crt sets are hosted by ucrtbase, the core/shell sets by
// kernelbase). Takes and returns folded names; empty when not a set.
std::string_view api_set_host(std::string_view folded_name);

struct ResolvedExport {
    bool ok{};                    // false: unresolvable (recorded by the caller)
    bool forwarded{};             // the export was a forwarder string
    std::uint64_t va{};           // resolved function VA (ok && !forwarded)
    const LoadedModule* module{}; // owning module of the final resolution
    std::string final_name{};     // final resolved function name
};

// Exact-name export lookup in one module. A forwarder entry ("dll.func")
// starts a bounded chain across `modules` (up to 4 hops); the final stop's
// function VA wins and `module`/`final_name` describe it.
ResolvedExport resolve_export(const std::vector<LoadedModule>& modules,
                              const std::string_view module_name,
                              const std::string_view function_name);

struct ImportFixup {
    std::uint64_t iat_rva{};  // image RVA of the IAT slot written
    std::uint64_t resolved{}; // function VA written into the slot
};

struct UnresolvedImport {
    std::string dll_name{};
    std::string function_name{};
};

// Walks the sample image's import directory and resolves every thunk against
// `modules`, writing resolved VAs into the FirstThunk array in place.
// Unresolvable thunks are appended to `unresolved` (never fatal). The
// import directory is optional: absent (RVA 0) is a clean no-op.
std::expected<std::vector<ImportFixup>, LoadError>
resolve_imports(std::span<std::uint8_t> image, const std::vector<LoadedModule>& modules,
                std::vector<UnresolvedImport>* unresolved);

} // namespace sheller::loader

#endif // SHELLER_LOADER_IMPORTS_H
