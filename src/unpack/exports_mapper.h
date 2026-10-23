// ExportsMapper: registers each snapshot module's
// export table from its rebuilt image bytes and answers
// address -> "module!function" lookups for the IAT repair. Implemented over
// the engine's own PE walking - no peconv; portable across hosts since the
// Linux unpack route. The repair pipeline is the only consumer.

#ifndef SHELLER_UNPACK_EXPORTS_MAPPER_H
#define SHELLER_UNPACK_EXPORTS_MAPPER_H

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace sheller::unpack {

class ExportsMapper {
  public:
    ExportsMapper() = default;

    // Registers one module's exports from its rebuilt image bytes; returns
    // the number of registered exports (a parse failure registers zero - the
    // module then resolves nothing and the coverage report reflects it).
    std::size_t add_module(const std::string& module_name, std::uint64_t base,
                           const std::uint8_t* image, std::size_t size);

    struct Resolved {
        std::string module;
        std::string function; // export name, or "#<ordinal>"
    };

    // Interval attribution: the export whose computed VA is the nearest at or
    // below this one (the loader's semantic - IAT thunks point at exact
    // exports, but honouring the interval keeps the lookup total).
    std::optional<Resolved> resolve(std::uint64_t va) const;

    // Exact-address attribution: the registered export whose computed VA
    // equals this one. The dump's resolved IAT slots carry precise addresses,
    // and a gap VA must stay uncovered instead of borrowing a neighbour's
    // name.
    std::optional<Resolved> resolve_exact(std::uint64_t va) const;

  private:
    // Exact export VAs registered by add_module: VA -> attribution. Kept
    // alongside the interval lookup because the repair audit must not
    // attribute a gap VA to a neighbouring export.
    std::map<std::uint64_t, Resolved> exact_;
    // Forwarded exports whose target was not yet registered: deferred until
    // the target module appears (add_module order is snapshot-dependent).
    struct PendingForwarder {
        std::uint64_t forwarder_va;
        std::string target_module; // folded, with extension
        std::string target_function;
    };
    std::vector<PendingForwarder> pending_forwarders_;
    bool forwarders_associated_{true}; // nothing deferred yet
};

} // namespace sheller::unpack

#endif // SHELLER_UNPACK_EXPORTS_MAPPER_H
