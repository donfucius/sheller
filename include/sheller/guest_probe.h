// Fault-free guest memory access: consumers such as
// the dump engine and the detection rules probe guest memory through this
// interface. Every failure -- unmapped, protected, bad pointer -- is
// expressed as a false return; the contract never crashes the caller and
// never throws. The engine provides the implementation on top of its own
// machinery.

#ifndef SHELLER_GUEST_PROBE_H
#define SHELLER_GUEST_PROBE_H

#include <cstddef>
#include <cstdint>

namespace sheller {

class GuestProbe {
  public:
    virtual ~GuestProbe() = default;

    [[nodiscard]] virtual bool read_mem(std::uint64_t addr, void* buf, std::size_t len) = 0;
    [[nodiscard]] virtual bool write_mem(std::uint64_t addr, const void* buf, std::size_t len) = 0;
};

} // namespace sheller

#endif // SHELLER_GUEST_PROBE_H
