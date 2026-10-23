// Guest register snapshot: the engine-agnostic shape
// of the guest's register file. Upper layers read guest state through this
// type and never see the engine's register representation.

#ifndef SHELLER_GUEST_CONTEXT_H
#define SHELLER_GUEST_CONTEXT_H

#include <array>
#include <cstddef>
#include <cstdint>

namespace sheller {

// Number of general-purpose registers in the snapshot: Intel ordinal order,
// RAX=0 .. R15=15. Under the x86 (32-bit) mode R8..R15 stay zero.
inline constexpr std::size_t kGuestGprCount = 16;

struct GuestContext {
    std::array<std::uint64_t, kGuestGprCount> regs{}; // Intel ordinal order
    std::uint64_t rip{};                              // at a syscall interception: the resume RIP
    std::uint64_t rflags{};
};

static_assert(sizeof(GuestContext) == kGuestGprCount * sizeof(std::uint64_t) + 16,
              "GuestContext layout is part of the contract");

} // namespace sheller

#endif // SHELLER_GUEST_CONTEXT_H
