// Real syscall number resolution: ntdll's Nt*
// stubs embed their syscall number as `mov eax, imm32` - invisible in any
// table and build-dependent. This module enumerates a module's PE exports and
// decodes each stub immediate per Nt-prefixed export, producing the
// number<->name pairs the policy registration translates by function name.
// Runs once at prepare; guest reads are bounded and undecodable stubs are
// skipped deterministically. The unicorn handle is forward
// declared so this header keeps the syscalls module free of third-party
// includes.

#ifndef SHELLER_SYSCALLS_NUMBER_MAP_H
#define SHELLER_SYSCALLS_NUMBER_MAP_H

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

struct uc_struct;
typedef struct uc_struct uc_engine;

namespace sheller::syscalls {

// Name capacity: the longest ntdll export name is far below this bound.
inline constexpr std::size_t kExportNameBytes = 64;

struct ExportedFunction {
    std::uint64_t address{}; // guest VA (module base + function RVA)
    // guest VA of this export's slot in the functions array - the address a
    // walking reader touches to resolve the export (behavior-layer signal).
    std::uint64_t slot_va{};
    std::array<char, kExportNameBytes> name{};
};

// Walks the module's PE export directory (names / ordinals / functions).
// Forwarders (function RVA inside the export directory) are skipped - they
// are not callable code in this image.
std::vector<ExportedFunction> enumerate_exports(uc_engine* uc, std::uint64_t module_base);

struct SyscallNumberEntry {
    std::uint32_t number{};
    std::array<char, kExportNameBytes> name{};
};

// The syscall immediate of the canonical ntdll stub (mov r10, rcx;
// mov eax, imm32) at function_va, or nullopt when the bytes are not that
// canonical prefix.
std::optional<std::uint32_t> syscall_stub_number(uc_engine* uc, std::uint64_t function_va);

// All Nt-prefixed exports of ntdll whose stub decodes to a syscall number.
std::vector<SyscallNumberEntry> enumerate_ntdll_syscalls(uc_engine* uc, std::uint64_t ntdll_base);

// Resolves one export by exact name via a bounded enumeration; nullopt when
// absent or a forwarder.
std::optional<std::uint64_t> resolve_export(uc_engine* uc, std::uint64_t module_base,
                                            std::string_view name);

} // namespace sheller::syscalls

#endif // SHELLER_SYSCALLS_NUMBER_MAP_H
