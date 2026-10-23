// Shared syscall dispatch: the policy-table answer plus its side effects,
// counters, and completed-call event; the x64 syscall-instruction hook; and
// the ISA/CFG environment-normalization passes the run loop applies before
// the first leg.

#ifndef SHELLER_ENGINE_SYSCALL_DISPATCH_H
#define SHELLER_ENGINE_SYSCALL_DISPATCH_H

#include "rebuild_state.h"

namespace sheller::engine {

// Shared syscall dispatch: event, policy answer, allocation/protect side
// effects, counters. The caller synthesizes the instruction-specific ABI
// (x64 syscall vs x86 int 2e) and handles termination.
syscalls::SyscallOutcome dispatch_one_syscall(SyscallRunState* state, uc_engine* const uc,
                                              const syscalls::SyscallFrame& frame);

void on_syscall_callback(uc_engine* const uc, void* const user_data);

void normalize_isa_feature_gates(uc_engine* const uc, const mem_region::MemRegionMap& map);

void normalize_scp_cfg_gate(uc_engine* const uc, const std::uint64_t ntdll_base,
                            const std::uint64_t ntdll_size);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_SYSCALL_DISPATCH_H
