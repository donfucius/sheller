// The run stage: bounded execution paths over a rebuilt guest - the entry
// proof and the syscall run loop. Construction lives in loader_route.*; the
// public facades that compose rebuild + run live in rebuild.cpp.

#ifndef SHELLER_ENGINE_RUN_H
#define SHELLER_ENGINE_RUN_H

#include "rebuild_state.h"
#include <sheller/syscallrun.h>

#include <expected>

namespace sheller::engine {

// A completed entry-proof run: the live Unicorn instance (kept alive so the
// probe can read state back) plus the verdict statistics.
struct BoundedRun {
    UnicornEngine unicorn{nullptr};
    RebuildStats stats{};
};

// Entry proof: spin on the patched entry for a fixed instruction count.
std::expected<BoundedRun, RebuildFailure> run_entry_proof(PreparedGuest& guest);

// Syscall run: rebuild, attach the policy, execute until the guest
// terminates or the budget/timeout expires. The fact channel (the rules
// layer's internal seam) rides beside the options, not on them.
std::expected<SyscallRunStats, SyscallRunFailure>
run_syscalls(PreparedGuest& guest, const SyscallRunOptions& options, const FactChannel& facts);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_RUN_H
