// Exception plumbing: the engine hooks record exception
// facts and stop the emulation; the run loop synthesizes the dispatch
// between legs. This module owns the INTR / invalid-memory hooks, the
// NtRaiseException / NtContinue / NtQueryVirtualMemory applies, and the
// kernel-faithful CONTEXT/EXCEPTION_RECORD synthesis into the real ntdll
// dispatcher (fidelity mode) beside the event emitters both dispatch modes
// share.

#ifndef SHELLER_ENGINE_EXCEPTION_PIPELINE_H
#define SHELLER_ENGINE_EXCEPTION_PIPELINE_H

#include "rebuild_state.h"

namespace sheller::engine {

// Interrupt hook: software exceptions surface here. Breakpoint vectors
// dispatch; __fastfail bypasses every handler by definition and any other
// vector has no accepted mapping - both crash without dispatch. x86 guests
// additionally route the 0x2E system-service vector here.
void on_intr_callback(uc_engine* const uc, const std::uint32_t vector, void* const user_data);

// Invalid-memory hook: unmapped or access-protected faults surface here with
// the access kind and faulting address in hand.
bool on_mem_invalid_callback(uc_engine* const uc, const uc_mem_type type,
                             const std::uint64_t address, const int, const std::int64_t,
                             void* const user_data);

// NtContinue: the x86 dispatch resumes the interrupted context through
// this syscall (KiUserExceptionDispatcher's tail after the walk succeeds).
// The engine applies the passed CONTEXT to the machine and the run loop
// resumes at its Eip; like NtRaiseException the caller's flow never returns.
void apply_continue(SyscallRunState* state, uc_engine* const uc,
                    const syscalls::SyscallFrame& frame);

// NtRaiseException: the kernel re-dispatches the passed record
// against the passed context; a last-chance raise never returns - the
// process dies on the crash-fallback path. Callers run this after the
// syscall ABI synthesis so the adopted context registers win; both hook
// sites stop the leg right after.
void apply_raise_exception(SyscallRunState* state, uc_engine* const uc,
                           const syscalls::SyscallFrame& frame);

// NtQueryVirtualMemory: answers MemoryBasicInformation from the
// region map - the declaration for the hook sites below.
void apply_query_virtual_memory(SyscallRunState* state, uc_engine* const uc,
                                const syscalls::SyscallFrame& frame,
                                syscalls::SyscallOutcome& outcome);

// Outcome of one exception synthesis: dispatched into the real ntdll code,
// unhandled (crash fallback), or an engine-side resolution failure.
enum class DispatchOutcome { kDispatched, kUnhandled, kEngineError };

DispatchOutcome synthesize_and_dispatch(PreparedGuest& guest, SyscallRunState& state);

void emit_exception_event(SyscallRunState& state, const std::uint32_t code, const std::uint64_t pc,
                          const bool last_chance, const std::uint64_t related_pc = 0);

// The handler-dispatch report: the engine-side dispatcher staged a guest
// handler callback. Not an exception - the exception counters stay
// untouched; pc is the handler entry, related_pc the fault that selected it.
void emit_handler_dispatch_event(SyscallRunState& state, const std::uint32_t code,
                                 const std::uint64_t handler_pc, const std::uint64_t fault_pc);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_EXCEPTION_PIPELINE_H
