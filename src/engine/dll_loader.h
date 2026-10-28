// DLL-input synthetic loading (dll-loading capability): when the guest calls
// an intercepted LoadLibrary with the pending module's name, the engine
// constructs the module inside the emulated world - map, relocate, resolve
// IAT against the resident modules, link the Ldr chains, schedule TLS -
// then arms a synthetic ATTACH frame into DllMain whose return lands on the
// continuation slot below. The slot is a registered intercept: the handler
// converts DllMain's verdict into the LoadLibrary answer (handle / NULL) and
// resumes the caller. The pending module never ran a byte on the host.

#ifndef SHELLER_ENGINE_DLL_LOADER_H
#define SHELLER_ENGINE_DLL_LOADER_H

#include "rebuild_state.h"

#include <optional>
#include <string>

namespace sheller::engine {

// Continuation-slot intercept VA: a dedicated page far outside both the
// captured-world band and the loader-route fixed band. One byte of `ret`
// lives there as a decode fallback; the code hook claims execution before
// the byte ever runs.
inline constexpr std::uint64_t kDllResumeSlotVa = 0x500000000000ULL;

// Maps the resume-slot page and registers its intercept in the run state.
// No-op when no pending module travels with the guest.
void arm_dll_resume_slot(SyscallRunState& state, uc_engine* uc);

// Synthetic load of the pending module on an intercepted LoadLibrary hit.
// On success the ATTACH/TLS frame chain is armed and the caller's resume
// site is recorded - do NOT intercept_return (the call is still in flight;
// dll_load_resume finishes it). Returns an error string on a construction
// failure (the caller answers NULL); nullopt = frames armed or reused.
std::optional<std::string> synthesize_pending_load(SyscallRunState& state);

// Continuation-slot handler: TLS callbacks advance the chain, DllMain's
// verdict finishes the LoadLibrary answer (handle / NULL + rollback).
void dll_load_resume(SyscallRunState& state);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_DLL_LOADER_H
