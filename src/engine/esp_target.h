// ESP-law stop target: the product form of the entry
// save window. The window is the entry's contiguous push prefix, scanned
// once per run with Zydis and clamped at 64 bytes (the extent is
// a per-sample fact, not a global constant; the data-slot pushes and the
// nested-call return slot sit below the prefix and stay out of the window).
// A range-scoped UC_HOOK_MEM_READ over [S-extent, S) feeds the confirmation
// state machine; everything here is opt-in (an esp stop goal requested) and
// a run that never asks pays one null check per option copy.
//
// Confirmation criteria, adjudicated form:
//   1. the read lands in the window;
//   2. the reader decodes as a pop of a register (the closed confirmation
//      set the probe's tables seeded: pop family; equivalent read-back
//      forms extend the set only with evidence);
//   3. the RSP criterion: unicorn calls read hooks before the instruction's
//      rsp write-back (the probe's micro-experiment fact), so a genuine pop
//      reads with callback rsp == the slot address; the restore is complete
//      at the read where rsp + access width == the entry rsp.
// A read that satisfies the window but not the decode (an anti-debug probe
// of its own save area, or a later frame reusing the region) is not a
// restore: the run continues on the miss path, never stops.
//
// Known silent-miss shape (DLL inputs): UPX-class DllMain stubs open with
// argument-shadow stores and a reason branch before their register saves,
// so the contiguous-prefix scan finds no pushes at the entry and the
// monitor never arms. `--stop xfer=1` is the usable stop face there - the
// stub's post-restore jump to the unpacked entry is the first counted
// transfer.
#ifndef SHELLER_ENGINE_ESP_TARGET_H
#define SHELLER_ENGINE_ESP_TARGET_H

#include "rebuild_state.h"

namespace sheller::engine::esp_target {

// The 64-byte cap: an upper clamp on the static extent.
inline constexpr std::uint64_t kExtentCap = 64;

// Scans the entry's contiguous push prefix and registers the range-scoped
// read hook on the run state whenever the prefix is non-empty - the monitor
// is the default passive observation (every confirmed restore emits
// kStackRestore to the event sink, no stop goal required); the stop and the
// arm are what the goal turns on. Called from run_syscalls after the
// TLS-callback legs and before the main loop, so S is the world's starting
// rsp (samples with entry TLS callbacks leave their own frame on the stack:
// their window would sit below the true save area, which lands them on the
// documented silent-miss path, same as the VM shape).
void install(uc_engine* uc, const PreparedGuest& guest, SyscallRunState& state);

// DLL-input route: re-arms the monitor at the synthesized module's
// DllMain entry once the synthetic load has armed its frame - the world's
// starting registers belong to the runner here, and the unpack-relevant
// entry scene is DllMain's. Deletes the runner-entry hook first; a goal
// that was never requested stays a no-op.
void reinstall_at(uc_engine* uc, std::uint64_t entry_va, SyscallRunState& state);

} // namespace sheller::engine::esp_target

#endif // SHELLER_ENGINE_ESP_TARGET_H
