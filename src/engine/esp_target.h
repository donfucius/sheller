// ESP-law stop target (change esp-law-oep): the product form of the entry
// save window. The window is the entry's contiguous push prefix, scanned
// once per run with Zydis and clamped at 64 bytes (design D3: the extent is
// a per-sample fact, not a global constant; the data-slot pushes and the
// nested-call return slot sit below the prefix and stay out of the window).
// A range-scoped UC_HOOK_MEM_READ over [S-extent, S) feeds the confirmation
// state machine; everything here is opt-in (an esp stop goal requested) and
// a run that never asks pays one null check per option copy.
//
// Confirmation criteria, adjudicated form (probe/adjudication.md, design D2):
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
#ifndef SHELLER_ENGINE_ESP_TARGET_H
#define SHELLER_ENGINE_ESP_TARGET_H

#include "rebuild_state.h"

namespace sheller::engine::esp_target {

// The 64-byte cap from design D3: an upper clamp on the static extent.
inline constexpr std::uint64_t kExtentCap = 64;

// Scans the entry's contiguous push prefix and registers the range-scoped
// read hook on the run state whenever the prefix is non-empty - the monitor
// is the default passive observation (Form A: every confirmed restore emits
// kStackRestore to the event sink, no stop goal required); the stop and the
// arm are what the goal turns on. Called from run_syscalls after the
// TLS-callback legs and before the main loop, so S is the world's starting
// rsp (samples with entry TLS callbacks leave their own frame on the stack:
// their window would sit below the true save area, which lands them on the
// documented silent-miss path, same as the VM shape).
void install(uc_engine* uc, const PreparedGuest& guest, SyscallRunState& state);

} // namespace sheller::engine::esp_target

#endif // SHELLER_ENGINE_ESP_TARGET_H
