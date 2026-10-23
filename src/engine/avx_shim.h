// Single-instruction shim for the VEX.256 data moves unicorn2's TCG cannot
// translate (QEMU TCG tops out at SSE). The run loop registers the
// UC_HOOK_INSN_INVALID callback declared here; the decoding internals stay
// module-private.

#ifndef SHELLER_ENGINE_AVX_SHIM_H
#define SHELLER_ENGINE_AVX_SHIM_H

#include "rebuild_state.h"

namespace sheller::engine {

// Interprets the pure data-move subset the captured ntdll actually executes
// (all on ymm0) against the exposed YMM register file, and fails loudly on
// anything outside the subset - never silent corruption.
bool on_insn_invalid_callback(uc_engine* const uc, void* const user_data);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_AVX_SHIM_H
