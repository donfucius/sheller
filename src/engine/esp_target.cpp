#include "esp_target.h"

#include <Zydis/Zydis.h>

namespace sheller::engine::esp_target {
namespace {

// uc_mem_read fails wholesale when the request straddles a mapping edge; the
// scan only needs the bytes its instructions actually occupy (same shape as
// the loop gate's reader).
std::size_t read_bytes_at(uc_engine* const uc, const std::uint64_t va, std::uint8_t* const out,
                          const std::size_t size)
{
    for (std::size_t take = size; take > 0; --take) {
        if (uc_mem_read(uc, va, out, take) == UC_ERR_OK) {
            return take;
        }
    }
    return 0;
}

// The contiguous push prefix, one Zydis pass: every PUSH widens the window by
// its stack width until a non-push decodes or the cap clamps. The extent is
// the run's own fact; 0 means the entry saves nothing and the monitor is not
// established (the documented silent-miss path).
std::uint64_t scan_save_extent(uc_engine* const uc, const std::uint64_t entry_rip, const bool x64)
{
    ZydisDecoder decoder{};
    if (x64) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    }
    const std::uint32_t slot_width = x64 ? 8 : 4;
    std::uint64_t extent = 0;
    std::uint64_t position = entry_rip;
    for (int count = 0; count < 64; ++count) {
        std::uint8_t window[32]{};
        // The decode gets whatever is actually mapped: an instruction near a
        // mapping edge is decodable from its own bytes, and Zydis fails on an
        // instruction that runs past the buffer - a full 15-byte runway is a
        // loop-gate need (arbitrary instructions), not this scan's.
        const std::size_t window_len = read_bytes_at(uc, position, window, sizeof window);
        if (window_len == 0) {
            break;
        }
        ZydisDecodedInstruction insn{};
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
        if (ZydisDecoderDecodeFull(&decoder, window, window_len, &insn, operands) !=
            ZYAN_STATUS_SUCCESS) {
            break;
        }
        if (insn.mnemonic != ZYDIS_MNEMONIC_PUSH) {
            break;
        }
        if (extent + slot_width > kExtentCap) {
            break; // clamped: an over-long prefix loses its tail, by design
        }
        extent += slot_width;
        position += insn.length;
    }
    return extent;
}

// The closed confirmation set: a register pop. The read-back equivalence
// forms the probe's tables hinted at (mov/xor from the restored frame) are
// exactly the noise shapes the decode has to reject, so the set stays at the
// pop family until evidence widens it.
bool decode_is_register_pop(uc_engine* const uc, const std::uint64_t rip, const bool x64,
                            std::uint32_t slot_width)
{
    std::uint8_t window[32]{};
    // The same short-read rule as the entry scan: the bytes that are actually
    // mapped are all a decodable pop needs (a pop at a page's last byte still
    // confirms; Zydis rejects an instruction that overruns the buffer).
    const std::size_t window_len = read_bytes_at(uc, rip, window, sizeof window);
    if (window_len == 0) {
        return false;
    }
    ZydisDecoder decoder{};
    if (x64) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    }
    ZydisDecodedInstruction insn{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    if (ZydisDecoderDecodeFull(&decoder, window, window_len, &insn, operands) !=
        ZYAN_STATUS_SUCCESS) {
        return false;
    }
    if (insn.mnemonic != ZYDIS_MNEMONIC_POP) {
        return false;
    }
    if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER ||
        (operands[0].actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) == 0 ||
        operands[0].size != slot_width * 8) {
        return false;
    }
    // POP RSP/ESP is a stack pivot, not a restore: the popped value replaces
    // the pointer, so the post-retirement rsp the completion criterion is
    // built on (the slot address plus the width) never materializes. It rides
    // the same exclusion as every other shape outside the set - the silent
    // miss, never a false confirmation.
    const ZydisRegister destination = operands[0].reg.value;
    return destination != ZYDIS_REGISTER_RSP && destination != ZYDIS_REGISTER_ESP;
}

// The window's read hook: the confirmation state machine. Speculative legs
// (the burn-loop probe's chunked re-entry) never arm, never count, never
// stop and never emit - the same exclusion the xfer count carries, because a
// uc_emu_stop a probe chunk swallows would make the host read the stop as
// the probe's, and a confirmation the chunk made would roll back with it.
void on_esp_read(uc_engine* const uc, const uc_mem_type, const std::uint64_t address,
                 const std::uint32_t size, const std::int64_t, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    if (state->loop_probe_pending || state->esp_stop_reached || !state->esp_monitor_armed) {
        return;
    }
    // RSP criterion, gate level: a genuine pop reads with the callback rsp at
    // the slot address (pre-increment fact). Everything else - frame reads
    // into the reused region, system-module reads - has rsp elsewhere and is
    // turned away before the decode.
    const std::uint64_t rsp = read_rsp(uc);
    if (rsp != address) {
        return;
    }
    if (!decode_is_register_pop(uc, read_rip(uc), state->guest_mode == GuestMode::kX64,
                                state->esp_slot_width)) {
        return;
    }
    // Completion: this read puts the stack pointer back at the entry face.
    if (address + size != state->esp_window_hi) {
        return; // an intermediate pop of the restore: keep reading
    }
    // The passive event rides the confirmation on every instrumented
    // run, goal or no goal - the stop (when a goal asked for one) rides the
    // same read, after the event, like every other engine stop.
    if (state->event_sink) {
        const EventPreamble preamble{.seq = 0, .tid = state->current_tid, .pc = read_rip(uc)};
        state->event_sink(EventTypeId::kStackRestore, preamble, {});
    }
    if (state->esp_stop_goal == EspStopGoal::kNone) {
        return; // observation only: the run continues
    }
    if (state->esp_stop_goal == EspStopGoal::kStopAtRestore) {
        // esp form: the stop lands inside the read hook, mid-block. The leg
        // loop breaks on the flag ahead of every resume path; no deferred
        // write grant can be pending here (a grant stops its own leg in the
        // write hook, so a leg carrying one can never reach this hook).
        state->esp_stop_reached = true;
        state->esp_stop_rip = read_rip(uc);
        state->esp_stop_rsp = rsp;
        uc_emu_stop(uc);
        return;
    }
    // esp+xfer form: arm on the completed restore, stop at the next counted
    // execution transfer (the xfer machinery takes the stop, so the landing
    // block never executes and the dump face is the xfer stop's).
    state->esp_armed_next_xfer = true;
    state->xfer_number = state->xfers + 1;
}

// Shared arm core: window_hi = the live rsp, extent scanned at entry_va.
void arm_window(uc_engine* const uc, const std::uint64_t entry_va, SyscallRunState& state)
{
    state.esp_slot_width = state.guest_mode == GuestMode::kX64 ? 8 : 4;
    state.esp_window_hi = read_rsp(uc);
    const std::uint64_t extent =
        scan_save_extent(uc, entry_va, state.guest_mode == GuestMode::kX64);
    if (extent == 0 || state.esp_window_hi < extent) {
        return; // the entry saves nothing: monitor not established, silent miss
    }
    state.esp_window_lo = state.esp_window_hi - extent;
    if (uc_hook_add(uc, &state.esp_read_hook, UC_HOOK_MEM_READ,
                    reinterpret_cast<void*>(on_esp_read), &state, state.esp_window_lo,
                    state.esp_window_hi - 1) != UC_ERR_OK) {
        state.esp_window_lo = 0;
        state.esp_window_hi = 0;
        state.esp_monitor_armed = false;
        return;
    }
    state.esp_monitor_armed = true;
}

} // namespace

void install(uc_engine* const uc, const PreparedGuest& guest, SyscallRunState& state)
{
    arm_window(uc, guest.metadata.entry_address, state);
}

// DLL-input route: re-arms the monitor at the synthesized module's
// DllMain entry once the synthetic load has armed its frame - the world's
// starting registers belong to the runner here, and the unpack-relevant
// entry scene is DllMain's. Deletes the runner-entry hook first; a goal
// that was never requested stays a no-op.
void reinstall_at(uc_engine* const uc, const std::uint64_t entry_va, SyscallRunState& state)
{
    // The passive monitor migrates with the sample identity
    // regardless of any stop goal - whether to STOP stays in on_esp_read's
    // goal branches, exactly like the runner-entry install.
    if (state.esp_monitor_armed && state.esp_read_hook != 0) {
        uc_hook_del(uc, state.esp_read_hook);
        state.esp_read_hook = 0;
    }
    state.esp_monitor_armed = false;
    state.esp_window_lo = 0;
    state.esp_window_hi = 0;
    arm_window(uc, entry_va, state);
}

} // namespace sheller::engine::esp_target
