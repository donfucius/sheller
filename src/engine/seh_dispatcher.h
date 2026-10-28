// Engine-side SEH dispatch: the dispatch
// semantics - function table lookup, virtual unwind, scope tables, VEH
// traversal - run in the engine; handler/filter/VEH callbacks execute as
// real guest code against a scratch stack and return through an engine
// trampoline page (int3 marker consumed by the run loop's INTR hook).
//
// The dispatcher is a state machine stepped from the run loop's head: each
// step either stages one guest callback (RunCallback), applies a resume
// context (ResumeHandled), or declares the exception unhandled (Unhandled).
// Nested exceptions inside a callback stack a new dispatch layer; the
// outer layer's staged callback resumes when the nested one completes.

#ifndef SHELLER_ENGINE_SEH_DISPATCHER_H
#define SHELLER_ENGINE_SEH_DISPATCHER_H

#include "../engine/mem_region_map.h"
#include "exception_layout.h"

#include <unicorn/unicorn.h>

#include <array>
#include <cstdint>
#include <vector>

namespace sheller::engine::seh {

// One frame the walk has opened (a function whose handler/scope table the
// dispatcher is examining, or has passed over).
struct Frame {
    std::uint64_t pc{};                  // covering pc in this frame (fault or call site)
    std::uint32_t code{};                // exception code dispatched to this frame
    std::uint64_t module_base{};         // owning module (0 = none found)
    std::uint64_t function_begin{};      // function VA base (scope offsets are RVAs)
    std::uint64_t runtime_function{};    // guest VA of the RUNTIME_FUNCTION entry
    std::uint64_t info_va{};             // UNWIND_INFO guest VA (the frame's own - funclet
                                         // faults keep their prolog accounting here)
    std::uint32_t count_of_codes{};      // its code count (prolog accounting input)
    std::uint32_t rip_offset{};          // pc offset into the function (code filter)
    std::uint64_t total{};               // prolog rsp total (return-address placement)
    std::uint64_t establisher{};         // x64: frame rsp; x86: chain record VA
    std::uint64_t language_handler{};    // 0 = no handler in this frame
    std::uint64_t handler_data{};        // scope table / FuncInfo guest VA (x64)
    std::uint64_t record_va{};           // per-frame guest EXCEPTION_RECORD
    std::uint64_t context_va{};          // per-frame guest CONTEXT
    std::uint64_t dispatcher_va{};       // per-frame guest DISPATCHER_CONTEXT
    std::uint32_t scope_cursor{};        // next scope index to examine (search pass)
    std::uint32_t unwind_scope_cursor{}; // reverse __finally scan cursor (unwind pass)
    bool cxx_handler{};                  // language handler is __CxxFrameHandler{,2,3,4}:
                                         // the real handler runs and the engine never
                                         // interprets handler_data (false = scope table)
    bool search_handler{};               // UNW_FLAG_EHANDLER: the handler takes the search
                                         // pass. UHANDLER-only frames (pure cleanup, the
                                         // /EHa shape) are skipped in search and get their
                                         // UNWINDING call during the unwind pass.
    std::uint32_t target_state{};        // DISPATCHER_CONTEXT.ScopeIndex round-trip
    bool opened{};                       // lookup + unwind info fully processed
};

// One nested dispatch layer: a fault opens a layer; its frames stack here.
struct Layer {
    std::vector<Frame> frames;
    enum class Phase { Veh, Dispatch, Unwind } phase{Phase::Veh};
    std::uint64_t veh_head{};           // LdrpVectorHandlerList VA (0 = scan failed)
    std::uint64_t veh_node{};           // current VEH node (0 = not started)
    bool veh_scanned{};                 // list head located (else VEH skipped)
    std::uint64_t accept_jump_target{}; // resume rip once unwind completes (SEH scope
                                        // JumpTarget, or the C++ handler's TargetIp)
    std::uint64_t accept_establisher{}; // resume rsp once unwind completes
    std::size_t accept_frame{};         // index of the accepting frame
    std::size_t unwind_cursor{};        // unwind pass: next frame to examine; frames
                                        // [0, accept_frame) run UNWINDING callbacks,
                                        // innermost (highest index) first
};

// Per-run engine-dispatch state (lives in the syscall run state).
struct SehDispatchState {
    bool active{};
    // Fault facts captured at dispatch entry (sized to the wire maximum so a
    // raised record - the C++ EH 0xE06D7363 carries five - never truncates).
    exceptions::RegisterSnapshot snapshot{};
    std::uint32_t code{};
    std::uint64_t pc{};
    std::uint64_t fault_address{};
    std::array<std::uint64_t, exceptions::kRecordMaxParameters> information{};
    std::uint32_t information_count{};
    // Trampoline page (int3 marker) the callbacks return through.
    std::uint64_t trampoline{};
    // Scratch region (per-layer guest structs).
    std::uint64_t scratch{};
    // Callback rendezvous.
    bool awaiting_callback{};
    bool callback_done{};
    std::uint64_t callback_rax{};
    std::size_t callback_layer{};
    // VEH handler decode (Win10+ ntdll encodes the node handler with a
    // per-process key): 0 = not yet derived, 1 = key verified and cached.
    std::uint8_t veh_key_state{};
    std::uint64_t veh_decode_key{};
    // Nested layers; layers.back() is the innermost dispatch.
    std::vector<Layer> layers;
};

// Opens a dispatch layer for a freshly captured fault. The machine state
// is snapshotted here - callbacks run against this snapshot afterwards.
void begin_dispatch(SehDispatchState& seh, uc_engine* uc, bool x86, std::uint32_t code,
                    std::uint64_t pc, std::uint64_t fault_address, const std::uint64_t* information,
                    std::uint32_t information_count);

// One state-machine step. The run loop calls this whenever the engine
// dispatch owns control (a fresh fault with a dispatch in progress, a
// callback return at the trampoline, or a walk continuation).
enum class Step {
    RunCallback,   // a guest callback is staged: run until the trampoline
    ResumeHandled, // the machine carries the resume context: continue the run
    Unhandled,     // no handler accepted: crash fallback
    EngineError,   // dispatch could not continue (guest memory broken)
};

struct StepResult {
    Step action{Step::Unhandled};
    std::uint64_t begin{}; // resume rip for ResumeHandled (informational)
};

StepResult step(uc_engine* uc, SehDispatchState& seh, bool x86, std::uint64_t teb,
                const mem_region::MemRegionMap& map);

// The real C++ frame handler drove RtlUnwindEx as guest code (the accept
// protocol of __CxxFrameHandler4: it never returns to the staged callback).
// The engine retires the dispatch handshake and lets the real unwind
// machinery run: deeper frames' UNWINDING callbacks, the target-unwind
// re-call of the accepting frame, the catch funclet and the continuation
// transfer - all as guest code, exactly the fidelity-mode chain.
void retire_dispatch(SehDispatchState& seh);

// Puts the fault snapshot captured at begin_dispatch back into the machine -
// the accept handoff re-delivers the fault through the real guest
// dispatcher, which synthesizes its frame from the live registers.
void restore_snapshot(uc_engine* uc, const SehDispatchState& seh, bool x86);

// Test seam: sums the prolog's rsp effects for the unwind codes
// already executed at `rip_offset` bytes into the function. Full
// UNWIND_CODE set; saving-only ops move the cursor, push/alloc ops move
// both cursor and total.
bool prolog_total(uc_engine* uc, std::uint64_t info_va, std::uint32_t count_of_codes,
                  std::uint32_t rip_offset, std::uint64_t& total);

// The language-handler classification the walk routes on: FuncInfo signature
// or exported __CxxFrameHandler{,2,3,4} means the C++ protocol (the real
// handler runs; the engine never interprets handler_data); a shape-validated
// {count, entries} table keeps the __C_specific_handler scope-table
// semantics; anything else (private wrapper handlers whose HandlerData is
// metadata, not a count) also runs as a guest handler - the real function
// reads DispatcherContext.HandlerData and dispatches itself.
enum class HandlerKind { ScopeTable, Cxx };
HandlerKind classify_language_handler(uc_engine* uc, const mem_region::MemRegionMap& map,
                                      std::uint64_t handler_va, std::uint64_t handler_data);

// Recovered nonvolatile state of one frame - the unwind parity piece of
// RtlUnwindEx: callee-saved GPRs (and XMMs) the executed prolog codes saved
// into the frame, read back from [establisher + slot]. Only the entries the
// corresponding valid flag admits are meaningful.
struct NonvolatileFrame {
    std::array<std::uint64_t, 16> gpr{}; // Intel order RAX=0..R15
    std::array<bool, 16> gpr_valid{};
    std::array<std::uint8_t, 16 * 16> xmm{}; // XMM i at xmm[i * 16]
    std::array<bool, 16> xmm_valid{};
};

bool nonvolatile_frame(uc_engine* uc, std::uint64_t info_va, std::uint32_t count_of_codes,
                       std::uint32_t rip_offset, std::uint64_t establisher, std::uint64_t total,
                       NonvolatileFrame& out);

// True while a dispatch is in flight (the run loop owes the ledger the
// last-chance event if the run ends in this state).
bool in_flight(const SehDispatchState& seh);

// Fault facts of the dispatch in flight (the last-chance event source).
std::uint32_t fault_code(const SehDispatchState& seh);
std::uint64_t fault_pc(const SehDispatchState& seh);

} // namespace sheller::engine::seh

#endif // SHELLER_ENGINE_SEH_DISPATCHER_H
