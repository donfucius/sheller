#include "exception_pipeline.h"

#include "diag_trace.h"
#include "engine_hooks.h"
#include "syscall_dispatch.h"

#include "../syscalls/syscall_number_map.h"

#include <algorithm>

namespace sheller::engine {
namespace {

// NtQueryVirtualMemory: ntdll's image-lookup fallback queries the
// memory region when a PC is outside every registered function table - the
// loader route's ntdll data is never populated, so the dispatch walk leans
// on this answer. MemoryBasicInformation is composed from the region map
// (extent/protection/type of the owning region); free addresses answer as
// MEM_FREE and other information classes are rejected. The MEM_IMAGE /
// MEM_PRIVATE type values come from write_ledger.h (same constants the
// region records carry).
constexpr std::uint64_t kMemCommit = 0x1000;
constexpr std::uint64_t kMemFree = 0x10000;
constexpr std::uint32_t kPageNoaccess = 0x01;
constexpr std::uint32_t kMemoryBasicInformationClass = 0x00;
constexpr std::uint32_t kMemoryImageInformationClass = 0x06;

std::uint64_t resolve_ki_user_exception_dispatcher(const mem_region::MemRegionMap& map,
                                                   uc_engine* const uc)
{
    const auto ntdll = map.module_index_by_name("ntdll.dll");
    if (!ntdll.has_value()) {
        return 0;
    }
    const auto resolved =
        syscalls::resolve_export(uc, map.module(*ntdll).base, "KiUserExceptionDispatcher");
    return resolved.value_or(0);
}

// Exception disposition carried in the event payload (u32): the first-
// chance delivery into the guest dispatcher, the handler-dispatch report
// (the engine-side dispatcher staged a guest handler), or the last-chance
// raise that means nobody handled the exception.
constexpr std::uint32_t kChanceFirstChance = 0;
constexpr std::uint32_t kChanceHandlerDispatch = 2;
constexpr std::uint32_t kChanceLastChance = 1;

// Shared kException emitter: {u32 code, u32 disposition, u64 related pc}.
// related_pc carries the fault pc on a handler-dispatch report (whose event
// pc is the handler entry); it is 0 for the plain first-chance/last-chance
// pair.
void emit_exception_payload(SyscallRunState& state, const std::uint32_t code,
                            const std::uint32_t disposition, const std::uint64_t pc,
                            const std::uint64_t related_pc)
{
    if (!state.event_sink) {
        return;
    }
    std::array<std::uint8_t, 16> fields{};
    le::store_le32(fields.data(), code);
    le::store_le32(fields.data() + 4, disposition);
    le::store_le64(fields.data() + 8, related_pc);
    const EventPreamble preamble{.seq = 0, .tid = state.current_tid, .pc = pc};
    state.event_sink(EventTypeId::kException, preamble, fields);
}

} // namespace

// Interrupt hook: software exceptions surface here. Breakpoint vectors
// dispatch; __fastfail bypasses every handler by definition and any other
// vector has no accepted mapping - both crash without dispatch. x86 guests
// additionally route the 0x2E system-service vector here.
void on_intr_callback(uc_engine* const uc, const std::uint32_t vector, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    // engine dispatch: a staged callback returned into the trampoline
    // (int3 marker page). Hand the verdict to the run loop's state machine.
    // The page is exclusively the trampoline's, and unicorn may report the
    // int3's rip at or just past the marker byte - match the page range.
    if (state->seh.awaiting_callback && read_rip(uc) - state->seh.trampoline < 0x1000) {
        std::uint64_t rax = 0;
        const bool x86 = state->guest_mode == GuestMode::kX86;
        if (x86) {
            std::uint32_t eax = 0;
            uc_reg_read(uc, UC_X86_REG_EAX, &eax);
            rax = eax;
        } else {
            uc_reg_read(uc, UC_X86_REG_RAX, &rax);
        }
        state->seh.callback_rax = rax;
        state->seh.awaiting_callback = false;
        state->seh.callback_done = true;
        uc_emu_stop(uc);
        return;
    }
    if (vector == 0x2E && state->guest_mode == GuestMode::kX86) {
        // x86 system-service entry: eax carries the number, edx points at
        // the argument block (the stub's `lea edx,[esp+4]`). Map the four
        // register-class args onto the shared frame shape and aim the
        // stack-arg window at args 4/5; edx is left to the guest.
        syscalls::SyscallFrame frame{};
        std::uint64_t eax = 0, edx = 0;
        uc_reg_read(uc, UC_X86_REG_EAX, &eax);
        uc_reg_read(uc, UC_X86_REG_EDX, &edx);
        frame.number = static_cast<std::uint32_t>(eax);
        frame.tid = state->current_tid;
        frame.rip = read_rip(uc);
        // The two x86 service conventions differ only in where the argument
        // block lives: real SysWOW64 stubs carry stdcall args on the stack
        // two return addresses deep (the caller's call plus the stub's own
        // call into the transition thunk, which tail-jumps here; edx holds
        // the thunk's address, not an argument block), while the engine's
        // synthetic samples pass edx = argument block. Both carry 4-byte
        // arguments; the policy handlers read 8-byte stack slots, so args
        // 5..8 are re-assembled into a zero-extended window on the stub
        // page and frame.rsp aims that window at [rsp+0x28].
        const bool transition_call = frame.rip == kLoaderWow64StubBase + 2;
        std::uint64_t esp = 0;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        const auto arg = [&](const std::size_t index) {
            return transition_call ? read_guest_u32(uc, esp + 8 + 4 * index)
                                   : read_guest_u32(uc, edx + 4 * index);
        };
        frame.rcx = arg(0);
        frame.r10 = frame.rcx;
        frame.rdx = arg(1);
        frame.r8 = arg(2);
        frame.r9 = arg(3);
        constexpr std::uint64_t kArgWindow = kLoaderWow64StubBase + 0x40;
        for (std::size_t i = 0; i < 4; ++i) {
            const std::uint64_t wide = arg(4 + i);
            uc_mem_write(uc, kArgWindow + 8 * i, &wide, sizeof wide);
        }
        frame.rsp = kArgWindow - 0x28;
        auto outcome = dispatch_one_syscall(state, uc, frame);
        // the INTR hook is post-instruction: rip already sits past the int
        std::uint64_t next_rip = frame.rip;
        const std::uint64_t status = static_cast<std::uint64_t>(outcome.status);
        uc_reg_write(uc, UC_X86_REG_EAX, &status);
        write_rip(uc, next_rip);
        // kRaiseException: adopt the raised context (over the synthesis
        // above); the unconditional stop below hands off to the run loop
        if (outcome.raise) {
            apply_raise_exception(state, uc, frame);
            uc_emu_stop(uc);
            return;
        }
        // kContinue: the x86 dispatch resumes at the passed context's Eip;
        // the stop hands the new rip to the run loop
        if (outcome.continue_ctx) {
            apply_continue(state, uc, frame);
            uc_emu_stop(uc);
            return;
        }
        // thread outcomes (post-instruction semantics: the resume rip is
        // the hook-time rip, no +2)
        if (outcome.thread_create) {
            apply_thread_creation(state, uc, frame, outcome, frame.rip);
        }
        if (outcome.blocking && state->scheduler.enabled) {
            state->scheduler.blocked = true;
            state->scheduler.cur().rip_resume = frame.rip;
        }
        if (outcome.terminate_thread) {
            scheduler_thread_exit(state, outcome.exit_code);
            return;
        }
        // Always stop the leg: after the INTR hook returns, QEMU would
        // otherwise deliver the raw int (user-mode int 2e has no CPU
        // handler here) and the guest faults inside its own next step. The
        // run loop resumes at next_rip (or a rotated thread's resume point).
        uc_emu_stop(uc);
        if (outcome.terminate) {
            state->terminated = true;
            state->exit_code = outcome.exit_code;
        }
        return;
    }
    if (vector == 3 || vector == 0xD || vector == 0x2D) {
        // The v2 unwind tail restores the resumed context with IRETQ through
        // the machine frame the walk built; unicorn surfaces that as a #GP
        // (or breakpoint) vector. Register writes from inside the hook leave
        // unicorn's view and the executing guest out of sync, so only flag
        // it here: the run loop performs the frame pop between legs.
        std::array<std::uint8_t, 2> code_bytes = {};
        const auto pc = read_rip(uc);
        if (uc_mem_read(uc, pc, code_bytes.data(), code_bytes.size()) == UC_ERR_OK &&
            code_bytes[0] == 0x48 && code_bytes[1] == 0xCF) {
            state->iretq_pending = true;
            uc_reg_read(uc, UC_X86_REG_RSP, &state->iretq_rsp);
            uc_emu_stop(uc);
            return;
        }
        state->exception = {.valid = true,
                            .unhandled = false,
                            .code = exceptions::kStatusBreakpoint,
                            .pc = read_rip(uc)};
    } else if (vector == 0x29) {
        state->exception = {.valid = true,
                            .unhandled = true,
                            .code = exceptions::kStatusStackBufferOverrun,
                            .pc = read_rip(uc)};
    } else {
        state->exception = {.valid = true,
                            .unhandled = true,
                            .code = exceptions::kStatusBreakpoint,
                            .pc = read_rip(uc)};
    }
    uc_emu_stop(uc);
}

// NtRaiseException: the kernel re-dispatches the passed record
// against the passed context; a last-chance raise never returns - the
// process dies on the crash-fallback path. ntdll's own no-handler tail
// calls this syscall directly (this build: KiUserExceptionDispatcher+0x4e,
// xor r8b,r8b), so a plain rejection sends the guest down an endless
// RtlRaiseStatus recursion instead of the deterministic stop.
//
// NtContinue: the x86 dispatch resumes the interrupted context through
// this syscall (KiUserExceptionDispatcher's tail after the walk succeeds).
// The engine applies the passed CONTEXT to the machine and the run loop
// resumes at its Eip; like NtRaiseException the caller's flow never returns.
void apply_continue(SyscallRunState* state, uc_engine* const uc,
                    const syscalls::SyscallFrame& frame)
{
    const auto context_va = frame.rcx;
    if (context_va == 0) {
        return;
    }
    // the interrupted context resumes through NtContinue: the exception
    // ended handled - the dispatch guard disarms (see the IRETQ leg)
    state->dispatch_guard_armed = false;
    for (std::size_t i = 0; i < gpr_count_for(state->guest_mode); ++i) {
        const auto value = read_guest_u32(uc, context_va + exceptions::kContextGprOffsets32[i]);
        uc_reg_write(uc, gpr_register_for(state->guest_mode, i), &value);
    }
    const auto eflags = read_guest_u32(uc, context_va + exceptions::kContextEFlagsOffset32);
    uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);
    write_rip(uc, read_guest_u32(uc, context_va + exceptions::kContextEipOffset32));
}

// Callers run this after the syscall ABI synthesis so the adopted context
// registers win; both hook sites stop the leg right after.
void apply_raise_exception(SyscallRunState* state, uc_engine* const uc,
                           const syscalls::SyscallFrame& frame)
{
    const bool x86 = state->guest_mode == GuestMode::kX86;
    // Both ABIs land the three args in the frame's register-class slots:
    // x64 passes them in rcx/rdx/r8, and the int-2E handler maps the edx
    // argument block onto the same slots ([edx]=record, [edx+4]=context,
    // [edx+8]=first chance).
    const std::uint64_t record_va = frame.rcx;
    const std::uint64_t context_va = frame.rdx;
    const std::uint32_t first_chance = static_cast<std::uint32_t>(frame.r8 & 0xFF);
    std::uint32_t code = 0;
    if (record_va != 0) {
        code = x86 ? read_guest_u32(uc, record_va + exceptions::kRecordCodeOffset32)
                   : read_guest_u32(uc, record_va + exceptions::kRecordCodeOffset);
    }
    if (record_va == 0 || context_va == 0) {
        state->exception = {.valid = true,
                            .unhandled = true,
                            .code = exceptions::kStatusAccessViolation,
                            .pc = frame.rip};
        return;
    }
    if (first_chance == 0) {
        // last chance: no handler anywhere accepted the exception - the
        // deterministic crash-fallback stop (kernel: process termination)
        state->exception = {.valid = true, .unhandled = true, .code = code, .pc = frame.rip};
        return;
    }
    // First-chance raise: adopt the passed context (GPRs, rip, eflags) and
    // dispatch the record's exception at it through the real ntdll walk.
    if (x86) {
        for (std::size_t i = 0; i < gpr_count_for(state->guest_mode); ++i) {
            const auto value = read_guest_u32(uc, context_va + exceptions::kContextGprOffsets32[i]);
            uc_reg_write(uc, gpr_register_for(state->guest_mode, i), &value);
        }
        const auto eip = read_guest_u32(uc, context_va + exceptions::kContextEipOffset32);
        write_rip(uc, eip);
        const auto eflags = read_guest_u32(uc, context_va + exceptions::kContextEFlagsOffset32);
        uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);
    } else {
        for (std::size_t i = 0; i < gpr_count_for(state->guest_mode); ++i) {
            const auto value = read_guest_u64(uc, context_va + exceptions::kContextGprOffsets[i]);
            uc_reg_write(uc, gpr_register_for(state->guest_mode, i), &value);
        }
        const auto rip = read_guest_u64(uc, context_va + exceptions::kContextRipOffset);
        write_rip(uc, rip);
        const auto eflags = read_guest_u32(uc, context_va + exceptions::kContextEFlagsOffset);
        uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);
    }
    // the record's information array: the full wire capacity - the C++ EH
    // 0xE06D7363 record carries five entries and the real __CxxFrameHandler
    // reads them all, so nothing here may truncate
    std::uint32_t parameter_count = 0;
    std::uint64_t information[exceptions::kRecordMaxParameters] = {};
    if (x86) {
        parameter_count =
            read_guest_u32(uc, record_va + exceptions::kRecordNumberParametersOffset32);
        for (std::size_t i = 0; i < exceptions::kRecordMaxParameters && i < parameter_count; ++i) {
            information[i] =
                read_guest_u32(uc, record_va + exceptions::kRecordInformationOffset32 + i * 4);
        }
    } else {
        parameter_count = read_guest_u32(uc, record_va + exceptions::kRecordNumberParametersOffset);
        for (std::size_t i = 0; i < exceptions::kRecordMaxParameters && i < parameter_count; ++i) {
            information[i] =
                read_guest_u64(uc, record_va + exceptions::kRecordInformationOffset + i * 8);
        }
    }
    const auto carried =
        (std::min)(parameter_count, static_cast<std::uint32_t>(exceptions::kRecordMaxParameters));
    const auto pc = read_rip(uc);
    auto& facts = state->exception;
    facts = {.valid = true, .unhandled = false, .code = code, .pc = pc};
    for (std::size_t i = 0; i < carried; ++i) {
        facts.information[i] = information[i];
    }
    facts.information_count = carried;
}

void apply_query_virtual_memory(SyscallRunState* state, uc_engine* const uc,
                                const syscalls::SyscallFrame& frame,
                                syscalls::SyscallOutcome& outcome)
{
    const bool x86 = state->guest_mode == GuestMode::kX86;
    std::uint64_t base_address = 0, information_class = 0, buffer = 0, return_length_ptr = 0;
    // both ABIs land args 1..4 in the frame's register-class slots (x86's
    // int-2E hook maps the argument block onto them) and arg 6 in the stack
    // window the hook normalized to 8-byte slots
    base_address = frame.rdx;
    information_class = frame.r8;
    buffer = frame.r9;
    return_length_ptr = read_guest_u64(uc, frame.rsp + 0x30); // arg6
    if (buffer == 0) {
        outcome.status = syscalls::kStatusInvalidParameter;
        outcome.rejected = true;
        return;
    }
    const auto page = base_address & ~static_cast<std::uint64_t>(0xFFF);
    const auto attribution =
        state->region_map != nullptr ? state->region_map->query(page) : std::nullopt;
    std::uint64_t region_base = page;
    std::uint64_t region_size = 0x10000;
    std::uint64_t state_field = kMemFree;
    std::uint32_t protect = kPageNoaccess;
    std::uint64_t type = 0;
    std::uint64_t image_base = 0;
    std::uint64_t image_size = 0;
    if (attribution.has_value()) {
        const auto& region = state->region_map->region(attribution->region_index);
        region_base = region.base;
        region_size = region.size;
        state_field = kMemCommit;
        protect = region.protection;
        type = region.type != 0                                            ? region.type
               : attribution->kind == mem_region::AttributionKind::kRegion ? kMemPrivate
                                                                           : kMemImage;
        if (attribution->kind != mem_region::AttributionKind::kRegion && type == kMemPrivate) {
            type = kMemImage;
        }
        if (attribution->kind != mem_region::AttributionKind::kRegion) {
            const auto& module = state->region_map->module(attribution->module_index);
            image_base = module.base;
            image_size = module.size;
        } else {
            image_base = region.base;
            image_size = region.size;
        }
    }
    if (information_class == kMemoryImageInformationClass && !state->fidelity_dispatch) {
        // the MII answer exists for the real ntdll's exception lookup
        // fallback - the engine-side dispatcher reads .pdata directly and
        // never consumes it, so the version-pinned width special-cases only
        // run in fidelity mode. (MemoryBasicInformation stays answered: its
        // shape is stable ABI and samples VirtualQuery it.)
        outcome.status = syscalls::kStatusInvalidParameter;
        outcome.rejected = true;
        return;
    }
    if (information_class == kMemoryImageInformationClass) {
        // MEMORY_IMAGE_INFORMATION: {ImageBase, SizeOfImage} - ntdll's
        // lookup fallback reads the image extent from here and then parses
        // the exception directory at the base. The structure width follows
        // the pointer size: 16 bytes on x64, 12 on x86 (the trailing dword
        // is the execution-state flags the callers test for zero) - writing
        // the x64 width under an x86 caller overruns into its frame.
        if (x86) {
            const std::uint32_t base32 = static_cast<std::uint32_t>(image_base);
            const std::uint32_t size32 = static_cast<std::uint32_t>(image_size);
            const std::uint32_t flags = 0;
            if (uc_mem_write(uc, buffer, &base32, sizeof base32) != UC_ERR_OK ||
                uc_mem_write(uc, buffer + 4, &size32, sizeof size32) != UC_ERR_OK ||
                uc_mem_write(uc, buffer + 8, &flags, sizeof flags) != UC_ERR_OK) {
                outcome.status = syscalls::kStatusAccessViolation;
                return;
            }
            const std::uint32_t info_size = 0xC;
            if (return_length_ptr != 0) {
                uc_mem_write(uc, return_length_ptr, &info_size, sizeof info_size);
            }
        } else {
            const auto put64 = [&](std::uint64_t offset, std::uint64_t value) {
                return uc_mem_write(uc, buffer + offset, &value, sizeof value);
            };
            if (put64(0x00, image_base) != UC_ERR_OK || put64(0x08, image_size) != UC_ERR_OK) {
                outcome.status = syscalls::kStatusAccessViolation;
                return;
            }
            const std::uint64_t info_size = 0x10;
            if (return_length_ptr != 0) {
                uc_mem_write(uc, return_length_ptr, &info_size, sizeof info_size);
            }
        }
        outcome.status = syscalls::kStatusSuccess;
        return;
    }
    if (information_class != kMemoryBasicInformationClass) {
        // The real Ldr's KnownDll load path queries
        // information class 0x0E over the freshly mapped view (observed on
        // the packed corpus: the post-map validation chain in ntdll calls
        // NtQueryVirtualMemory(-1, <view>, 0x0E, buf, 0x18, *retlen) and
        // treats STATUS_INVALID_PARAMETER as a hard load failure). The
        // engine has no equivalent kernel state to expose, so the answer is
        // the deterministic empty verdict: zeroed buffer + ReturnLength =
        // requested length, success. Everything else keeps the reject.
        constexpr std::uint32_t kMemoryPostMapProbeClass = 0x0E;
        if (information_class == kMemoryPostMapProbeClass) {
            // The real Ldr's post-map validation
            // chain queries information class 0x0E over the freshly mapped
            // view. The consumer is the CFG function-table registration
            // (RtlpInsertOrRemoveScpCfgFunctionTable)
            // - it carries the mapped region's extent at +0x08 and the
            // replay has no CFG bitmap machinery to back a real answer, so
            // the deterministic empty verdict keeps the registered failure
            // shape (the registration fails -> the load reports through the
            // WER path) instead of a deeper half-initialized CFG walk.
            constexpr std::uint64_t kAnswerCap = 0x40;
            const auto length =
                static_cast<std::size_t>(frame.r9 < kAnswerCap ? frame.r9 : kAnswerCap);
            if (length != 0) {
                std::array<std::uint8_t, 0x40> zeros{};
                if (uc_mem_write(uc, buffer, zeros.data(), length) != UC_ERR_OK) {
                    outcome.status = syscalls::kStatusAccessViolation;
                    return;
                }
            }
            if (return_length_ptr != 0) {
                const std::uint64_t requested_length = read_guest_u64(uc, frame.rsp + 0x28);
                uc_mem_write(uc, return_length_ptr, &requested_length, sizeof requested_length);
            }
            outcome.status = syscalls::kStatusSuccess;
            return;
        }
        outcome.status = syscalls::kStatusInvalidParameter;
        outcome.rejected = true;
        return;
    }
    if (x86) {
        const auto put32 = [&](std::uint64_t offset, std::uint32_t value) {
            uc_mem_write(uc, buffer + offset, &value, sizeof value);
        };
        put32(0x00, static_cast<std::uint32_t>(region_base));
        put32(0x04, static_cast<std::uint32_t>(region_base));
        put32(0x08, protect);
        put32(0x0C, static_cast<std::uint32_t>(region_size));
        put32(0x10, static_cast<std::uint32_t>(state_field));
        put32(0x14, protect);
        put32(0x18, static_cast<std::uint32_t>(type));
        const std::uint32_t mbi_size = 0x1C;
        if (return_length_ptr != 0) {
            uc_mem_write(uc, return_length_ptr, &mbi_size, sizeof mbi_size);
        }
    } else {
        // x64 MEMORY_BASIC_INFORMATION (winnt.h _MEMORY_BASIC_INFORMATION64,
        // 16-byte aligned front, 4-byte tail fields): BaseAddress/AllocationBase
        // at +0x00/+0x08, AllocationProtect at +0x10 (+ alignment), RegionSize
        // at +0x18, then State/Protect/Type/alignment as dwords at +0x20..
        const auto put64 = [&](std::uint64_t offset, std::uint64_t value) {
            uc_mem_write(uc, buffer + offset, &value, sizeof value);
        };
        const auto put32 = [&](std::uint64_t offset, std::uint32_t value) {
            uc_mem_write(uc, buffer + offset, &value, sizeof value);
        };
        put64(0x00, region_base);                             // BaseAddress
        put64(0x08, region_base);                             // AllocationBase
        put32(0x10, protect);                                 // AllocationProtect
        put32(0x14, 0);                                       // __alignment1
        put64(0x18, region_size);                             // RegionSize
        put32(0x20, static_cast<std::uint32_t>(state_field)); // State
        put32(0x24, protect);                                 // Protect
        put32(0x28, static_cast<std::uint32_t>(type));        // Type
        put32(0x2C, 0);                                       // __alignment2
        const std::uint64_t mbi_size = 0x30;
        if (return_length_ptr != 0) {
            uc_mem_write(uc, return_length_ptr, &mbi_size, sizeof mbi_size);
        }
    }
    outcome.status = syscalls::kStatusSuccess;
}

// Invalid-memory hook: unmapped or access-protected faults surface here with
// the access kind and faulting address in hand.
bool on_mem_invalid_callback(uc_engine* const uc, const uc_mem_type type,
                             const std::uint64_t address, const int, const std::int64_t,
                             void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    // The ledger-grant hook claims prot faults first (it registers earlier):
    // once it has queued a grant, this hook must not raise a competing
    // exception for the same access.
    if (state->write_prot_resume) {
        uc_emu_stop(uc);
        return false;
    }
    // kernel stack-guard semantics: a data access just below the
    // committed stack limit is the stack growing, not a wild pointer. Map
    // the touched range, move the TEB limit down and retry the access
    // natively. Execute faults stay exceptions (a wild jump is a crash).
    const bool unmapped_data = type == UC_MEM_READ_UNMAPPED || type == UC_MEM_WRITE_UNMAPPED;
    if (unmapped_data && state->teb_base != 0) {
        const bool x64 = state->guest_mode == GuestMode::kX64;
        std::uint64_t limit = 0;
        if (x64) {
            limit = read_guest_u64(uc, state->teb_base + 0x10); // NtTib.StackLimit
        } else {
            limit = read_guest_u32(uc, state->teb_base + 0x08);
        }
        constexpr std::uint64_t kStackGrowWindow = 0x100000; // the 1 MB reserve
        if (limit != 0 && address < limit && address + kStackGrowWindow >= limit) {
            // map only the unmapped pages, walking up from the faulting page
            // until we reach mapped memory. Page-granular: the region between
            // the fault and the limit may interleave mapped (ledger read-only
            // stack) and unmapped pages, and wholesale uc_mem_map over mapped
            // pages fails silently.
            auto page = address & ~(engine::kLedgerPageSize - 1);
            const auto lowest = page;
            auto mapped_any = false;
            while (page < limit) {
                std::uint8_t probe = 0;
                if (uc_mem_read(uc, page, &probe, sizeof probe) == UC_ERR_OK) {
                    break; // reached mapped memory: done
                }
                if (uc_mem_map(uc, page, engine::kLedgerPageSize, UC_PROT_READ | UC_PROT_WRITE) !=
                    UC_ERR_OK) {
                    break;
                }
                mapped_any = true;
                if (limit - page <= engine::kLedgerPageSize) {
                    break;
                }
                page += engine::kLedgerPageSize;
            }
            if (mapped_any) {
                if (x64) {
                    uc_mem_write(uc, state->teb_base + 0x10, &lowest, sizeof lowest);
                } else {
                    const auto lowest32 = static_cast<std::uint32_t>(lowest);
                    uc_mem_write(uc, state->teb_base + 0x08, &lowest32, sizeof lowest32);
                }
                return true; // the access retries natively
            }
        }
    }
    std::uint64_t access = exceptions::kAccessRead;
    if (type == UC_MEM_WRITE_UNMAPPED || type == UC_MEM_WRITE_PROT) {
        access = exceptions::kAccessWrite;
    } else if (type == UC_MEM_FETCH_UNMAPPED || type == UC_MEM_FETCH_PROT) {
        access = exceptions::kAccessExecute;
    }
    state->exception = {.valid = true,
                        .unhandled = false,
                        .code = exceptions::kStatusAccessViolation,
                        .pc = read_rip(uc),
                        .information = {access, address},
                        .information_count = 2};
    uc_emu_stop(uc);
    return false;
}

void emit_exception_event(SyscallRunState& state, const std::uint32_t code, const std::uint64_t pc,
                          const bool last_chance, const std::uint64_t related_pc)
{
    ++state.exceptions;
    // An exception is a guest-visible side effect: re-arm the burn-loop
    // detector so the exception dispatch itself is never skipped.
    state.hot_run = 0;
    // Nested-dispatch cascade guard: exceptions delivered within a few
    // blocks of each other mean the dispatcher is crashing on its own state —
    // a bounded run of them ends the guest on the crash-fallback path instead
    // of spinning inside ntdll internals until the wall clock.
    if (state.blocks - state.blocks_at_last_exception < 1000) {
        ++state.consecutive_exceptions;
    } else {
        state.consecutive_exceptions = 0;
    }
    state.blocks_at_last_exception = state.blocks;
    if (state.consecutive_exceptions > 8) {
        state.unhandled = true;
    }
    // Total-exception budget: a dispatch loop (the unwind machinery walking a
    // broken frame chain) raises exceptions endlessly — bounded here so the
    // run lands on the deterministic crash-fallback stop.
    constexpr std::uint64_t kMaxExceptionsPerRun = 4096;
    if (state.exceptions > kMaxExceptionsPerRun) {
        state.unhandled = true;
    }
    emit_exception_payload(state, code, last_chance ? kChanceLastChance : kChanceFirstChance, pc,
                           related_pc);
}

// The handler-dispatch report: the engine-side dispatcher staged a guest
// handler callback. Not an exception - the counters above stay untouched;
// pc is the handler entry, related_pc the fault that selected it.
void emit_handler_dispatch_event(SyscallRunState& state, const std::uint32_t code,
                                 const std::uint64_t handler_pc, const std::uint64_t fault_pc)
{
    emit_exception_payload(state, code, kChanceHandlerDispatch, handler_pc, fault_pc);
}

// Fidelity-trace hook body: prints every instruction's RVA inside the
// faulting module (user_data = module base) - the handler invocations and
// funclet entries the real chain produces, address-comparable with the
// staged-callback trace of engine mode. Handler-thunk entries additionally
// dump the DISPATCHER_CONTEXT the real dispatcher handed over (TargetIp,
// ScopeIndex, record flags) - the ground-truth accept protocol.
void on_fidelity_trace(uc_engine* uc, const std::uint64_t address,
                       [[maybe_unused]] const std::uint32_t size, void* const user_data)
{
    const auto base = reinterpret_cast<std::uintptr_t>(user_data);
    const auto rva = address - base;
    if (rva != 0x466d) {
        diag::emit(sheller::log::level::kDebug, diag::seh_on(), "[seh-cb] fidelity rva={:x}", rva);
        return;
    }
    std::uint64_t record = 0;
    std::uint64_t dispatcher = 0;
    uc_reg_read(uc, UC_X86_REG_RCX, &record);
    uc_reg_read(uc, UC_X86_REG_R9, &dispatcher);
    std::uint64_t target_ip = 0;
    std::uint64_t scope_index = 0;
    std::uint32_t flags = 0;
    if (dispatcher != 0) {
        static_cast<void>(uc_mem_read(uc, dispatcher + 0x20, &target_ip, sizeof target_ip));
        static_cast<void>(uc_mem_read(uc, dispatcher + 0x48, &scope_index, sizeof scope_index));
    }
    if (record != 0) {
        static_cast<void>(uc_mem_read(uc, record + 4, &flags, sizeof flags));
    }
    diag::emit(sheller::log::level::kDebug, diag::seh_on(),
               "[seh-cb] fidelity handler rva={:x} rec={:x} dc={:x} flags={:x} ti={:x} scope={}",
               rva, record, dispatcher, flags, target_ip, scope_index);
}

DispatchOutcome synthesize_and_dispatch(PreparedGuest& guest, SyscallRunState& state)
{
    uc_engine* const uc = guest.unicorn.get();
    const auto facts = state.exception;

    // Fidelity-mode trace (SHELLER_SEH_TRACE): per-instruction log over the
    // faulting module while the real ntdll dispatch runs - the guest-side
    // picture (handler invocations, funclet entries, resume point) the
    // staged-callback trace shows in engine mode. Installed once, at the
    // first delivery.
    if (state.fidelity_dispatch && state.fidelity_trace_hook == 0 &&
        state.guest_mode == GuestMode::kX64) {
        if (diag::seh_on()) {
            for (std::size_t i = 0; i < guest.map.module_count(); ++i) {
                const auto& module = guest.map.module(i);
                if (facts.pc < module.base || facts.pc >= module.base + module.size) {
                    continue;
                }
                auto module_base =
                    reinterpret_cast<void*>(static_cast<std::uintptr_t>(module.base));
                uc_hook hook = 0;
                if (uc_hook_add(guest.unicorn.get(), &hook, UC_HOOK_CODE,
                                reinterpret_cast<void*>(on_fidelity_trace), module_base,
                                module.base, module.base + module.size) == UC_ERR_OK) {
                    state.fidelity_trace_hook = hook;
                }
                break;
            }
        }
    }

    // The C++ accept handoff replays a fault already in the ledger: no
    // second exception event.
    if (!facts.replay_in_guest) {
        emit_exception_event(state, facts.code, facts.pc, false);
    }
    if (state.dispatch_guard_armed && state.last_dispatch_pc == facts.pc &&
        state.last_dispatch_code == facts.code) {
        return DispatchOutcome::kUnhandled;
    }

    if (state.dispatcher_address == 0) {
        state.dispatcher_address = resolve_ki_user_exception_dispatcher(guest.map, uc);
        if (state.dispatcher_address == 0) {
            return DispatchOutcome::kEngineError;
        }
    }

    exceptions::RegisterSnapshot snapshot{};
    for (std::size_t i = 0; i < gpr_count_for(state.guest_mode); ++i) {
        uc_reg_read(uc, gpr_register_for(state.guest_mode, i), &snapshot.gpr[i]);
    }
    snapshot.rip = facts.pc;
    std::uint32_t eflags = 0;
    uc_reg_read(uc, UC_X86_REG_EFLAGS, &eflags);
    snapshot.eflags = eflags;
    uc_reg_read(uc, UC_X86_REG_CS, &snapshot.cs);
    uc_reg_read(uc, UC_X86_REG_DS, &snapshot.ds);
    uc_reg_read(uc, UC_X86_REG_ES, &snapshot.es);
    uc_reg_read(uc, UC_X86_REG_FS, &snapshot.fs);
    uc_reg_read(uc, UC_X86_REG_GS, &snapshot.gs);
    uc_reg_read(uc, UC_X86_REG_SS, &snapshot.ss);

    const bool x86 = state.guest_mode == GuestMode::kX86;
    static_assert(exceptions::kContextSize32 <= exceptions::kContextSize,
                  "the shared stack buffer must fit both shapes");
    static_assert(exceptions::kExceptionRecordSize32 <= exceptions::kExceptionRecordSize,
                  "the shared record buffer must fit both shapes");
    std::uint8_t context_buffer[exceptions::kContextSize];
    std::uint8_t record_buffer[exceptions::kExceptionRecordSize];
    if (x86) {
        exceptions::write_context_x86(context_buffer, snapshot);
        exceptions::write_record_x86(record_buffer, facts.code, facts.pc, facts.information,
                                     facts.information_count);
    } else {
        exceptions::write_context(context_buffer, snapshot);
        exceptions::write_record(record_buffer, facts.code, facts.pc, facts.information,
                                 facts.information_count);
    }

    // Kernel-faithful placement: the frame goes below the faulting stack
    // pointer (dead territory by ABI). x64 reads both structure pointers
    // from RSP - CONTEXT at RSP, EXCEPTION_RECORD at RSP +
    // kUserDispatchRecordDisplacement (KiUserExceptionDispatcher does `mov
    // rcx,rsp; add rcx,disp; mov rdx,rsp`) - so RSP itself points at the
    // CONTEXT. x86 takes both pointers from the stack ([esp]=record,
    // [esp+4]=context), so the engine pushes them under the structs. The
    // TEB base register is GS (x64) or FS (x86); NtTib StackBase/StackLimit
    // live at +0x08/+0x10 (x64) or +0x04/+0x08 (x86).
    std::uint64_t teb = 0;
    if (x86) {
        teb = guest.metadata.teb_address; // FS_BASE register id no-ops in 32-bit
    } else {
        uc_reg_read(uc, UC_X86_REG_GS_BASE, &teb);
    }
    std::uint64_t stack_base = 0;
    std::uint64_t stack_limit = 0;
    if (x86) {
        stack_base = read_guest_u32(uc, teb + 0x04);
        stack_limit = read_guest_u32(uc, teb + 0x08);
    } else {
        stack_base = read_guest_u64(uc, teb + 0x08);
        stack_limit = read_guest_u64(uc, teb + 0x10);
    }
    auto frame_top = snapshot.gpr[4];
    if (frame_top > stack_base || frame_top == 0) {
        frame_top = stack_base;
    }
    const auto context_size = x86 ? exceptions::kContextSize32 : exceptions::kContextSize;
    const auto record_size =
        x86 ? exceptions::kExceptionRecordSize32 : exceptions::kExceptionRecordSize;
    const std::uint64_t dispatch_headroom =
        x86 ? 0x100 : (0x40 + exceptions::kUserDispatchRecordDisplacement);
    auto context_va = (frame_top - dispatch_headroom - record_size - context_size) &
                      ~static_cast<std::uint64_t>(0xF);

    // The kernel grows the committed stack automatically; the emulator must
    // do it explicitly: when the frame would reach below the committed
    // limit, map fresh pages down from the limit and move the TEB limit to
    // match, so RtlpGetStackLimits consumers see the grown window.
    // The dispatcher's own frame (locals, spills) lives below the synthesized
    // frame; reserve headroom so its pushes stay inside the grown window.
    const std::uint64_t frame_floor = (context_va - 0x5000) & ~static_cast<std::uint64_t>(0xF);
    if (frame_floor < stack_limit) {
        const auto map_start = frame_floor & ~static_cast<std::uint64_t>(0xFFF);
        const std::uint64_t map_size = stack_limit - map_start;
        constexpr std::uint64_t kMaxStackGrowth = 0x100000; // 1MB: reserve sanity bound
        if (map_size == 0 || map_size > kMaxStackGrowth) {
            // the synthesized frame already fits inside the committed stack:
            // dispatch without growing
            return DispatchOutcome::kDispatched;
        }
        // Only the unmapped gap adjacent to the limit can grow: probe page
        // by page downward and stop at the first already-mapped page.
        auto gap_start = stack_limit;
        while (gap_start > map_start) {
            const auto probe_page = gap_start - 0x1000;
            std::uint8_t probe_byte = 0;
            if (uc_mem_read(uc, probe_page, &probe_byte, sizeof probe_byte) == UC_ERR_OK) {
                break;
            }
            gap_start = probe_page;
        }
        if (gap_start < stack_limit) {
            const auto map_err =
                uc_mem_map(uc, gap_start, static_cast<std::size_t>(stack_limit - gap_start),
                           UC_PROT_READ | UC_PROT_WRITE);
            if (map_err != UC_ERR_OK) {
                return DispatchOutcome::kEngineError;
            }
            stack_limit = gap_start;
        }
        const std::uint64_t new_limit = map_start;
        if (x86) {
            const auto limit32 = static_cast<std::uint32_t>(new_limit);
            uc_mem_write(uc, teb + 0x08, &limit32, sizeof limit32);
        } else {
            uc_mem_write(uc, teb + 0x10, &new_limit, sizeof new_limit);
        }
    }
    // x64: record above the context at the pinned displacement. x86: record
    // below the context, then an 8-byte arg frame under it.
    const std::uint64_t record_va =
        x86 ? context_va - record_size : context_va + exceptions::kUserDispatchRecordDisplacement;
    const auto write1 = uc_mem_write(uc, context_va, context_buffer, context_size);
    const auto write2 = uc_mem_write(uc, record_va, record_buffer, record_size);
    if (write1 != UC_ERR_OK || write2 != UC_ERR_OK) {
        return DispatchOutcome::kEngineError;
    }
    if (!x86 && facts.pc != 0) {
        // The kernel's interrupt machine frame sits directly above the
        // EXCEPTION_RECORD (16-aligned past its 0x98 bytes): {rip, cs,
        // eflags, rsp, ss} carrying the faulting rip/rsp. KiUserException-
        // Dispatcher's own unwind (v2) releases its frame with
        // UWOP_PUSH_MACHFRAME, which restores the continuation from exactly
        // these slots; without them the walk computes a zero context at the
        // KiUser -> fault transition and spins inside its own frame list.
        const auto machframe = context_va + exceptions::kUserDispatchMachineFrame;
        const auto store = [&uc](const std::uint64_t address, const std::uint64_t value) {
            return uc_mem_write(uc, address, &value, sizeof value);
        };
        if (store(machframe + 0x00, facts.pc) != UC_ERR_OK ||
            store(machframe + 0x08, 0x33) != UC_ERR_OK || // cs
            store(machframe + 0x10, snapshot.eflags) != UC_ERR_OK ||
            store(machframe + 0x18, snapshot.gpr[4]) != UC_ERR_OK || // rsp
            store(machframe + 0x20, 0x2b) != UC_ERR_OK) {            // ss
            return DispatchOutcome::kEngineError;
        }
    }

    // User-dispatch ABI: x64 - RSP at the CONTEXT, the dispatcher loads both
    // of its pointers from RSP. x86 - [esp]=record, [esp+4]=context.
    std::uint64_t rsp = 0;
    if (x86) {
        const std::uint64_t args_frame = record_va - 8;
        const auto record32 = static_cast<std::uint32_t>(record_va);
        const auto context32 = static_cast<std::uint32_t>(context_va);
        if (uc_mem_write(uc, args_frame, &record32, sizeof record32) != UC_ERR_OK ||
            uc_mem_write(uc, args_frame + 4, &context32, sizeof context32) != UC_ERR_OK) {
            return DispatchOutcome::kEngineError;
        }
        rsp = args_frame;
    } else {
        const std::uint64_t rcx = record_va;
        const std::uint64_t rdx = context_va;
        uc_reg_write(uc, UC_X86_REG_RCX, &rcx);
        uc_reg_write(uc, UC_X86_REG_RDX, &rdx);
        rsp = context_va;
    }
    write_rsp(uc, rsp);
    write_rip(uc, state.dispatcher_address);

    state.last_dispatch_pc = facts.pc;
    state.last_dispatch_code = facts.code;
    state.dispatch_guard_armed = true;
    state.exception = {};
    return DispatchOutcome::kDispatched;
}

} // namespace sheller::engine
