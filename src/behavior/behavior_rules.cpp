#include "behavior_rules.h"

#include "../engine/write_ledger.h" // PAGE_* constants (read-only)

#include <algorithm>
#include <format>
#include <string>

namespace sheller::behavior {
namespace {

// Judgment payload ceiling: the ledger's per-event field budget. The payload
// is addressed, subtype and an annotation - far below this.
inline constexpr std::size_t kJudgmentFieldBytes = 256;
// Follower search depth for the fnstenv -> slot-read pattern (code facts).
inline constexpr std::uint64_t kFnstenvFollowerWindow = 16;

// The sorted export-slot table member annotation, or empty when no slot
// holds the address (every slot covers 8 bytes: one functions-array entry).
std::string_view export_annotation(const std::vector<BehaviorRulesParams::ExportSlot>& slots,
                                   const std::uint64_t address)
{
    const auto it = std::ranges::upper_bound(slots, address, std::ranges::less{},
                                             &BehaviorRulesParams::ExportSlot::slot_va);
    if (it == slots.begin()) {
        return {};
    }
    const auto& slot = *std::prev(it);
    if (address < slot.slot_va + sizeof(std::uint64_t)) {
        return std::string_view(slot.annotation.data());
    }
    return {};
}

// True when pc executes inside the sample's own image span.
bool pc_in_sample_image(const BehaviorRulesParams& params, const std::uint64_t pc)
{
    return pc >= params.sample_image_base &&
           pc < params.sample_image_base + params.sample_image_size;
}

// Exact function-entry annotation: the entry-arrival signals (probe-api
// call, exception-handler install, staged exception handler) land on a
// function's first byte, which the export-slot table (EAT slots) cannot
// annotate.
std::string_view function_annotation(const BehaviorRulesParams& params, const std::uint64_t va)
{
    const auto it = std::ranges::lower_bound(params.function_entries, va, std::ranges::less{},
                                             &BehaviorRulesParams::ExportSlot::slot_va);
    if (it == params.function_entries.end() || it->slot_va != va) {
        return {};
    }
    return std::string_view(it->annotation.data());
}

} // namespace

BehaviorRules::BehaviorRules(BehaviorRulesParams params) : params_(std::move(params))
{
    // the annotation tables binary-search at lookup: canonical order is the
    // constructor's job, not every caller's
    std::ranges::sort(params_.export_slots, std::ranges::less{},
                      &BehaviorRulesParams::ExportSlot::slot_va);
    std::ranges::sort(params_.function_entries, std::ranges::less{},
                      &BehaviorRulesParams::ExportSlot::slot_va);
}

void BehaviorRules::set_event_emitter(EventEmitter emitter)
{
    emitter_ = std::move(emitter);
}

void BehaviorRules::emit(const EventTypeId type, const std::uint64_t pc,
                         const std::uint64_t address, const std::uint64_t aux,
                         const std::uint32_t subtype, const std::string_view api,
                         const std::uint32_t tid)
{
    if (!emitter_) {
        return;
    }
    std::array<std::uint8_t, kJudgmentFieldBytes> fields{};
    const auto written = encode_judgment(
        fields, JudgmentFields{.address = address, .aux = aux, .subtype = subtype, .api = api});
    if (!written.has_value()) {
        return; // annotation over 255 bytes cannot happen: the tables cap at 96
    }
    const EventPreamble preamble{.seq = 0, .tid = tid, .pc = pc};
    emitter_(type, preamble, std::span(fields.data(), *written));
}

void BehaviorRules::on_fact(const engine::BehaviorFact& fact)
{
    switch (fact.kind) {
    case engine::BehaviorFact::Kind::kMemRead:
        on_mem_read(fact);
        break;
    case engine::BehaviorFact::Kind::kMemWrite:
        on_mem_write(fact);
        break;
    case engine::BehaviorFact::Kind::kCode:
        on_code(fact);
        break;
    case engine::BehaviorFact::Kind::kProtect:
        on_protect(fact);
        break;
    case engine::BehaviorFact::Kind::kCpuidLeaf:
        // Hypervisor-range leaves are only queried to probe for a hypervisor
        // (leaf 1's bit-31 check rides ordinary feature queries and is not
        // judgment-worthy); the engine answers zeros here regardless.
        if (fact.aux >= 0x40000000ULL && fact.aux < 0x40000100ULL) {
            emit(EventTypeId::kAntiDebug, fact.pc, 0, fact.aux,
                 static_cast<std::uint32_t>(AntiDebugSubtype::kCpuidHypervisor), {}, 0);
        }
        break;
    case engine::BehaviorFact::Kind::kLoopSkip:
        // The engine force-exited a zero-write block cycle: pure-counter and
        // clock-wait delay loops are delay-family behavior. Every forced exit
        // is its own event (no per-site folding).
        emit(EventTypeId::kLoopSkip, fact.pc, 0, fact.aux, 0, {}, 0);
        break;
    }
}

void BehaviorRules::on_mem_read(const engine::BehaviorFact& fact)
{
    const auto addr = fact.addr;

    // PEB walk: TEB process-environment read arming, PEB Ldr-pointer read
    // firing ([TEB+0x60] -> [PEB+0x18], the shellcode chain-walk opener).
    if (params_.teb_address != 0 && addr == params_.teb_address + 0x60 &&
        fact.aux == params_.peb_address) {
        peb_armed_ = true;
    } else if (peb_armed_ && params_.peb_address != 0 && addr == params_.peb_address + 0x18) {
        peb_armed_ = false;
        emit(EventTypeId::kPebWalk, fact.pc, addr, 0, 0, {}, 0);
    }

    // BeingDebugged: the PEB flag byte read is the debugger probe itself -
    // attributed to sample code only (ntdll's own init-time check is
    // infrastructure, same attribution rule as the write ledger).
    if (params_.peb_address != 0 && addr == params_.peb_address + 0x2 &&
        pc_in_sample_image(params_, fact.pc)) {
        emit(EventTypeId::kAntiDebug, fact.pc, addr, 0,
             static_cast<std::uint32_t>(AntiDebugSubtype::kBeingDebugged), {}, 0);
    }

    // GetPC via TEB self-reference: reading own TEB from sample code.
    if (params_.teb_address != 0 && fact.aux == params_.teb_address &&
        pc_in_sample_image(params_, fact.pc)) {
        emit(EventTypeId::kGetPc, fact.pc, addr, 0, 0, {}, 0);
    }

    // Export walk: reads inside an export functions-array slot resolve to
    // the named export; module PE-header reads are the table-walk opener.
    if (const auto annotation = export_annotation(params_.export_slots, addr);
        !annotation.empty()) {
        emit(EventTypeId::kExportWalk, fact.pc, addr, 0, 0, annotation, 0);
    } else {
        for (const auto& module : params_.modules) {
            if (addr >= module.base && addr < module.base + engine::mem_region::kImageHeaderBytes) {
                emit(EventTypeId::kExportWalk, fact.pc, addr, 0, 0, {}, 0);
                break;
            }
        }
    }

    // KUSER_SHARED_DATA direct access: sample code reading the shared page
    // itself (TickCount/SystemTime fields and friends) instead of calling an
    // API - the delay-loop and anti-sandbox timing marker. The loader-module
    // reader filter sits engine-side (ntdll's own GetTickCount reads never
    // reach here); no image gate so shellcode readers are kept. addr carries
    // the field offset (0x320/0x324 TickCount, 0x14 SystemTime, ...), aux
    // the value read.
    if (addr >= 0x7FFE0000ULL && addr < 0x7FFE0000ULL + 0x1000) {
        emit(EventTypeId::kKusdAccess, fact.pc, addr, fact.aux, 0, {}, 0);
    }
}

void BehaviorRules::on_mem_write(const engine::BehaviorFact& fact)
{
    // Every fact IS a first-touch write of this run (the fault-based hook
    // fires once per page), so the page joins the SMC watch set directly.
    const auto page = fact.addr & ~(engine::kLedgerPageSize - 1);
    new_dirty_pages_.emplace(page, fact.pc);
}

void BehaviorRules::on_code(const engine::BehaviorFact& fact)
{
    // call $+5: E8 with a zero displacement lands on the next instruction;
    // the following pop (58-5F) then holds the return address.
    if (fact.length >= 5 && fact.bytes[0] == 0xE8 && fact.bytes[1] == 0 && fact.bytes[2] == 0 &&
        fact.bytes[3] == 0 && fact.bytes[4] == 0) {
        callpop_pc_ = fact.pc;
        return;
    }
    if (callpop_pc_ != 0 && fact.pc == callpop_pc_ + 5 && fact.length == 1 &&
        fact.bytes[0] >= 0x58 && fact.bytes[0] <= 0x5F) {
        callpop_pc_ = 0;
        emit(EventTypeId::kGetPc, fact.pc, fact.pc, 0, 0, {}, 0);
        return;
    }
    if (fact.pc == callpop_pc_ + 5) {
        callpop_pc_ = 0; // armed call consumed by any other follower
    }

    // fnstenv (D9 /6) followed within a window by mov r32, [esp+0xC] - the
    // saved-frame slot holding the return address.
    if (fact.length >= 2 && fact.bytes[0] == 0xD9 && (fact.bytes[1] & 0x38) == 0x30) {
        fnstenv_countdown_ = kFnstenvFollowerWindow;
        return;
    }
    if (fnstenv_countdown_ != 0) {
        --fnstenv_countdown_;
        if (fact.length >= 4 && fact.bytes[0] == 0x8B && (fact.bytes[1] & 0xC7) == 0x44 &&
            fact.bytes[2] == 0x24 && fact.bytes[3] == 0x0C) {
            fnstenv_countdown_ = 0;
            emit(EventTypeId::kGetPc, fact.pc, fact.pc, 0, 0, {}, 0);
        }
    }
}

void BehaviorRules::on_protect(const engine::BehaviorFact& fact)
{
    // One-shot RWX: protect or allocate landing on execute+write directly.
    const auto protection = fact.size;
    const bool rwx =
        protection == engine::kPageExecuteReadwrite || protection == engine::kPageExecuteWritecopy;
    // W+X sequence: a page first made plain-writable, then execute-enabled -
    // the classic write-payload-then-flip unpacking pattern.
    const bool exec_only =
        protection == engine::kPageExecute || protection == engine::kPageExecuteRead;
    bool sequence = false;
    if (exec_only) {
        const auto page = fact.addr & ~(engine::kLedgerPageSize - 1);
        const auto it = page_protection_.find(page);
        sequence = it != page_protection_.end() &&
                   (it->second == engine::kPageReadwrite || it->second == engine::kPageWritecopy);
    }
    page_protection_[fact.addr & ~(engine::kLedgerPageSize - 1)] = protection;
    if (!rwx && !sequence) {
        return;
    }
    // The window joins the syscall-classification set: an RWX allocation
    // spans [addr, addr+size) (aux carries the byte size), a W->X flipped
    // page is its own one-page window. Syscall pcs landing inside classify
    // as the shellcode's own direct syscalls.
    if (rwx && fact.aux != 0) {
        exec_windows_[fact.addr] = fact.addr + fact.aux;
    } else if (sequence) {
        const auto page = fact.addr & ~(engine::kLedgerPageSize - 1);
        exec_windows_[page] = page + engine::kLedgerPageSize;
    }
    emit(EventTypeId::kRwxAlloc, fact.pc, fact.addr, fact.aux, 0, {}, 0);
}

void BehaviorRules::on_event(const EventTypeId type, const EventPreamble& preamble,
                             const std::span<const std::uint8_t> fields)
{
    switch (type) {
    case EventTypeId::kBlockExec: {
        // Entry-arrival arming rides the block stream directly: the
        // previous block in sample territory (the sample image or a
        // sample-side execution window) followed by a landing on a
        // probe/handler API entry is the sample calling the API. The pair
        // test replaces the old xfer-edge arming - xfer events fire only on
        // the sample-territory edge rules now, so a sample->system-module
        // call never produces one, and the block sequence is the surviving
        // evidence. Probes entered from system-side sequences (CRT
        // internals, WER crash reporting) stay silent. The check consumes
        // the previous-block state either way, and both entry-arrival
        // checks (probe + exception-handler-install) share the value.
        const bool previous_sample =
            last_block_valid_ && last_block_tid_ == preamble.tid && last_block_sample_;
        if (previous_sample) {
            if (std::binary_search(params_.probe_api_entries.begin(),
                                   params_.probe_api_entries.end(), preamble.pc)) {
                const auto annotation = function_annotation(params_, preamble.pc);
                emit(EventTypeId::kAntiDebug, preamble.pc, preamble.pc, preamble.pc,
                     static_cast<std::uint32_t>(AntiDebugSubtype::kProbeApiCall), annotation,
                     preamble.tid);
            }
        }
        // Exception-handler install: same attribution as the probe list -
        // only an entry reached straight from a sample-side block is the
        // sample installing its own exception handler; CRT/WER machinery
        // entering registration APIs from system-side sequences stays
        // silent.
        if (previous_sample) {
            if (std::binary_search(params_.exception_handler_api_entries.begin(),
                                   params_.exception_handler_api_entries.end(), preamble.pc)) {
                const auto annotation = function_annotation(params_, preamble.pc);
                emit(EventTypeId::kExceptionHandlerInstall, preamble.pc, preamble.pc, preamble.pc,
                     0, annotation, preamble.tid);
            }
        }
        // remember this block's territory for the next entry-arrival check
        last_block_sample_ = pc_in_sample_image(params_, preamble.pc);
        if (!last_block_sample_) {
            for (const auto& [base, end] : exec_windows_) {
                if (preamble.pc >= base && preamble.pc < end) {
                    last_block_sample_ = true;
                    break;
                }
            }
        }
        last_block_tid_ = preamble.tid;
        last_block_valid_ = true;
        // SMC cross: a block landing on a page first-written this run.
        const auto page = preamble.pc & ~(engine::kLedgerPageSize - 1);
        if (const auto it = new_dirty_pages_.find(page); it != new_dirty_pages_.end()) {
            emit(EventTypeId::kSmcExecute, preamble.pc, preamble.pc, it->second, 0, {},
                 preamble.tid);
            // OEP candidate: the page is runtime (outside the sample
            // image), written this run, and this is its first executed block -
            // the unpacker handing control to its unpacked payload. First
            // candidate per page; the repair picks the one inside the dumped
            // payload image region.
            const bool in_sample_image =
                preamble.pc >= params_.sample_image_base &&
                preamble.pc < params_.sample_image_base + params_.sample_image_size;
            if (!in_sample_image && oep_pages_.find(page) == oep_pages_.end()) {
                oep_pages_.insert(page);
                emit(EventTypeId::kOepCandidate, preamble.pc, preamble.pc, it->second, 0, {},
                     preamble.tid);
            }
        }
        // rdtsc burst window over block count.
        ++window_blocks_;
        if (window_blocks_ >= params_.rdtsc_window_blocks) {
            if (window_rdtsc_ >= params_.rdtsc_burst_threshold) {
                emit(EventTypeId::kAntiDebug, preamble.pc, 0, window_rdtsc_,
                     static_cast<std::uint32_t>(AntiDebugSubtype::kRdtscBurst), {}, preamble.tid);
            }
            window_blocks_ = 0;
            window_rdtsc_ = 0;
        }
        break;
    }
    case EventTypeId::kRdtsc:
        ++window_rdtsc_;
        break;
    case EventTypeId::kXfer:
        // xfer events fire only on the sample-territory edge rules (see the
        // engine's is_xfer_edge); the entry-arrival arming reads the block
        // stream instead - a sample->system call never produces one. What
        // remains here is the in-place-unpacker OEP check: the handoff
        // crosses into a page first-written this run.
        if (fields.size() >= 8) {
            // in-place unpackers: the unpacked payload lives inside the
            // sample image, so the handoff crosses a section boundary (the
            // xfer fires) while landing on a page first-written this run.
            const auto landed_page = preamble.pc & ~(engine::kLedgerPageSize - 1);
            if (new_dirty_pages_.find(landed_page) != new_dirty_pages_.end() &&
                oep_pages_.find(landed_page) == oep_pages_.end()) {
                oep_pages_.insert(landed_page);
                emit(EventTypeId::kOepCandidate, preamble.pc, preamble.pc,
                     new_dirty_pages_.at(landed_page), 0, {}, preamble.tid);
            }
        }
        break;
    case EventTypeId::kSyscall: {
        // Direct-syscall classification: the sample's own code counts as
        // behavior (the same attribution rule as the write ledger). The
        // sample region sits outside every ntdll stub by definition, so a
        // sample-region syscall is always a direct one. A syscall inside a
        // runtime execution window (RWX allocation, W->X flipped page) is
        // the shellcode's own direct syscall - the window base rides aux.
        // Function-form payload, read through the
        // contract codec: number, flags, status, stack return address, then
        // the parameter record stream (raw u64 register values today).
        const auto call = read_syscall(fields);
        if (!call.has_value()) {
            break; // short payload: deterministic skip
        }
        // Raw-register record lookup: record i is register argument i+1
        // (rcx/rdx/r8/r9 in Windows x64 syscall ABI order).
        const auto raw_register = [&call](const std::size_t index) {
            std::size_t cursor = 0;
            std::size_t seen = 0;
            while (cursor < call->records.size()) {
                const auto record = read_param_record(call->records, cursor);
                if (!record.has_value()) {
                    break;
                }
                if (seen == index && record->bytes.size() == 8) {
                    std::uint64_t value = 0;
                    for (std::size_t i = 0; i < 8; ++i) {
                        value |= static_cast<std::uint64_t>(record->bytes[i]) << (8 * i);
                    }
                    return value;
                }
                ++seen;
            }
            return std::uint64_t{0};
        };
        const bool in_sample = pc_in_sample_image(params_, preamble.pc);
        const std::uint64_t window_base = [&] {
            for (const auto& [base, end] : exec_windows_) {
                if (preamble.pc >= base && preamble.pc < end) {
                    return base;
                }
            }
            return std::uint64_t{0};
        }();
        if (in_sample || window_base != 0) {
            emit(EventTypeId::kDirectSyscall, preamble.pc, preamble.pc, window_base, 0, {},
                 preamble.tid);
        } else if (std::binary_search(params_.syscall_entries.begin(),
                                      params_.syscall_entries.end(), preamble.pc)) {
            // Indirect syscall: a stub-internal syscall whose stack return
            // address belongs to the sample image or a runtime execution
            // window - the sample called (or jump-entered with a faked
            // return address) into the stub. System-internal callers
            // (kernelbase/CRT) return into system modules and stay silent.
            const auto return_address = call->fields.caller_retaddr;
            const bool sample_caller = pc_in_sample_image(params_, return_address);
            bool window_caller = false;
            for (const auto& [base, end] : exec_windows_) {
                if (return_address >= base && return_address < end) {
                    window_caller = true;
                    break;
                }
            }
            if (sample_caller || window_caller) {
                emit(EventTypeId::kIndirectSyscall, preamble.pc, return_address, 0, 0, {},
                     preamble.tid);
            }
        }
        // Probe-class NtQueryInformationProcess issued directly by the
        // sample as a hand-rolled syscall (the import-level call is
        // covered by the probe-api-entry rule). The information class rides
        // raw register record 1 (arg2 = rdx, ProcessInformationClass).
        // Queries that merely transit system machinery (CRT internals, WER
        // crash reporting) have a system-side pc and are that system's
        // behavior, not ours.
        if (params_.query_process_number != 0 && (in_sample || window_base != 0)) {
            const auto number = call->fields.number;
            const auto info_class = static_cast<std::uint32_t>(raw_register(1));
            // ProcessDebugPort(7) / ProcessDebugObjectHandle(30) /
            // ProcessDebugFlags(31) - winnt.h values, spelled out because
            // this layer builds on Linux too.
            const bool debug_probe = info_class == 7 || info_class == 30 || info_class == 31;
            if (number == params_.query_process_number && debug_probe) {
                emit(EventTypeId::kAntiDebug, preamble.pc, preamble.pc, info_class,
                     static_cast<std::uint32_t>(AntiDebugSubtype::kQueryInformationProcess), {},
                     preamble.tid);
            }
        }
        break;
    }
    case EventTypeId::kException:
        // Exception report: an exception during the sample's execution is
        // part of that run regardless of where the faulting instruction
        // sits (sample image or a system module), so unlike the api-call
        // signals this carries no image attribution. Payload, u32 LE: the
        // status code, the disposition, then u64 the related pc - the fault
        // pc for a handler-dispatch report (disposition 2: the engine-side
        // dispatcher staged that guest handler; preamble.pc is the handler
        // entry). The pair lets the report separate exceptions the sample
        // absorbed (SEH control flow, anti-debug traps) from the crash
        // that killed it, and names who absorbed them.
        if (fields.size() >= 8) {
            const auto code = static_cast<std::uint32_t>(fields[0]) |
                              (static_cast<std::uint32_t>(fields[1]) << 8) |
                              (static_cast<std::uint32_t>(fields[2]) << 16) |
                              (static_cast<std::uint32_t>(fields[3]) << 24);
            const auto chance = static_cast<std::uint32_t>(fields[4]) |
                                (static_cast<std::uint32_t>(fields[5]) << 8) |
                                (static_cast<std::uint32_t>(fields[6]) << 16) |
                                (static_cast<std::uint32_t>(fields[7]) << 24);
            const auto subtype =
                static_cast<std::uint32_t>(chance == 0   ? ExceptionDisposition::kFirstChance
                                           : chance == 2 ? ExceptionDisposition::kHandlerDispatch
                                                         : ExceptionDisposition::kUnhandled);
            if (chance == 2 && fields.size() >= 16) {
                // handler attribution: pc is the handler entry, the fault pc
                // rides the payload, the handler resolves against the export
                // slots for the module!function annotation
                std::uint64_t related = 0;
                for (std::size_t i = 0; i < 8; ++i) {
                    related |= static_cast<std::uint64_t>(fields[8 + i]) << (8 * i);
                }
                const auto annotation = function_annotation(params_, preamble.pc);
                emit(EventTypeId::kExceptionDisposition, preamble.pc, related, code, subtype,
                     annotation, preamble.tid);
                break;
            }
            emit(EventTypeId::kExceptionDisposition, preamble.pc, preamble.pc, code, subtype, {},
                 preamble.tid);
        }
        break;
    default:
        break;
    }
}

} // namespace sheller::behavior
