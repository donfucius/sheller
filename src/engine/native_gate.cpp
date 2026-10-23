#include "native_gate.h"

#include <Zydis/Zydis.h>

namespace sheller::engine::native_gate {
namespace {

// Per-decode byte window: comfortably above the 15-byte x86 instruction
// ceiling. When a decode would run off the window the fill slides forward,
// so a terminator-less nop sled still terminates by budget, not by luck.
constexpr std::size_t kByteWindow = 96;
// Statically-resolvable store targets recorded per scan; the overflow case
// answers kDecodeFailure (an incomplete self-write check is not an admit).
constexpr std::size_t kMaxResolvedWrites = 64;

struct ResolvedWrite {
    std::uint64_t address;
    std::uint32_t size;
};

bool is_blacklisted_mnemonic(const ZydisMnemonic mnemonic, RejectReason& reason)
{
    switch (mnemonic) {
    case ZYDIS_MNEMONIC_SYSCALL:
    case ZYDIS_MNEMONIC_SYSENTER:
    case ZYDIS_MNEMONIC_SYSRET:
    case ZYDIS_MNEMONIC_SYSEXIT:
        reason = RejectReason::kSyscall;
        return true;
    case ZYDIS_MNEMONIC_INT:
    case ZYDIS_MNEMONIC_INT1:
    case ZYDIS_MNEMONIC_INT3:
    case ZYDIS_MNEMONIC_INTO:
    case ZYDIS_MNEMONIC_UD0:
    case ZYDIS_MNEMONIC_UD1:
    case ZYDIS_MNEMONIC_UD2:
        reason = RejectReason::kSoftInterrupt;
        return true;
    case ZYDIS_MNEMONIC_RDTSC:
    case ZYDIS_MNEMONIC_RDTSCP:
    case ZYDIS_MNEMONIC_RDPMC:
        reason = RejectReason::kClockRead;
        return true;
    case ZYDIS_MNEMONIC_CPUID:
        reason = RejectReason::kFeatureQuery;
        return true;
    case ZYDIS_MNEMONIC_IN:
    case ZYDIS_MNEMONIC_INSB:
    case ZYDIS_MNEMONIC_INSW:
    case ZYDIS_MNEMONIC_INSD:
    case ZYDIS_MNEMONIC_OUT:
    case ZYDIS_MNEMONIC_OUTSB:
    case ZYDIS_MNEMONIC_OUTSW:
    case ZYDIS_MNEMONIC_OUTSD:
        reason = RejectReason::kPortIo;
        return true;
    case ZYDIS_MNEMONIC_RDRAND:
    case ZYDIS_MNEMONIC_RDSEED:
    case ZYDIS_MNEMONIC_XBEGIN:
    case ZYDIS_MNEMONIC_XABORT:
    case ZYDIS_MNEMONIC_XEND:
    case ZYDIS_MNEMONIC_XTEST:
        reason = RejectReason::kNondeterministic;
        return true;
    case ZYDIS_MNEMONIC_F2XM1:
    case ZYDIS_MNEMONIC_FYL2X:
    case ZYDIS_MNEMONIC_FYL2XP1:
    case ZYDIS_MNEMONIC_FPATAN:
    case ZYDIS_MNEMONIC_FPTAN:
    case ZYDIS_MNEMONIC_FSIN:
    case ZYDIS_MNEMONIC_FSINCOS:
    case ZYDIS_MNEMONIC_FCOS:
    case ZYDIS_MNEMONIC_FSCALE:
        reason = RejectReason::kX87Transcendental;
        return true;
    case ZYDIS_MNEMONIC_CALL:
    case ZYDIS_MNEMONIC_RET:
    case ZYDIS_MNEMONIC_IRET:
    case ZYDIS_MNEMONIC_IRETD:
    case ZYDIS_MNEMONIC_IRETQ:
        reason = RejectReason::kCallRet;
        return true;
    case ZYDIS_MNEMONIC_HLT:
        reason = RejectReason::kHalt;
        return true;
    default:
        return false;
    }
}

// One decoded instruction against every blacklist, in classification order.
[[nodiscard]] RejectReason classify(const ZydisDecodedInstruction& insn,
                                    const ZydisDecodedOperand* operands)
{
    RejectReason reason = RejectReason::kNone;
    if (is_blacklisted_mnemonic(insn.mnemonic, reason)) {
        return reason;
    }
    if ((insn.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_FS) != 0 ||
        (insn.attributes & ZYDIS_ATTRIB_HAS_SEGMENT_GS) != 0) {
        return RejectReason::kSegmentPrefix;
    }
    if ((insn.attributes & ZYDIS_ATTRIB_HAS_LOCK) != 0 ||
        (insn.attributes & ZYDIS_ATTRIB_HAS_XACQUIRE) != 0 ||
        (insn.attributes & ZYDIS_ATTRIB_HAS_XRELEASE) != 0) {
        return RejectReason::kLockPrefix;
    }
    if ((insn.attributes & ZYDIS_ATTRIB_HAS_VEX) != 0 ||
        (insn.attributes & ZYDIS_ATTRIB_HAS_EVEX) != 0) {
        return RejectReason::kVectorEncoding;
    }
    // System-instruction catch-all (wrmsr/lgdt/swapgs/monitor-mwait/VMX/
    // SGX/segment loads...) plus the privileged register files.
    if (insn.meta.category == ZYDIS_CATEGORY_SYSTEM || insn.meta.category == ZYDIS_CATEGORY_SEGOP) {
        return RejectReason::kHalt;
    }
    for (std::size_t i = 0; i < insn.operand_count; ++i) {
        if (operands[i].type != ZYDIS_OPERAND_TYPE_REGISTER) {
            continue;
        }
        const auto reg_class = ZydisRegisterGetClass(operands[i].reg.value);
        if (reg_class == ZYDIS_REGCLASS_CONTROL || reg_class == ZYDIS_REGCLASS_DEBUG) {
            return RejectReason::kHalt;
        }
    }
    return RejectReason::kNone;
}

// The instruction stores to memory whose effective address the scan can
// fully resolve (rip-relative or pure displacement). Those targets are
// checked against the scanned byte ranges once every block extent is known;
// register-indirect stores stay for the probe's write-journal cross-check.
[[nodiscard]] bool resolve_store_target(const ZydisDecodedInstruction& insn,
                                        const ZydisDecodedOperand& operand,
                                        const std::uint64_t instruction_va, std::uint64_t& target)
{
    if (operand.type != ZYDIS_OPERAND_TYPE_MEMORY ||
        (operand.actions & ZYDIS_OPERAND_ACTION_MASK_WRITE) == 0) {
        return false;
    }
    if (operand.mem.base == ZYDIS_REGISTER_RIP) {
        target = instruction_va + insn.length + operand.mem.disp.value;
        return true;
    }
    if (operand.mem.base == ZYDIS_REGISTER_NONE && operand.mem.index == ZYDIS_REGISTER_NONE) {
        target = static_cast<std::uint64_t>(operand.mem.disp.value);
        return true;
    }
    return false;
}

[[nodiscard]] bool ranges_intersect(const std::uint64_t a_start, const std::uint64_t a_size,
                                    const std::uint64_t b_start, const std::uint64_t b_end)
{
    return a_start < b_end && b_start < a_start + a_size;
}

struct ScanContext {
    const std::uint64_t* block_vas;
    std::size_t block_count;
    GateVerdict& verdict;
    ResolvedWrite writes[kMaxResolvedWrites]{};
    std::size_t write_count{};
    bool write_overflow{};

    [[nodiscard]] bool in_block_set(const std::uint64_t address) const
    {
        for (std::size_t i = 0; i < block_count; ++i) {
            if (block_vas[i] == address) {
                return true;
            }
        }
        return false;
    }

    // A direct target outside the block set is a loop exit: dedupe into the
    // bounded exit set, overflow = no DR0-3 stop set = reject.
    [[nodiscard]] RejectReason add_exit(const std::uint64_t target)
    {
        for (std::size_t i = 0; i < verdict.exit_target_count; ++i) {
            if (verdict.exit_targets[i] == target) {
                return RejectReason::kNone;
            }
        }
        if (verdict.exit_target_count >= kMaxExitTargets) {
            return RejectReason::kExitTargetOverflow;
        }
        verdict.exit_targets[verdict.exit_target_count++] = target;
        return RejectReason::kNone;
    }

    // Direct successors of a conditional/unconditional branch: the branch
    // target (unless it re-enters the block set) and, for conditional
    // branches, the fall-through.
    [[nodiscard]] RejectReason check_successor(const std::uint64_t target)
    {
        if (in_block_set(target)) {
            return RejectReason::kNone;
        }
        return add_exit(target);
    }
};

} // namespace

GateVerdict scan(const std::uint64_t* const block_vas, const std::size_t block_count,
                 const MachineMode mode, ReadBytes read, void* context)
{
    GateVerdict verdict{};
    if (block_count == 0 || block_count > kMaxLoopBlocks || read == nullptr) {
        verdict.reason = RejectReason::kDecodeFailure;
        return verdict;
    }

    ZydisDecoder decoder{};
    if (mode == MachineMode::kX64) {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    } else {
        ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_COMPAT_32, ZYDIS_STACK_WIDTH_32);
    }

    ScanContext ctx{block_vas, block_count, verdict};
    ZydisDecodedInstruction insn{};
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT]{};
    std::uint8_t window[kByteWindow]{};
    std::size_t instruction_count = 0;

    for (std::size_t block = 0; block < block_count; ++block) {
        std::uint64_t position = block_vas[block];
        verdict.extents[verdict.extent_count].start = position;
        std::uint64_t window_base = 0;
        std::size_t window_len = 0;
        bool terminated = false;
        while (!terminated) {
            if (++instruction_count > kMaxScanInstructions) {
                verdict.reason = RejectReason::kDecodeFailure;
                return verdict;
            }
            // Slide the byte window so the next instruction always fits; a
            // short fill (region end straddling the request) is fine while
            // it still covers a full max-length instruction.
            if (position < window_base ||
                (position - window_base) + 15 > static_cast<std::uint64_t>(window_len)) {
                window_base = position;
                window_len = read(context, position, window, kByteWindow);
                if (window_len == 0) {
                    verdict.reason = RejectReason::kDecodeFailure;
                    return verdict;
                }
            }
            if (ZydisDecoderDecodeFull(&decoder, window + (position - window_base),
                                       window_len - (position - window_base), &insn,
                                       operands) != ZYAN_STATUS_SUCCESS) {
                verdict.reason = RejectReason::kDecodeFailure;
                return verdict;
            }

            const RejectReason reject = classify(insn, operands);
            if (reject != RejectReason::kNone) {
                verdict.reason = reject;
                return verdict;
            }

            std::uint64_t store_target = 0;
            for (std::size_t i = 0; i < insn.operand_count; ++i) {
                if (resolve_store_target(insn, operands[i], position, store_target)) {
                    if (ctx.write_count >= kMaxResolvedWrites) {
                        ctx.write_overflow = true;
                    } else {
                        ctx.writes[ctx.write_count++] = {
                            store_target, static_cast<std::uint32_t>(operands[i].size / 8)};
                    }
                }
            }

            // Control flow: classify successors, then end the block. Far and
            // reg/mem transfers the closure cannot follow are rejects; the
            // mnemonic blacklist already removed call/ret/int families.
            if (insn.meta.category == ZYDIS_CATEGORY_COND_BR ||
                insn.meta.category == ZYDIS_CATEGORY_UNCOND_BR) {
                if (insn.meta.branch_type == ZYDIS_BRANCH_TYPE_FAR) {
                    verdict.reason = RejectReason::kIndirectBranch;
                    return verdict;
                }
                bool conditional = false;
                std::uint64_t target = 0;
                if (insn.meta.category == ZYDIS_CATEGORY_COND_BR) {
                    conditional = true;
                }
                if (operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE) {
                    ZyanU64 absolute = 0;
                    if (ZydisCalcAbsoluteAddress(&insn, &operands[0], position, &absolute) !=
                        ZYAN_STATUS_SUCCESS) {
                        verdict.reason = RejectReason::kDecodeFailure;
                        return verdict;
                    }
                    target = absolute;
                } else {
                    verdict.reason = RejectReason::kIndirectBranch;
                    return verdict;
                }
                const RejectReason branch_reject = ctx.check_successor(target);
                if (branch_reject != RejectReason::kNone) {
                    verdict.reason = branch_reject;
                    return verdict;
                }
                if (conditional) {
                    const RejectReason fall_reject = ctx.check_successor(position + insn.length);
                    if (fall_reject != RejectReason::kNone) {
                        verdict.reason = fall_reject;
                        return verdict;
                    }
                }
                position += insn.length;
                terminated = true;
                break;
            }
            position += insn.length;
        }
        verdict.extents[verdict.extent_count].end = position;
        ++verdict.extent_count;
    }

    if (ctx.write_overflow) {
        verdict.reason = RejectReason::kDecodeFailure;
        return verdict;
    }
    // Self-modification: any fully-resolved store landing in the scanned
    // bytes voids the closure proof. Register-indirect stores are covered by
    // the probe's write-journal cross-check in run_loop_probe.
    for (std::size_t i = 0; i < ctx.write_count; ++i) {
        for (std::size_t e = 0; e < verdict.extent_count; ++e) {
            if (ranges_intersect(ctx.writes[i].address, ctx.writes[i].size,
                                 verdict.extents[e].start, verdict.extents[e].end)) {
                verdict.reason = RejectReason::kSelfWrite;
                return verdict;
            }
        }
    }

    verdict.category = Verdict::kAdmitZeroWrite; // provisional; probe upgrades on writes
    return verdict;
}

const char* verdict_name(const Verdict verdict)
{
    switch (verdict) {
    case Verdict::kAdmitZeroWrite:
        return "admitted_zero_write";
    case Verdict::kAdmitCompute:
        return "admitted_compute";
    case Verdict::kReject:
        return "rejected";
    }
    return "invalid";
}

const char* reject_reason_name(const RejectReason reason)
{
    switch (reason) {
    case RejectReason::kNone:
        return "none";
    case RejectReason::kSyscall:
        return "syscall";
    case RejectReason::kSoftInterrupt:
        return "soft_interrupt";
    case RejectReason::kClockRead:
        return "clock_read";
    case RejectReason::kFeatureQuery:
        return "feature_query";
    case RejectReason::kPortIo:
        return "port_io";
    case RejectReason::kHalt:
        return "halt";
    case RejectReason::kCallRet:
        return "call_ret";
    case RejectReason::kIndirectBranch:
        return "indirect_branch";
    case RejectReason::kX87Transcendental:
        return "x87_transcendental";
    case RejectReason::kSegmentPrefix:
        return "segment_prefix";
    case RejectReason::kLockPrefix:
        return "lock_prefix";
    case RejectReason::kVectorEncoding:
        return "vector_encoding";
    case RejectReason::kNondeterministic:
        return "nondeterministic";
    case RejectReason::kClosureEscape:
        return "closure_escape";
    case RejectReason::kExitTargetOverflow:
        return "exit_target_overflow";
    case RejectReason::kSelfWrite:
        return "self_write";
    case RejectReason::kClockSensitiveRead:
        return "clock_sensitive_read";
    case RejectReason::kHookSensitiveInsn:
        return "hook_sensitive_insn";
    case RejectReason::kDecodeFailure:
        return "decode_failure";
    }
    return "invalid";
}

} // namespace sheller::engine::native_gate
