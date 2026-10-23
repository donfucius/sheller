// Loop-native-gate static scan: closed-CFG classification over fixture
// bytes. Portable by design - the gate is a pure Zydis scan with a
// caller-supplied read callback, no unicorn involved.

#include "native_gate.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

using namespace sheller::engine::native_gate;

namespace {

// Flat fixture memory the read callback serves from; reads past the end
// answer 0 (the gate must answer kDecodeFailure, never a guess).
class FlatMemory {
  public:
    FlatMemory(const std::uint64_t base, std::vector<std::uint8_t> bytes)
        : base_(base), bytes_(std::move(bytes))
    {
    }

    static std::size_t read(void* const context, const std::uint64_t va, std::uint8_t* const out,
                            const std::size_t size)
    {
        auto* memory = static_cast<FlatMemory*>(context);
        if (va < memory->base_ || va >= memory->base_ + memory->bytes_.size()) {
            return 0;
        }
        const auto offset = va - memory->base_;
        const auto take = std::min(size, memory->bytes_.size() - offset);
        std::memcpy(out, memory->bytes_.data() + offset, take);
        return take;
    }

  private:
    std::uint64_t base_;
    std::vector<std::uint8_t> bytes_;
};

GateVerdict scan_bytes(const std::uint64_t base, const std::vector<std::uint8_t>& bytes,
                       const std::vector<std::uint64_t>& blocks,
                       const MachineMode mode = MachineMode::kX64)
{
    FlatMemory memory(base, bytes);
    return scan(blocks.data(), blocks.size(), mode, &FlatMemory::read, &memory);
}

// dec rcx ; jnz back - the canonical pure-counter delay loop.
std::vector<std::uint8_t> dec_jnz_bytes()
{
    return {0x48, 0xFF, 0xC9, 0x75, 0xFB};
}

} // namespace

TEST(NativeGateTest, DecJnzClosedLoopAdmittedWithFallOutExit)
{
    const auto verdict = scan_bytes(0x1000, dec_jnz_bytes(), {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kAdmitZeroWrite);
    EXPECT_EQ(verdict.reason, RejectReason::kNone);
    ASSERT_EQ(verdict.exit_target_count, 1u);
    EXPECT_EQ(verdict.exit_targets[0], 0x1005u); // the jnz fall-out
    ASSERT_EQ(verdict.extent_count, 1u);
    EXPECT_EQ(verdict.extents[0].start, 0x1000u);
    EXPECT_EQ(verdict.extents[0].end, 0x1005u);
}

TEST(NativeGateTest, RepMovsLoopAdmitted)
{
    // rep movsq ; dec rcx ; jnz head - a compute-loop shape writing through
    // registers (rdi): unresolvable statically, so no self-write reject.
    const std::vector<std::uint8_t> bytes = {0xF3, 0x48, 0xA5, 0x48, 0xFF, 0xC9, 0x75, 0xF8};
    const auto verdict = scan_bytes(0x1000, bytes, {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kAdmitZeroWrite);
    ASSERT_EQ(verdict.exit_target_count, 1u);
    EXPECT_EQ(verdict.exit_targets[0], 0x1008u);
}

TEST(NativeGateTest, SyscallEncodingRejected)
{
    const std::vector<std::uint8_t> bytes = {0x48, 0xFF, 0xC9, 0x0F, 0x05, 0x75, 0xF9};
    const auto verdict = scan_bytes(0x1000, bytes, {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kSyscall);
}

TEST(NativeGateTest, IndirectJumpRejected)
{
    const auto verdict = scan_bytes(0x1000, {0xFF, 0xE0}, {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kIndirectBranch);
}

TEST(NativeGateTest, RegisterBranchRejected)
{
    const auto verdict = scan_bytes(0x1000, {0x48, 0xFF, 0xE1}, {0x1000}); // jmp rcx
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kIndirectBranch);
}

TEST(NativeGateTest, FsPrefixRejected)
{
    const std::vector<std::uint8_t> bytes = {0x64, 0x8B, 0x04, 0x25, 0x00, 0x04, 0x00, 0x00};
    const auto verdict = scan_bytes(0x1000, bytes, {0x1000}); // mov eax, fs:[0x400]
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kSegmentPrefix);
}

TEST(NativeGateTest, ClockReadRejected)
{
    const auto verdict = scan_bytes(0x1000, {0x0F, 0x31}, {0x1000}); // rdtsc
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kClockRead);
}

TEST(NativeGateTest, CpuidRejected)
{
    const auto verdict = scan_bytes(0x1000, {0x0F, 0xA2}, {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kFeatureQuery);
}

TEST(NativeGateTest, PortIoRejected)
{
    const auto verdict = scan_bytes(0x1000, {0xE4, 0x60}, {0x1000}); // in al, 0x60
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kPortIo);
}

TEST(NativeGateTest, HaltRejected)
{
    const auto verdict = scan_bytes(0x1000, {0xF4}, {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kHalt);
}

TEST(NativeGateTest, ControlRegisterAccessRejected)
{
    const auto verdict = scan_bytes(0x1000, {0x0F, 0x22, 0xC0}, {0x1000}); // mov cr0, rax
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kHalt);
}

TEST(NativeGateTest, SoftInterruptRejected)
{
    const auto verdict = scan_bytes(0x1000, {0xCD, 0x20}, {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kSoftInterrupt);
}

TEST(NativeGateTest, CallAndRetRejected)
{
    const auto call = scan_bytes(0x1000, {0xE8, 0x00, 0x00, 0x00, 0x00}, {0x1000});
    EXPECT_EQ(call.reason, RejectReason::kCallRet);
    const auto ret = scan_bytes(0x1000, {0xC3}, {0x1000});
    EXPECT_EQ(ret.reason, RejectReason::kCallRet);
}

TEST(NativeGateTest, X87TranscendentalRejected)
{
    const auto verdict = scan_bytes(0x1000, {0xD9, 0xFE}, {0x1000}); // fsin
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kX87Transcendental);
}

TEST(NativeGateTest, LockPrefixRejected)
{
    const std::vector<std::uint8_t> bytes = {0xF0, 0x48, 0x01, 0x01}; // lock add [rcx], rax
    const auto verdict = scan_bytes(0x1000, bytes, {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kLockPrefix);
}

TEST(NativeGateTest, VexEncodingRejected)
{
    const auto verdict = scan_bytes(0x1000, {0xC5, 0xF8, 0x28, 0xC1}, {0x1000}); // vmovaps
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kVectorEncoding);
}

TEST(NativeGateTest, RdrandRejected)
{
    const auto verdict = scan_bytes(0x1000, {0x0F, 0xC7, 0xF0}, {0x1000}); // rdrand eax
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kNondeterministic);
}

TEST(NativeGateTest, ExitTargetOverflowRejected)
{
    // A 7-block ring (a TCG block ends at its first conditional, so the
    // distinct exits spread across blocks). Five of the conditionals fall
    // out to five distinct targets: no DR0-3 stop set exists for that shape.
    std::vector<std::uint8_t> bytes(0x40, 0x90);
    bytes[0x00] = 0x48; // A @0x1000: dec rcx
    bytes[0x01] = 0xFF;
    bytes[0x02] = 0xC9;
    bytes[0x03] = 0x75; // A: jnz 0x1010 (B)
    bytes[0x04] = 0x0B; //    fallthrough C=0x1005 stays in the ring
    bytes[0x05] = 0x90; // C: nop
    bytes[0x06] = 0xEB; // C: jmp A
    bytes[0x07] = 0xF9;
    bytes[0x10] = 0x74; // B @0x1010: je 0x1024 (exit 1)
    bytes[0x11] = 0x12; //    fallthrough D=0x1012 stays in the ring
    bytes[0x12] = 0x72; // D: jc 0x1028 (exit 2)
    bytes[0x13] = 0x14; //    fallthrough E=0x1014 stays in the ring
    bytes[0x14] = 0x7A; // E: jp 0x102C (exit 3)
    bytes[0x15] = 0x16; //    fallthrough F=0x1016 stays in the ring
    bytes[0x16] = 0x79; // F: jns 0x1030 (exit 4)
    bytes[0x17] = 0x18; //    fallthrough G=0x1018 stays in the ring
    bytes[0x18] = 0x7C; // G: jl 0x1034 (exit 5 -> overflow)
    bytes[0x19] = 0x1A;
    const std::vector<std::uint64_t> blocks = {0x1000, 0x1005, 0x1010, 0x1012,
                                               0x1014, 0x1016, 0x1018};
    const auto verdict = scan_bytes(0x1000, bytes, blocks);
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kExitTargetOverflow);
    EXPECT_EQ(verdict.exit_target_count, kMaxExitTargets);
}

TEST(NativeGateTest, DuplicateExitsDeduped)
{
    // Two branches landing on the same fall-out: one exit slot, admitted.
    std::vector<std::uint8_t> bytes(0x20, 0x90);
    bytes[0x00] = 0x48; // A @0x1000: dec rcx
    bytes[0x01] = 0xFF;
    bytes[0x02] = 0xC9;
    bytes[0x03] = 0x74; // A: jz 0x1010 (B, in the ring)
    bytes[0x04] = 0x0B; //    fallthrough C=0x1005
    bytes[0x05] = 0x90; // C: nop
    bytes[0x06] = 0x74; // C: jz 0x100D (exit, first sighting)
    bytes[0x07] = 0x05; //    fallthrough D=0x1008
    bytes[0x08] = 0xEB; // D: jmp A
    bytes[0x09] = 0xF6;
    bytes[0x10] = 0x90; // B @0x1010: nop
    bytes[0x11] = 0xEB; // B: jmp 0x100D (same exit, deduped)
    bytes[0x12] = 0xFA;
    const std::vector<std::uint64_t> blocks = {0x1000, 0x1005, 0x1008, 0x1010};
    const auto verdict = scan_bytes(0x1000, bytes, blocks);
    EXPECT_EQ(verdict.category, Verdict::kAdmitZeroWrite);
    ASSERT_EQ(verdict.exit_target_count, 1u);
    EXPECT_EQ(verdict.exit_targets[0], 0x100Du);
}

TEST(NativeGateTest, MultiBlockClosureAdmitted)
{
    // Block A decs and jumps to block B; block B decs and jnz's back to A.
    std::vector<std::uint8_t> bytes(0x20, 0x90);
    bytes[0] = 0x48; // A @0x1000: dec rax
    bytes[1] = 0xFF;
    bytes[2] = 0xC8;
    bytes[3] = 0xEB; // A: jmp 0x1010
    bytes[4] = 0x0B;
    bytes[0x10] = 0x48; // B @0x1010: dec rcx
    bytes[0x11] = 0xFF;
    bytes[0x12] = 0xC9;
    bytes[0x13] = 0x75; // B: jnz 0x1000
    bytes[0x14] = 0xEB;
    const auto verdict = scan_bytes(0x1000, bytes, {0x1000, 0x1010});
    EXPECT_EQ(verdict.category, Verdict::kAdmitZeroWrite);
    ASSERT_EQ(verdict.exit_target_count, 1u);
    EXPECT_EQ(verdict.exit_targets[0], 0x1015u);
    ASSERT_EQ(verdict.extent_count, 2u);
}

TEST(NativeGateTest, RipRelativeSelfWriteRejected)
{
    // mov qword [rip-8], 0 ; jnz head - the store lands inside the scanned
    // range: self-modification voids the closure proof.
    std::vector<std::uint8_t> bytes = {0x48, 0xC7, 0x05, 0xF8, 0xFF, 0xFF,
                                       0xFF, 0x00, 0x00, 0x00, 0x00};
    bytes.insert(bytes.end(), {0x75, 0xF3}); // jnz 0x1000
    const auto verdict = scan_bytes(0x1000, bytes, {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kSelfWrite);
}

TEST(NativeGateTest, SelfWriteIntoLaterBlockRejected)
{
    // Block A stores to block B's bytes (the range check runs after all
    // extents are known).
    std::vector<std::uint8_t> bytes(0x40, 0x90);
    // A @0x1000: mov qword [rip+0x15], 0 -> target 0x1020, inside B
    bytes[0] = 0x48;
    bytes[1] = 0xC7;
    bytes[2] = 0x05;
    bytes[3] = 0x15;
    bytes[4] = 0x00;
    bytes[5] = 0x00;
    bytes[6] = 0x00;
    bytes[7] = 0x00;
    bytes[8] = 0x00;
    bytes[9] = 0x00;
    bytes[10] = 0x00;
    bytes[11] = 0xEB; // A: jmp 0x1020
    bytes[12] = 0x13;
    bytes[0x20] = 0x48; // B @0x1020: dec rcx
    bytes[0x21] = 0xFF;
    bytes[0x22] = 0xC9;
    bytes[0x23] = 0x75; // B: jnz 0x1000
    bytes[0x24] = 0xDB;
    const auto verdict = scan_bytes(0x1000, bytes, {0x1000, 0x1020});
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kSelfWrite);
}

TEST(NativeGateTest, UnresolvedIndirectStoreNotSelfWrite)
{
    // add [rcx], rax inside the loop: indirect store target - the static
    // half cannot resolve it (the probe's journal cross-check owns that).
    const std::vector<std::uint8_t> bytes = {0x48, 0x01, 0x01, 0x48, 0xFF, 0xC9, 0x75, 0xF8};
    const auto verdict = scan_bytes(0x1000, bytes, {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kAdmitZeroWrite);
}

TEST(NativeGateTest, TruncatedInstructionRejected)
{
    const auto verdict = scan_bytes(0x1000, {0x0F}, {0x1000}); // incomplete opcode
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kDecodeFailure);
}

TEST(NativeGateTest, UnreadableBytesRejected)
{
    const auto verdict = scan_bytes(0x1000, {}, {0x1000}); // no bytes at all
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kDecodeFailure);
}

TEST(NativeGateTest, TerminatorlessRunOverBudgetRejected)
{
    // A nop sled longer than the scan budget: no terminator, no admit.
    const auto verdict = scan_bytes(0x1000, std::vector<std::uint8_t>(1024, 0x90), {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kDecodeFailure);
}

TEST(NativeGateTest, GarbageStreamNeverAdmitted)
{
    // 0x00 bytes decode as add [rax], al - runs forever without a
    // terminator, so the budget ends it as a decode failure, not an admit.
    const auto verdict = scan_bytes(0x1000, std::vector<std::uint8_t>(1024, 0x00), {0x1000});
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kDecodeFailure);
}

TEST(NativeGateTest, DegenerateInputsRejected)
{
    FlatMemory memory(0x1000, dec_jnz_bytes());
    const auto empty = scan(nullptr, 0, MachineMode::kX64, &FlatMemory::read, &memory);
    EXPECT_EQ(empty.reason, RejectReason::kDecodeFailure);
    const auto no_reader = scan(nullptr, 0, MachineMode::kX64, nullptr, &memory);
    EXPECT_EQ(no_reader.reason, RejectReason::kDecodeFailure);
}

TEST(NativeGateTest, X86ModeStillClassifies)
{
    // 32-bit decoding works; the same syscall encoding rejects there too.
    const auto verdict = scan_bytes(0x1000, {0x0F, 0x05}, {0x1000}, MachineMode::kX86);
    EXPECT_EQ(verdict.category, Verdict::kReject);
    EXPECT_EQ(verdict.reason, RejectReason::kSyscall);
}

TEST(NativeGateTest, LedgerSlotMappingIsStable)
{
    // The state counter array is indexed by these slots - append-only ABI.
    GateVerdict admit{};
    admit.category = Verdict::kAdmitZeroWrite;
    EXPECT_EQ(verdict_slot(admit), kAdmitZeroWriteSlot);
    admit.category = Verdict::kAdmitCompute;
    EXPECT_EQ(verdict_slot(admit), kAdmitComputeSlot);
    GateVerdict reject{};
    reject.reason = RejectReason::kDecodeFailure;
    const auto slot = verdict_slot(reject);
    EXPECT_GE(slot, kRejectSlotBase);
    EXPECT_LT(slot, kVerdictSlotCount);
    EXPECT_EQ(reason_for_slot(slot), RejectReason::kDecodeFailure);
}
