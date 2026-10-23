// UNWIND_CODE prolog accounting unit tests: each opcode's
// rsp effect is pinned against winnt.h semantics - the walk's establisher
// and return-address placement are only as correct as this table.
//
// UNWIND_CODE encoding: byte0 = CodeOffset, byte1 = (OpInfo << 4) | Op.

#include "seh_dispatcher.h"

#include <unicorn/unicorn.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace {

constexpr std::uint64_t kInfoBase = 0x500000; // scratch page for the blobs

class SehDispatcherTest : public ::testing::Test {
  protected:
    void SetUp() override
    {
        uc_open(UC_ARCH_X86, UC_MODE_64, &uc_);
        uc_mem_map(uc_, kInfoBase, 0x1000, UC_PROT_ALL);
    }
    void TearDown() override
    {
        uc_close(uc_);
    }
    // Writes `codes` (2 bytes each, one UNWIND_CODE) and calls the
    // accountant with rip_offset.
    std::uint64_t total_for(const std::vector<std::uint8_t>& codes, std::uint32_t rip_offset,
                            bool& ok)
    {
        std::vector<std::uint8_t> blob(0x40, 0);
        // header: version 1, no flags; prolog; count; frame 0
        blob[0] = 0x01;
        blob[1] = 0x00;
        blob[2] = static_cast<std::uint8_t>(codes.size() / 2);
        blob[3] = 0x00;
        for (std::size_t i = 0; i < codes.size(); ++i) {
            blob[4 + i] = codes[i];
        }
        uc_mem_write(uc_, kInfoBase, blob.data(), blob.size());
        std::uint64_t total = 0;
        ok = sheller::engine::seh::prolog_total(uc_, kInfoBase, blob[2], rip_offset, total);
        return total;
    }
    uc_engine* uc_ = nullptr;
};

TEST_F(SehDispatcherTest, PushNonvol)
{
    bool ok = true;
    // push rbx: byte1 = (0 << 4) | 3, rsp effect +8
    EXPECT_EQ(total_for({0x04, 0x30}, 0x10, ok), 8U);
    EXPECT_TRUE(ok);
}

TEST_F(SehDispatcherTest, AllocSmallAndLarge)
{
    bool ok = true;
    // alloc_small op_info=1: (1+1)*8 = 16
    EXPECT_EQ(total_for({0x05, 0x12}, 0x10, ok), 16U);
    // alloc_large info=0: next slot 0x20 * 8 = 256
    EXPECT_EQ(total_for({0x05, 0x01, 0x20, 0x00}, 0x10, ok), 256U);
    // alloc_large info=1: next two slots as u32 = 0x100
    EXPECT_EQ(total_for({0x05, 0x11, 0x00, 0x01}, 0x10, ok), 0x100U);
    EXPECT_TRUE(ok);
}

TEST_F(SehDispatcherTest, SaveOpsDoNotMoveRsp)
{
    bool ok = true;
    // save_nonvol rbx @2; save_xmm128 xmm5 @4; save_nonvol_far rsi @0x10;
    // save_xmm128_far xmm7 @0x20 - savings never move rsp
    const std::uint64_t total =
        total_for({0x06, 0x34, 0x02, 0x00, 0x08, 0x58, 0x04, 0x00, 0x09, 0x65,
                   0x10, 0x00, 0x00, 0x00, 0x0A, 0x79, 0x20, 0x00, 0x00, 0x00},
                  0x40, ok);
    EXPECT_EQ(total, 0U);
    EXPECT_TRUE(ok);
}

TEST_F(SehDispatcherTest, PushMachframe)
{
    bool ok = true;
    // machframe without error code: 0x28
    EXPECT_EQ(total_for({0x04, 0x0A}, 0x10, ok), 0x28U);
    // with error code (op_info=1): 0x30
    EXPECT_EQ(total_for({0x04, 0x1A}, 0x10, ok), 0x30U);
    EXPECT_TRUE(ok);
}

TEST_F(SehDispatcherTest, RipOffsetGatesUnexecutedCodes)
{
    bool ok = true;
    // two pushes; the second's code offset (0x20) is past the rip offset
    // (0x10): only the first push counts
    EXPECT_EQ(total_for({0x02, 0x30, 0x20, 0x30}, 0x10, ok), 8U);
    EXPECT_TRUE(ok);
    // at rip offset 0x20 both count
    EXPECT_EQ(total_for({0x02, 0x30, 0x20, 0x30}, 0x20, ok), 16U);
}

TEST_F(SehDispatcherTest, MixedProlog)
{
    bool ok = true;
    // push rbp (slot 1) + alloc_small 16 (slot 2) + save_nonvol rsi @0
    // (slots 3-4: code + operand): 8 + 16 + 0
    const std::uint64_t total =
        total_for({0x00, 0x50, 0x08, 0x12, 0x06, 0x64, 0x00, 0x00}, 0x30, ok);
    EXPECT_EQ(total, 24U);
    EXPECT_TRUE(ok);
}

// The nonvolatile recovery - the engine-side parity of
// RtlUnwindEx's virtual unwind - reads the callee-saved values the executed
// prolog codes stored into the frame.
TEST_F(SehDispatcherTest, NonvolatileFrameRecoversSavedRegisters)
{
    // prolog: push rbx (op 0, info 3) then save_nonvol rsi @0x18 (op 4,
    // info 6, operand slot 0x18/8=3). Entry rsp = establisher + total(0x20).
    std::vector<std::uint8_t> blob(0x40, 0);
    blob[0] = 0x01; // version 1, no flags
    blob[1] = 0x00;
    blob[2] = 0x03; // three slots: push, code, operand
    blob[3] = 0x00;
    blob[4] = 0x02; // push rbx @ offset 0x02
    blob[5] = 0x30;
    blob[6] = 0x06; // save rsi @0x28, offset 0x06
    blob[7] = 0x64; // (op_info 6 << 4) | op 4 = UWOP_SAVE_NONVOL rsi
    blob[8] = 0x05; // slot operand: index 5 (byte offset 0x28 = 5 * 8)
    blob[9] = 0x00;
    uc_mem_write(uc_, kInfoBase, blob.data(), blob.size());

    const std::uint64_t establisher = kInfoBase + 0x800;
    const std::uint64_t total = 0x20;
    // the pushed rbx sits just below the entry rsp; the saved rsi at
    // establisher + 0x28
    const std::uint64_t rbx_value = 0x1111222233334444ULL;
    const std::uint64_t rsi_value = 0x5555666677778888ULL;
    uc_mem_write(uc_, establisher + total - 8, &rbx_value, sizeof rbx_value);
    uc_mem_write(uc_, establisher + 0x28, &rsi_value, sizeof rsi_value);

    sheller::engine::seh::NonvolatileFrame nv;
    ASSERT_TRUE(
        sheller::engine::seh::nonvolatile_frame(uc_, kInfoBase, 3, 0x10, establisher, total, nv));
    ASSERT_TRUE(nv.gpr_valid.at(3)); // rbx
    EXPECT_EQ(nv.gpr.at(3), rbx_value);
    ASSERT_TRUE(nv.gpr_valid.at(6)); // rsi
    EXPECT_EQ(nv.gpr.at(6), rsi_value);
    EXPECT_FALSE(nv.gpr_valid.at(4)); // untouched registers stay unclaimed
}

// Malformed unwind data: the indices the walk takes out of its register
// tables come from guest bytes (UNWIND_CODE.OpInfo, UNWIND_INFO.FrameRegister),
// so a hostile directory is the input class to probe. The engine's answer must
// be the failure channel the code already has - a false return, an unclaimed
// slot - and never an escaping exception, because an engine frame carries no
// exception mechanism (tests/engine_nothrow_gate.cmake) and the export layer
// would otherwise be reading a library-internal error off a sample's bad data.
// These cases pin the range closure the .at() audit claims: the widest index a
// guest can name is the last slot of the table, and everything outside the
// mapped page fails soft.
TEST_F(SehDispatcherTest, WidestGuestNamedIndexLandsInTheTable)
{
    // Three executed codes, each naming the highest register the 4-bit field
    // can express: PUSH_NONVOL r15 (op 0, info 15), SET_FPREG with
    // FrameRegister = 15 (header byte 3: offset units 15 << 4 | 15), and
    // SAVE_XMM128 xmm15 (op 8, info 15). Every store target sits outside the
    // mapped page, so each read must fail and leave its slot unclaimed.
    std::vector<std::uint8_t> blob(0x40, 0);
    blob[0] = 0x01;
    blob[1] = 0x00;
    blob[2] = 0x04; // push, fpreg code, save code, operand
    blob[3] = 0xFF; // FrameRegister 15, FrameOffsetUnits 15
    blob[4] = 0x01;
    blob[5] = 0xF0; // (info 15 << 4) | op 0  = UWOP_PUSH_NONVOL r15
    blob[6] = 0x02;
    blob[7] = 0x03; // (info 0 << 4) | op 3   = UWOP_SET_FPREG
    blob[8] = 0x03;
    blob[9] = 0xF8; // (info 15 << 4) | op 8  = UWOP_SAVE_XMM128 xmm15
    blob[10] = 0x01;
    blob[11] = 0x00;
    uc_mem_write(uc_, kInfoBase, blob.data(), blob.size());

    // Nothing is mapped at the frame the codes point into: establisher + total
    // sits a page past the scratch region.
    const std::uint64_t unmapped = kInfoBase + 0x8000;
    sheller::engine::seh::NonvolatileFrame nv{};
    EXPECT_NO_THROW({
        const bool ok =
            sheller::engine::seh::nonvolatile_frame(uc_, kInfoBase, 4, 0x10, unmapped, 0x20, nv);
        // The directory itself parsed; the reads are what fail.
        EXPECT_TRUE(ok);
    });
    EXPECT_EQ(nv.gpr_valid.size(), 16U);
    EXPECT_FALSE(nv.gpr_valid.at(15)) << "the widest guest-named GPR slot must stay unclaimed";
    EXPECT_FALSE(nv.xmm_valid.at(15)) << "the widest guest-named XMM slot must stay unclaimed";
    // And the accounting path takes the same input without throwing.
    std::uint64_t total = 0;
    EXPECT_NO_THROW(
        { EXPECT_TRUE(sheller::engine::seh::prolog_total(uc_, kInfoBase, 4, 0x10, total)); });

    // Not vacuous: with the frame inside the mapping the very same directory
    // claims its slot 15 - so the unclaimed result above is about the failed
    // read, and index 15 is a usable slot rather than a dead one. The GPR slot
    // stays unclaimed here either way (UWOP_SET_FPREG runs after the push and
    // its FrameOffsetUnits 15 * 16 points below the frame), so the claim is
    // shown through the XMM save, whose operand slot 1 resolves inside the page.
    const std::uint64_t mapped = kInfoBase + 0x800;
    sheller::engine::seh::NonvolatileFrame claimed{};
    ASSERT_TRUE(
        sheller::engine::seh::nonvolatile_frame(uc_, kInfoBase, 4, 0x10, mapped, 0x20, claimed));
    ASSERT_TRUE(claimed.xmm_valid.at(15));
}

TEST_F(SehDispatcherTest, CountOfCodesPastTheMappedPageFailsSoft)
{
    // A header at the edge of the mapped page claiming 255 code slots: the code
    // array runs off the mapping, and "could not read" is the engine's
    // malformed-data signal - a false return, not an exception.
    const std::uint64_t edge = kInfoBase + 0xFE0;
    std::array<std::uint8_t, 4> header{0x01, 0x00, 0xFF, 0x00};
    uc_mem_write(uc_, edge, header.data(), header.size());

    sheller::engine::seh::NonvolatileFrame nv{};
    EXPECT_NO_THROW({
        EXPECT_FALSE(sheller::engine::seh::nonvolatile_frame(uc_, edge, 0xFF, 0x100, edge + 0x800,
                                                             0x20, nv));
    });
    std::uint64_t total = 0;
    EXPECT_NO_THROW(
        { EXPECT_FALSE(sheller::engine::seh::prolog_total(uc_, edge, 0xFF, 0x100, total)); });
}

TEST_F(SehDispatcherTest, HandlerRvaPastTheMappingFailsSoft)
{
    // UNWIND_INFO with the ExceptionHandler present (flag 0x1) whose handler
    // slot sits past the mapping: the parse cannot complete, and the walk is
    // told so through the false return rather than by throwing.
    const std::uint64_t edge = kInfoBase + 0xFF8;
    // byte0: version 1 | flags 0x1 shifted up by 3 (UnwHasEHandler)
    std::array<std::uint8_t, 4> header{0x09, 0x00, 0x02, 0x00};
    uc_mem_write(uc_, edge, header.data(), header.size());

    sheller::engine::seh::NonvolatileFrame nv{};
    EXPECT_NO_THROW({
        EXPECT_FALSE(
            sheller::engine::seh::nonvolatile_frame(uc_, edge, 2, 0x10, edge + 0x800, 0x20, nv));
    });
}

// The language-handler classification routes C++ frames by
// the FuncInfo magic in the handler data before any export resolution - the
// /MT shape - and keeps everything else on the scope-table path.
TEST_F(SehDispatcherTest, ClassifyRoutesByFuncInfoSignature)
{
    const sheller::engine::mem_region::MemRegionMap empty_map({}, {});
    // FuncInfo magic (EH_MAGIC_NUMBER family): the first DWORD of a C++
    // frame's handler data
    for (const std::uint32_t magic : {0x19930520U, 0x19930521U, 0x19930522U, 0x19930523U}) {
        const std::uint64_t data = kInfoBase + 0x200;
        uc_mem_write(uc_, data, &magic, sizeof magic);
        EXPECT_EQ(sheller::engine::seh::classify_language_handler(uc_, empty_map, kInfoBase + 0x100,
                                                                  data),
                  sheller::engine::seh::HandlerKind::Cxx)
            << "magic " << std::hex << magic;
    }
    // a scope-table Count (a small integer) never collides with the magic
    // set: the frame keeps the __C_specific_handler semantics
    const std::uint32_t count = 2;
    const std::uint64_t data = kInfoBase + 0x240;
    uc_mem_write(uc_, data, &count, sizeof count);
    EXPECT_EQ(
        sheller::engine::seh::classify_language_handler(uc_, empty_map, kInfoBase + 0x100, data),
        sheller::engine::seh::HandlerKind::ScopeTable);
}

} // namespace
