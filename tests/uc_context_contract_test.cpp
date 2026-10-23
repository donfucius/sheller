// uc_context save/restore contract: the thread scheduler's
// context switching builds on these unicorn behaviors, pinned here so a
// unicorn bump that breaks them surfaces as this test, not as garbled
// guest threads.
//
// Probed findings (unicorn 2.1.4):
// - x64: GPR round-trip through save/restore is exact.
// - x86: GPR round-trip is exact, and the FS selector (hence the GDT
//   descriptor base = TEB view) is part of the restored state — per-thread
//   GDT slots + context swap is a complete TEB switch.

#include <unicorn/unicorn.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <vector>

namespace {

// GDT page with per-thread data descriptors; entry i carries base i-th
// argument. Matches the engine's write_registers_gdt layout (0x92 data RW,
// 0xCF 4K-granular 32-bit).
constexpr std::uint64_t kGdtBase = 0xFFEE0000;
constexpr std::uint16_t kSelectorA = 0x08;
constexpr std::uint16_t kSelectorB = 0x10;

class UcContextContract : public ::testing::Test {
  protected:
    void SetUp() override
    {
        ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_32, &uc_), UC_ERR_OK);
        ASSERT_EQ(uc_mem_map(uc_, kCodeBase, 0x1000, UC_PROT_ALL), UC_ERR_OK);
        ASSERT_EQ(uc_mem_map(uc_, kTebA, 0x1000, UC_PROT_ALL), UC_ERR_OK);
        ASSERT_EQ(uc_mem_map(uc_, kTebB, 0x1000, UC_PROT_ALL), UC_ERR_OK);
        ASSERT_EQ(uc_mem_map(uc_, kGdtBase, 0x1000, UC_PROT_ALL), UC_ERR_OK);

        // each TEB page carries its owner tag at +0x18 (the slot the probe
        // code reads through fs)
        constexpr std::uint32_t kTagA = 0xAAAA0001;
        constexpr std::uint32_t kTagB = 0xBBBB0002;
        ASSERT_EQ(uc_mem_write(uc_, kTebA + 0x18, &kTagA, sizeof kTagA), UC_ERR_OK);
        ASSERT_EQ(uc_mem_write(uc_, kTebB + 0x18, &kTagB, sizeof kTagB), UC_ERR_OK);

        std::array<std::uint8_t, 24> gdt{};
        write_data_desc(gdt.data() + 8, kTebA);
        write_data_desc(gdt.data() + 16, kTebB);
        ASSERT_EQ(uc_mem_write(uc_, kGdtBase, gdt.data(), gdt.size()), UC_ERR_OK);
        uc_x86_mmr gdtr{};
        gdtr.base = kGdtBase;
        gdtr.limit = 0xFFF;
        ASSERT_EQ(uc_reg_write(uc_, UC_X86_REG_GDTR, &gdtr), UC_ERR_OK);
    }

    void TearDown() override
    {
        for (uc_context* ctx : contexts_) {
            uc_context_free(ctx);
        }
        uc_close(uc_);
    }

    static void write_data_desc(std::uint8_t* at, const std::uint64_t base)
    {
        at[0] = 0xFF;
        at[1] = 0xFF;
        at[2] = static_cast<std::uint8_t>(base & 0xFF);
        at[3] = static_cast<std::uint8_t>((base >> 8) & 0xFF);
        at[4] = static_cast<std::uint8_t>((base >> 16) & 0xFF);
        at[5] = 0x92; // data segment, writable, present
        at[6] = 0xCF; // 4K granularity, 32-bit (B), limit high 0xF
        at[7] = static_cast<std::uint8_t>((base >> 24) & 0xFF);
    }

    uc_context* alloc_and_save()
    {
        uc_context* ctx = nullptr;
        EXPECT_EQ(uc_context_alloc(uc_, &ctx), UC_ERR_OK);
        contexts_.push_back(ctx);
        EXPECT_EQ(uc_context_save(uc_, ctx), UC_ERR_OK);
        return ctx;
    }

    std::uint32_t run_fs_read_and_read_eax()
    {
        // mov eax, fs:[18h]; nop — the TEB self-ish tag slot this probe pins
        const std::array<std::uint8_t, 7> code = {0x64, 0xA1, 0x18, 0x00, 0x00, 0x00, 0x90};
        EXPECT_EQ(uc_mem_write(uc_, kCodeBase, code.data(), code.size()), UC_ERR_OK);
        const uc_err err = uc_emu_start(uc_, kCodeBase, kCodeBase + 6, 0, 4); // stop at the nop
        EXPECT_EQ(err, UC_ERR_OK) << uc_strerror(err);
        std::uint32_t eax = 0;
        uc_reg_read(uc_, UC_X86_REG_EAX, &eax);
        return eax;
    }

    uc_engine* uc_{nullptr};
    std::vector<uc_context*> contexts_;

    static constexpr std::uint64_t kCodeBase = 0x400000;
    static constexpr std::uint64_t kTebA = 0x2000000;
    static constexpr std::uint64_t kTebB = 0x2001000;
};

TEST_F(UcContextContract, X64GprRoundTripIsExact)
{
    uc_close(uc_);
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc_), UC_ERR_OK);
    ASSERT_EQ(uc_mem_map(uc_, kCodeBase, 0x1000, UC_PROT_ALL), UC_ERR_OK);

    const std::uint64_t rsp_a = 0x1aff78;
    uc_reg_write(uc_, UC_X86_REG_RSP, &rsp_a);
    uc_context* ctx = alloc_and_save();

    const std::uint64_t rsp_b = 0x222000;
    const std::uint64_t rax_b = 0xDEADBEEF;
    uc_reg_write(uc_, UC_X86_REG_RSP, &rsp_b);
    uc_reg_write(uc_, UC_X86_REG_RAX, &rax_b);

    ASSERT_EQ(uc_context_restore(uc_, ctx), UC_ERR_OK);
    std::uint64_t rsp = 0, rax = 0;
    uc_reg_read(uc_, UC_X86_REG_RSP, &rsp);
    uc_reg_read(uc_, UC_X86_REG_RAX, &rax);
    EXPECT_EQ(rsp, rsp_a);
    EXPECT_EQ(rax, 0U);
}

TEST_F(UcContextContract, X86RestoreSwapsTebView)
{
    // thread A state: FS -> TEB A, its own stack
    uc_reg_write(uc_, UC_X86_REG_FS, &kSelectorA);
    const std::uint64_t rsp_a = 0x7FF00;
    uc_reg_write(uc_, UC_X86_REG_ESP, &rsp_a);
    uc_context* ctx_a = alloc_and_save();

    // thread B state: FS -> TEB B, a different stack
    uc_reg_write(uc_, UC_X86_REG_FS, &kSelectorB);
    const std::uint64_t rsp_b = 0x7FE00;
    uc_reg_write(uc_, UC_X86_REG_ESP, &rsp_b);
    uc_context* ctx_b = alloc_and_save();

    // restore A: the TEB view (FS descriptor base) and stack come back
    ASSERT_EQ(uc_context_restore(uc_, ctx_a), UC_ERR_OK);
    std::uint32_t esp = 0;
    uc_reg_read(uc_, UC_X86_REG_ESP, &esp);
    EXPECT_EQ(esp, rsp_a);
    EXPECT_EQ(run_fs_read_and_read_eax(), 0xAAAA0001U);

    // restore B: the same swap works for the other thread
    ASSERT_EQ(uc_context_restore(uc_, ctx_b), UC_ERR_OK);
    uc_reg_read(uc_, UC_X86_REG_ESP, &esp);
    EXPECT_EQ(esp, rsp_b);
    EXPECT_EQ(run_fs_read_and_read_eax(), 0xBBBB0002U);
}

} // namespace
