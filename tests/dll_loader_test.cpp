#include "dll_loader.h"
#include "write_ledger.h"
#include <cstring>
#include <gtest/gtest.h>
#include <sheller/snapshot.h>

namespace {
constexpr std::uint64_t kBase = 0x180000000;
constexpr std::uint64_t kNode = 0x7F0000000000ULL - 0x100000;
constexpr std::uint64_t kLdr = 0x2002000;

class DllLoadTransaction : public testing::Test {
  protected:
    void SetUp() override
    {
        ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc), UC_ERR_OK);
        ASSERT_EQ(uc_mem_map(uc, 0x1000000, 0x10000, UC_PROT_ALL), UC_ERR_OK);
        ASSERT_EQ(uc_mem_map(uc, 0x2000000, 0x4000, UC_PROT_ALL), UC_ERR_OK);
        put(0x2000060, 0x2001000);
        put(0x2001018, kLdr);
        for (std::uint64_t head : {kLdr + 0x10, kLdr + 0x20, kLdr + 0x30}) {
            put(head, head);
            put(head + 8, head);
        }
        pending.name = "fixture.dll";
        pending.bitness = 64;
        pending.bytes.resize(0x2000);
        const auto w16 = [&](std::size_t p, std::uint16_t v) {
            std::memcpy(pending.bytes.data() + p, &v, 2);
        };
        const auto w32 = [&](std::size_t p, std::uint32_t v) {
            std::memcpy(pending.bytes.data() + p, &v, 4);
        };
        const auto w64 = [&](std::size_t p, std::uint64_t v) {
            std::memcpy(pending.bytes.data() + p, &v, 8);
        };
        w16(0, 0x5A4D);
        w32(0x3C, 0x40);
        w32(0x40, 0x4550);
        w16(0x44, 0x8664);
        w16(0x46, 1);
        w16(0x54, 0xF0);
        w16(0x56, 0x2022);
        w16(0x58, 0x20B);
        w32(0x68, 0x1000);
        w64(0x70, kBase);
        w32(0x78, 0x1000);
        w32(0x90, 0x2000);
        w32(0x94, 0x400);
        w32(0xC4, 16);
        w32(0x150, 0x1000);
        w32(0x154, 0x1000);
        w32(0x158, 0x1000);
        w32(0x15C, 0x1000);
        w32(0x16C, 0x60000020);
        state.uc = uc;
        state.teb_base = 0x2000000;
        state.pending_module = &pending;
        state.write_ledger = &ledger;
        state.sample_module_known = true;
        state.sample_module_index = 7;
        state.dll_load.call_base_rsp = 0x1008000;
        state.dll_load.caller_rsp = 0x1008000;
        state.dll_load.caller_rip = 0x401011;
        state.dll_resume_slot = sheller::engine::kDllResumeSlotVa;
    }
    void TearDown() override
    {
        if (uc != nullptr) {
            uc_close(uc);
        }
    }
    void put(std::uint64_t a, std::uint64_t v)
    {
        ASSERT_EQ(uc_mem_write(uc, a, &v, 8), UC_ERR_OK);
    }
    std::uint64_t get(std::uint64_t a)
    {
        std::uint64_t v{};
        EXPECT_EQ(uc_mem_read(uc, a, &v, 8), UC_ERR_OK);
        return v;
    }
    void configure_tls(std::uint32_t array_rva, std::size_t count)
    {
        const std::uint32_t directory_rva = 0x1100;
        const std::uint32_t directory_size = 40;
        std::memcpy(pending.bytes.data() + 0x110, &directory_rva, 4);
        std::memcpy(pending.bytes.data() + 0x114, &directory_size, 4);
        const auto array_va = kBase + array_rva;
        std::memcpy(pending.bytes.data() + directory_rva + 0x18, &array_va, 8);
        for (std::size_t i = 0; i < count; ++i) {
            const auto callback = kBase + 0x1000;
            std::memcpy(pending.bytes.data() + array_rva + i * 8, &callback, 8);
        }
    }
    uc_engine* uc{};
    sheller::snapshot::PendingModule pending;
    sheller::engine::MemWriteLedger ledger{{}, 0x400000, 0x1000};
    sheller::engine::SyscallRunState state;
};

TEST_F(DllLoadTransaction, OccupiedNodePageSurvivesConstructionFailure)
{
    ASSERT_EQ(uc_mem_map(uc, kNode, 0x1000, UC_PROT_ALL), UC_ERR_OK);
    put(kNode, 0x2003000);
    put(kNode + 8, 0x2003010);
    put(0x2003008, 0x1234);
    put(0x2003010, 0x5678);
    const auto failure = sheller::engine::synthesize_pending_load(state);
    ASSERT_TRUE(failure.has_value());
    EXPECT_NE(failure->find("Ldr node page"), std::string::npos);
    EXPECT_EQ(get(kNode), 0x2003000U);
    EXPECT_EQ(get(0x2003008), 0x1234U);
    EXPECT_EQ(get(0x2003010), 0x5678U);
    EXPECT_EQ(ledger.region_count(), 0U);
    EXPECT_EQ(ledger.sample_span(), (std::pair<std::uint64_t, std::uint64_t>{0x400000, 0x1000}));
    EXPECT_TRUE(state.sample_module_known);
    EXPECT_EQ(state.sample_module_index, 7U);
}

TEST_F(DllLoadTransaction, UnterminatedTlsArrayRollsBackBeforeScheduling)
{
    configure_tls(0x1FF0, 2);
    const auto failure = sheller::engine::synthesize_pending_load(state);
    ASSERT_TRUE(failure.has_value());
    EXPECT_NE(failure->find("missing terminator"), std::string::npos);
    EXPECT_FALSE(state.dll_load.active);
    EXPECT_TRUE(state.loader_modules.empty());
    EXPECT_TRUE(state.loader_exports.empty());
    EXPECT_EQ(ledger.region_count(), 0U);
    EXPECT_EQ(state.sample_module_index, 7U);
    for (std::uint64_t head : {kLdr + 0x10, kLdr + 0x20, kLdr + 0x30}) {
        EXPECT_EQ(get(head), head);
        EXPECT_EQ(get(head + 8), head);
    }
    std::uint8_t byte{};
    EXPECT_EQ(uc_mem_read(uc, kBase, &byte, 1), UC_ERR_READ_UNMAPPED);
    EXPECT_EQ(uc_mem_read(uc, kNode, &byte, 1), UC_ERR_READ_UNMAPPED);
}

TEST_F(DllLoadTransaction, TlsArrayBeyondCallbackLimitIsRejected)
{
    configure_tls(0x1800, 65);
    const auto failure = sheller::engine::synthesize_pending_load(state);
    ASSERT_TRUE(failure.has_value());
    EXPECT_NE(failure->find("limit exceeded"), std::string::npos);
    EXPECT_FALSE(state.dll_load.active);
    EXPECT_EQ(ledger.region_count(), 0U);
}

TEST_F(DllLoadTransaction, TerminatedTlsArrayAtCallbackLimitIsAccepted)
{
    configure_tls(0x1800, 64);
    ASSERT_FALSE(sheller::engine::synthesize_pending_load(state).has_value());
    EXPECT_EQ(state.dll_load.tls_pending.size(), 64U);
    EXPECT_EQ(state.dll_load.tls_cursor, 1U);
}

TEST_F(DllLoadTransaction, PartialLinkFailureRestoresPreviouslyLinkedHead)
{
    put(kLdr + 0x20, 0);
    ASSERT_TRUE(sheller::engine::synthesize_pending_load(state).has_value());
    EXPECT_EQ(get(kLdr + 0x10), kLdr + 0x10);
    EXPECT_EQ(get(kLdr + 0x18), kLdr + 0x10);
    EXPECT_EQ(get(kLdr + 0x20), 0U);
    EXPECT_EQ(ledger.region_count(), 0U);
}

TEST_F(DllLoadTransaction, DllMainFalseDropsDirtyImageAndAllowsRetry)
{
    ASSERT_FALSE(sheller::engine::synthesize_pending_load(state).has_value());
    ledger.on_write(kBase + 0x1000, 1);
    std::uint64_t result = 0;
    ASSERT_EQ(uc_reg_write(uc, UC_X86_REG_RAX, &result), UC_ERR_OK);
    sheller::engine::dll_load_resume(state);
    EXPECT_EQ(ledger.region_count(), 0U);
    EXPECT_TRUE(ledger.dirty_region_indices().empty());
    EXPECT_EQ(get(kLdr + 0x10), kLdr + 0x10);
    std::uint8_t byte{};
    EXPECT_EQ(uc_mem_read(uc, kBase, &byte, 1), UC_ERR_READ_UNMAPPED);
    EXPECT_EQ(uc_mem_read(uc, kNode, &byte, 1), UC_ERR_READ_UNMAPPED);
    state.dll_load.call_base_rsp = 0x1008000;
    ASSERT_FALSE(sheller::engine::synthesize_pending_load(state).has_value());
}

TEST_F(DllLoadTransaction, RuntimeModuleNotificationFollowsFalseRetryAndRebase)
{
    sheller::engine::mem_region::MemRegionMap map{{}, {}};
    state.region_map = &map;
    std::vector<std::size_t> indexes;
    std::vector<std::uint64_t> bases;
    state.module_sink = [&](std::size_t index,
                            const sheller::engine::mem_region::ModuleImage& image) {
        indexes.push_back(index);
        bases.push_back(image.module.base);
        EXPECT_STREQ(image.module.name.data(), "fixture.dll");
        EXPECT_EQ(map.module(index).base, image.module.base);
        EXPECT_FALSE(image.header_bytes.empty());
    };
    ASSERT_FALSE(sheller::engine::synthesize_pending_load(state).has_value());
    ASSERT_EQ(indexes.size(), 1U);
    EXPECT_EQ(indexes[0], state.dll_load.module_index);
    EXPECT_EQ(bases[0], kBase);
    const std::uint64_t failed = 0;
    ASSERT_EQ(uc_reg_write(uc, UC_X86_REG_RAX, &failed), UC_ERR_OK);
    sheller::engine::dll_load_resume(state);
    // Keep the preferred base occupied on the retry. Notification must
    // report its new index and actual placement, not a predicted slot/base.
    ASSERT_EQ(uc_mem_map(uc, kBase, 0x2000, UC_PROT_ALL), UC_ERR_OK);
    state.dll_load.call_base_rsp = 0x1008000;
    ASSERT_FALSE(sheller::engine::synthesize_pending_load(state).has_value());
    ASSERT_EQ(indexes.size(), 2U);
    EXPECT_NE(indexes[0], indexes[1]);
    EXPECT_EQ(indexes[1], state.dll_load.module_index);
    EXPECT_EQ(bases[1], state.dll_load.base);
    EXPECT_NE(bases[1], kBase);
}

} // namespace
