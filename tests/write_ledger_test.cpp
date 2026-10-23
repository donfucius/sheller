// Write ledger + raw region dump tests: page-granular dirty
// tracking, per-region summaries, and the original-bytes export (one
// .bin per written region plus the manifest). Portable: uc works on
// every platform.

#include "dump_writer.h"
#include "write_ledger.h"

#include <unicorn/unicorn.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {

namespace mem = sheller::engine;
namespace mem_region = sheller::engine::mem_region;

std::vector<mem_region::RegionRecord> tracked_regions()
{
    return {{0x1000, 0x2000, 0x4, 0x20000},
            {0x400000, 0x1000, 0x20, 0x400000},
            {0x40000000, 0x3000, 0x40, 0x20000}};
}

std::string hex16(std::uint64_t value)
{
    char buf[17] = {};
    std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(value));
    return buf;
}

TEST(WriteLedger, MarksPagesAndFirstWrite)
{
    const auto regions = tracked_regions();
    mem::MemWriteLedger ledger(regions);
    ledger.on_write(0x1000 + 0x1800, 4);

    const auto& region = ledger.region(0);
    EXPECT_TRUE(region.written);
    EXPECT_EQ(region.dirty_pages, 1U);
    EXPECT_EQ(region.first_dirty_page, 0x1000U + 0x1000U); // second page
}

TEST(WriteLedger, TracksPagesAcrossRegion)
{
    const auto regions = tracked_regions();
    mem::MemWriteLedger ledger(regions);
    ledger.on_write(0x1000 + 0xFFE, 8); // spans the page boundary

    const auto& region = ledger.region(0);
    EXPECT_EQ(region.dirty_pages, 2U);
    EXPECT_EQ(region.first_dirty_page, 0x1000U);
}

TEST(WriteLedger, IgnoresWritesOutsideTrackedRegions)
{
    mem::MemWriteLedger ledger(tracked_regions());
    ledger.on_write(0x50000000, 8); // in a gap between regions
    EXPECT_EQ(ledger.dirty_region_indices().size(), 0U);
}

TEST(WriteLedger, DirtyRegionIndicesInBaseOrder)
{
    mem::MemWriteLedger ledger(tracked_regions());
    ledger.on_write(0x40000000, 4);
    ledger.on_write(0x1000, 4);
    const auto indices = ledger.dirty_region_indices();
    ASSERT_EQ(indices.size(), 2U);
    EXPECT_EQ(indices[0], 0U);
    EXPECT_EQ(indices[1], 2U);
}

TEST(WriteLedger, AddedRegionJoinsTracking)
{
    mem::MemWriteLedger ledger(tracked_regions());
    // Guest-run allocation between the existing regions: base order holds
    // and the on_write binary search finds the inserted record.
    ledger.add_region(0x3000, 0x2000, 0x04, mem::kMemPrivate);
    ASSERT_EQ(ledger.region_count(), 4U);

    ledger.on_write(0x3000 + 0x100, 4);
    const auto indices = ledger.dirty_region_indices();
    ASSERT_EQ(indices.size(), 1U);
    const auto& region = ledger.region(indices[0]);
    EXPECT_EQ(region.base, 0x3000U);
    EXPECT_TRUE(region.written);
    EXPECT_EQ(region.first_dirty_page, 0x3000U);

    // The pre-existing regions still resolve through the re-sorted vector.
    ledger.on_write(0x1000, 4);
    EXPECT_EQ(ledger.dirty_region_indices().size(), 2U);
}

class DumpWriterEnv : public testing::Test {
  protected:
    void SetUp() override
    {
        ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc_), UC_ERR_OK);
        ASSERT_EQ(uc_mem_map(uc_, 0x40000000, 0x3000, UC_PROT_ALL), UC_ERR_OK);
        const std::uint8_t payload[] = {0xDE, 0xAD, 0xBE, 0xEF};
        std::vector<std::uint8_t> bytes(0x3000, 0);
        std::memcpy(bytes.data() + 0x100, payload, sizeof payload);
        ASSERT_EQ(uc_mem_write(uc_, 0x40000000, bytes.data(), bytes.size()), UC_ERR_OK);
    }

    void TearDown() override
    {
        if (uc_ != nullptr) {
            uc_close(uc_);
        }
    }

    uc_engine* uc_ = nullptr;
};

TEST_F(DumpWriterEnv, ExportsOriginalBytesAndManifest)
{
    const std::filesystem::path dir = testing::TempDir() + "dump_writer_ok";
    std::filesystem::remove_all(dir);

    std::vector<mem_region::RegionRecord> regions{{0x40000000, 0x3000, 0x40, 0x20000}};
    mem::MemWriteLedger ledger(regions);
    ledger.on_write(0x40000000 + 0x100, 4);
    ASSERT_TRUE(sheller::engine::write_dump(dir, ledger, uc_));

    const std::filesystem::path bin_path = dir / (hex16(0x40000000) + ".bin");
    std::ifstream bin(bin_path, std::ios::binary);
    ASSERT_TRUE(bin) << bin_path;
    std::vector<char> bytes(0x3000);
    bin.read(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    EXPECT_EQ(bytes[0x100], static_cast<char>(0xDE));
    EXPECT_EQ(bytes[0x103], static_cast<char>(0xEF));

    // Manifest line: five fixed-width hex fields - base, size, type,
    // protection, first dirty PAGE address.
    std::ifstream manifest(dir / "manifest.txt");
    ASSERT_TRUE(manifest);
    std::string line;
    ASSERT_TRUE(static_cast<bool>(std::getline(manifest, line)));
    EXPECT_EQ(line, hex16(0x40000000) + " " + hex16(0x3000) + " " + hex16(0x20000) + " " +
                        hex16(0x40) + " " + hex16(0x40000000));
}

TEST_F(DumpWriterEnv, DeterministicAcrossRuns)
{
    const std::filesystem::path dir_a = testing::TempDir() + "dump_writer_det_a";
    const std::filesystem::path dir_b = testing::TempDir() + "dump_writer_det_b";
    std::filesystem::remove_all(dir_a);
    std::filesystem::remove_all(dir_b);

    std::vector<mem_region::RegionRecord> regions{{0x40000000, 0x3000, 0x40, 0x20000}};
    mem::MemWriteLedger ledger(regions);
    ledger.on_write(0x40000000 + 0x100, 4);

    ASSERT_TRUE(sheller::engine::write_dump(dir_a, ledger, uc_));
    ASSERT_TRUE(sheller::engine::write_dump(dir_b, ledger, uc_));

    std::ifstream manifest_a(dir_a / "manifest.txt");
    std::ifstream manifest_b(dir_b / "manifest.txt");
    const std::string ma((std::istreambuf_iterator<char>(manifest_a)),
                         std::istreambuf_iterator<char>());
    const std::string mb((std::istreambuf_iterator<char>(manifest_b)),
                         std::istreambuf_iterator<char>());
    EXPECT_EQ(ma, mb);
}

} // namespace
