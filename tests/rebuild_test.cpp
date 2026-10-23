// Rebuild tests: synthetic page-aligned snapshots prove the rebuild and the
// entry-reach judgement on every platform (the serialized
// format is the review seam, so the engine side is tested far from the
// Windows capture path); on Windows a real capture of the compiled sample
// closes the loop end to end.

#include "capture_detail.h"
#include "rebuild_probe.h"

#include <sheller/rebuild.h>
#include <sheller/snapshot.h>

#include <gtest/gtest.h>

#ifdef _WIN32
#include <sheller/capture.h>

#include <string>
#endif

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace snapshot = sheller::snapshot;
namespace fs = std::filesystem;

// Win32 protection/type ABI numbers as captured into snapshots (the engine
// maps them to UC_PROT_*; here they only feed the fixture).
constexpr std::uint32_t kPageNoaccess = 0x01;
constexpr std::uint32_t kPageReadwrite = 0x04;
constexpr std::uint32_t kPageExecuteReadwrite = 0x40;
constexpr std::uint32_t kMemImage = 0x1000000;
constexpr std::uint32_t kMemPrivate = 0x20000;

// The engine runs a bounded spin of this many instructions; the self-jump
// makes blocks and instructions advance together.
constexpr std::uint64_t kSpinInstructionCount = 16;

// Fixture addresses - all 4KB aligned, the rebuild rejects anything else.
constexpr std::uint64_t kEntryRegionBase = 0x00400000;
constexpr std::uint64_t kStackRegionBase = 0x07F00000;
constexpr std::uint64_t kTebRegionBase = 0x07F10000;
constexpr std::uint64_t kEntryVa = kEntryRegionBase; // the EB FE lives here
constexpr std::uint64_t kStackVa = kStackRegionBase + 0x800;
constexpr std::uint64_t kTebVa = kTebRegionBase + 0x100;
constexpr std::size_t kRegionSize = 0x1000;

// A typical user-mode EFLAGS: interrupt enable, zero and parity flags, plus
// the reserved bit that is always 1.
constexpr std::uint64_t kEflagsReservedOne = 1U << 1;
constexpr std::uint64_t kEflagsParity = 1U << 2;
constexpr std::uint64_t kEflagsZero = 1U << 6;
constexpr std::uint64_t kEflagsInterruptEnable = 1U << 9;
constexpr std::uint64_t kFixtureRflags =
    kEflagsReservedOne | kEflagsParity | kEflagsZero | kEflagsInterruptEnable;
constexpr std::uint8_t kFixtureStackFill = 0x5A;
constexpr std::array<std::uint8_t, 2> kSpinBytes{0xEB, 0xFE}; // jmp $

snapshot::Registers fixture_registers()
{
    snapshot::Registers registers{};
    for (std::size_t i = 0; i < snapshot::kGprCount; ++i) {
        registers.gpr[i] = 0x1000 + i;
    }
    registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRsp)] = kStackVa;
    registers.rip = kEntryVa;
    registers.rflags = kFixtureRflags;
    return registers;
}

snapshot::Metadata fixture_metadata()
{
    snapshot::Metadata metadata{};
    metadata.peb_address = 0x07F20000;
    metadata.teb_address = kTebVa;
    metadata.image_base = kEntryRegionBase;
    metadata.entry_address = kEntryVa;
    for (std::size_t i = 0; i < snapshot::kOriginalEntryBytes; ++i) {
        metadata.original_entry_bytes[i] = static_cast<std::uint8_t>(0x90 + i);
    }
    return metadata;
}

// Writes a synthetic snapshot: entry page (RWX, EB FE spin), stack page
// (RW, patterned), TEB page (RW) and one content-absent NOACCESS page.
fs::path write_snapshot(const snapshot::Registers& registers, const snapshot::Metadata& metadata,
                        const std::uint8_t bitness, const std::string& name)
{
    std::array<std::uint8_t, kRegionSize> entry_bytes{};
    entry_bytes[0] = kSpinBytes[0];
    entry_bytes[1] = kSpinBytes[1];
    std::array<std::uint8_t, kRegionSize> stack_bytes{};
    stack_bytes.fill(kFixtureStackFill);
    const std::array<std::uint8_t, kRegionSize> teb_bytes{};

    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(snapshot::Header{.version = snapshot::kVersion, .bitness = bitness}) ||
        !writer.write_registers(registers) || !writer.write_metadata(metadata) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kEntryRegionBase,
                                                    .size = kRegionSize,
                                                    .protection = kPageExecuteReadwrite,
                                                    .type = kMemImage,
                                                    .content = snapshot::kContentPresent},
                             entry_bytes.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kStackRegionBase,
                                                    .size = kRegionSize,
                                                    .protection = kPageReadwrite,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             stack_bytes.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kTebRegionBase,
                                                    .size = kRegionSize,
                                                    .protection = kPageReadwrite,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             teb_bytes.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = 0x08000000,
                                                    .size = kRegionSize,
                                                    .protection = kPageNoaccess,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentAbsent},
                             nullptr) ||
        !writer.finalize_region_count()) {
        EXPECT_TRUE(false) << "synthetic snapshot serialization failed";
    }

    const auto dir = fs::temp_directory_path() / "sheller_rebuild_test";
    fs::create_directories(dir);
    const auto path = dir / name;
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << out.str();
    EXPECT_TRUE(file) << "cannot write synthetic snapshot";
    return path;
}

fs::path write_default_snapshot(const std::string& name)
{
    return write_snapshot(fixture_registers(), fixture_metadata(), snapshot::kBitness64, name);
}

TEST(Rebuild, ReachesEntrypointWithFullProof)
{
    const auto snapshot = write_default_snapshot("rebuild.snap");
    const auto stats = sheller::engine::run_snapshot_entrypoint(snapshot);
    ASSERT_TRUE(stats.has_value()) << sheller::engine::rebuild_error_message(stats.error().error);
    EXPECT_TRUE(stats->reached_entry);
    // Every executed block is the spin block; unicorn counts the interrupted
    // final block too, so only "at least the bounded instruction count" and
    // "all blocks hit the entry" are pinned here.
    EXPECT_GE(stats->blocks, kSpinInstructionCount);
    EXPECT_EQ(stats->blocks, stats->entry_hits);
    EXPECT_EQ(stats->final_rip, kEntryVa);
}

TEST(Rebuild, ProbeReadsBackRebuiltState)
{
    const auto snapshot = write_default_snapshot("probe.snap");
    const auto probe = sheller::engine::detail::rebuild_and_probe(snapshot);
    ASSERT_TRUE(probe.has_value()) << sheller::engine::rebuild_error_message(probe.error().error);

    EXPECT_EQ(probe->stats.reached_entry, true);
    EXPECT_EQ(probe->gs_base, kTebVa);
    EXPECT_EQ(probe->rip, kEntryVa);
    EXPECT_EQ(probe->rflags, kFixtureRflags);
    EXPECT_EQ(probe->gpr, fixture_registers().gpr);
    EXPECT_EQ(probe->entry_bytes, kSpinBytes);
}

TEST(Rebuild, RejectsUnknownBitness)
{
    // bitness 32 is a supported shape; only unknown values stay
    // rejected at the reader boundary.
    const auto snapshot =
        write_snapshot(fixture_registers(), fixture_metadata(), 128, "bitness128.snap");
    const auto stats = sheller::engine::run_snapshot_entrypoint(snapshot);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::RebuildError::kBitnessUnsupported);
}

TEST(Rebuild, RejectsRipEntryMismatch)
{
    auto metadata = fixture_metadata();
    metadata.entry_address = kEntryVa + 0x10;
    const auto snapshot =
        write_snapshot(fixture_registers(), metadata, snapshot::kBitness64, "mismatch.snap");
    const auto stats = sheller::engine::run_snapshot_entrypoint(snapshot);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::RebuildError::kInconsistent);
}

TEST(Rebuild, RejectsUnalignedRegion)
{
    // The entry region itself starts off the 4KB mapping alignment.
    constexpr std::uint64_t kUnalignedBase = kEntryRegionBase + 0x800;
    auto metadata = fixture_metadata();
    metadata.image_base = kUnalignedBase;
    metadata.entry_address = kUnalignedBase;
    auto registers = fixture_registers();
    registers.rip = kUnalignedBase;

    std::array<std::uint8_t, kRegionSize> entry_bytes{};
    entry_bytes[0] = kSpinBytes[0];
    entry_bytes[1] = kSpinBytes[1];

    std::ostringstream out;
    snapshot::Writer writer{out};
    ASSERT_TRUE(writer.write_header(
        snapshot::Header{.version = snapshot::kVersion, .bitness = snapshot::kBitness64}));
    ASSERT_TRUE(writer.write_registers(registers));
    ASSERT_TRUE(writer.write_metadata(metadata));
    ASSERT_TRUE(writer.write_region(snapshot::RegionHeader{.base_address = kUnalignedBase,
                                                           .size = kRegionSize,
                                                           .protection = kPageExecuteReadwrite,
                                                           .type = kMemImage,
                                                           .content = snapshot::kContentPresent},
                                    entry_bytes.data()));
    ASSERT_TRUE(writer.finalize_region_count());

    const auto dir = fs::temp_directory_path() / "sheller_rebuild_test";
    fs::create_directories(dir);
    const auto snapshot = dir / "unaligned.snap";
    std::ofstream file(snapshot, std::ios::binary | std::ios::trunc);
    file << out.str();
    file.close();

    const auto stats = sheller::engine::run_snapshot_entrypoint(snapshot);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::RebuildError::kUnalignedRegion);
}

// Replaces the entry region with NOACCESS + absent content: the rebuild maps
// it UC_PROT_NONE, so the first fetch must fault with an emulation error.
fs::path write_snapshot_with_inaccessible_entry(const std::string& name)
{
    const auto metadata = fixture_metadata();
    const auto registers = fixture_registers();

    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(
            snapshot::Header{.version = snapshot::kVersion, .bitness = snapshot::kBitness64}) ||
        !writer.write_registers(registers) || !writer.write_metadata(metadata) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kEntryRegionBase,
                                                    .size = kRegionSize,
                                                    .protection = kPageNoaccess,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentAbsent},
                             nullptr) ||
        !writer.finalize_region_count()) {
        EXPECT_TRUE(false) << "synthetic snapshot serialization failed";
    }

    const auto dir = fs::temp_directory_path() / "sheller_rebuild_test";
    fs::create_directories(dir);
    const auto path = dir / name;
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    file << out.str();
    EXPECT_TRUE(file) << "cannot write synthetic snapshot";
    return path;
}

TEST(Rebuild, ReportsFaultWhenEntryPageIsInaccessible)
{
    const auto snapshot = write_snapshot_with_inaccessible_entry("inaccessible.snap");
    const auto stats = sheller::engine::run_snapshot_entrypoint(snapshot);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::RebuildError::kEmulationFailure);
    EXPECT_NE(stats.error().unicorn_code, 0U);
}

#ifdef _WIN32

TEST(Rebuild, RealCaptureReachesEntrypoint)
{
    const auto dir = fs::temp_directory_path() / "sheller_rebuild_test";
    fs::create_directories(dir);
    const auto snapshot = dir / "real.snap";

    const auto captured = sheller::capture::detail::run_impl(sheller::capture::Options{
        .sample_path = SHELLER_CAPTURE_SAMPLE_PATH, .output_path = snapshot});
    ASSERT_EQ(captured.status, sheller::capture::Status::kOk) << captured.detail;

    const auto stats = sheller::engine::run_snapshot_entrypoint(snapshot);
    ASSERT_TRUE(stats.has_value()) << sheller::engine::rebuild_error_message(stats.error().error);
    EXPECT_TRUE(stats->reached_entry);
    EXPECT_GT(stats->entry_hits, 0U);
}

#endif

} // namespace
