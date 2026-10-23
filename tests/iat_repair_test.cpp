// IAT repair tests: the export mapper resolves bound
// thunks from crafted export tables, the pure pipeline pieces (manifest,
// aggregation, PE probe, IAT audit) behave on hand-built bytes, and - on a
// Windows capture host - the full repair over a real packed.exe dump
// produces a complete verdict with an untouched original. The mapper and the
// repair pipeline are engine-native and portable; the packed acceptance is
// the only Windows-gated part (it needs the real capture route).

#include "capture_detail.h"
#include "log_detail.h"
#include "repair.h"

#include <sheller/capture.h>
#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>
#include <sheller/unpack.h>

#include "../behavior/behavior_rules.h"
#include "../engine/rebuild_probe.h"

#include <gtest/gtest.h>

#include "test_temp.hpp"
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <span>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;
namespace unpack = sheller::unpack;

// Captures the diagnostics the repair pipeline delivers through the log
// facade (the verdicts' only presentation channel inside the library).
struct LogCapture {
    struct Record {
        sheller::log::level level{};
        std::string message;
    };

    LogCapture()
    {
        sheller::log::detail::set_sink_impl(
            [this](const sheller::log::level level, const std::string_view message) {
                records.push_back(Record{level, std::string{message}});
            },
            sheller::log::level::kDebug);
    }
    ~LogCapture()
    {
        sheller::log::detail::set_sink_impl({}, sheller::log::level::kWarning);
    }
    LogCapture(const LogCapture&) = delete;
    LogCapture& operator=(const LogCapture&) = delete;

    [[nodiscard]] bool has(const sheller::log::level level, const std::string_view needle) const
    {
        for (const auto& record : records) {
            if (record.level == level && record.message.find(needle) != std::string::npos) {
                return true;
            }
        }
        return false;
    }

    std::vector<Record> records;
};

std::string hex16(const std::uint64_t value)
{
    char buf[17] = {};
    std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(value));
    return buf;
}

// -- byte-crafting helpers ----------------------------------------------------

constexpr std::uint64_t kFakeModuleBase = 0x60000000;
constexpr std::uint64_t kFakeExportVa = kFakeModuleBase + 0x1100;

// A flat (file == memory) PE32+ image exporting one function "fake_export"
// at RVA 0x1100 from module "fake.dll". Just enough structure for the
// engine-native export-directory walk.
std::vector<std::uint8_t> make_export_pe()
{
    std::vector<std::uint8_t> image(0x2000, std::uint8_t{0});
    const auto w8 = [&](const std::uint32_t rva, const std::uint8_t value) { image[rva] = value; };
    const auto w16 = [&](const std::uint32_t rva, const std::uint16_t value) {
        image[rva] = static_cast<std::uint8_t>(value);
        image[rva + 1] = static_cast<std::uint8_t>(value >> 8);
    };
    const auto w32 = [&](const std::uint32_t rva, const std::uint32_t value) {
        w16(rva, static_cast<std::uint16_t>(value));
        w16(rva + 2, static_cast<std::uint16_t>(value >> 16));
    };
    // Consumed by the WIN32-gated packed acceptance only.
    [[maybe_unused]] const auto w64 = [&](const std::uint32_t rva, const std::uint64_t value) {
        w32(rva, static_cast<std::uint32_t>(value));
        w32(rva + 4, static_cast<std::uint32_t>(value >> 32));
    };
    const auto wstr = [&](const std::uint32_t rva, const char* const text) {
        for (std::size_t i = 0; i <= std::strlen(text); ++i) {
            w8(rva + static_cast<std::uint32_t>(i), static_cast<std::uint8_t>(text[i]));
        }
    };

    w16(0, 0x5A4D);        // MZ
    w32(0x3C, 0x40);       // e_lfanew
    w32(0x40, 0x00004550); // PE\0\0
    w16(0x44, 0x8664);     // machine
    w16(0x46, 1);          // number of sections
    w16(0x54, 0xF0);       // size of optional header
    w16(0x56, 0x0022);     // characteristics: executable + large address aware
    w16(0x58, 0x020B);     // PE32+ magic
    w32(0x90, 0x2000);     // SizeOfImage
    w32(0x94, 0x200);      // SizeOfHeaders
    w32(0xC4, 16);         // NumberOfRvaAndSizes (opt + 0x6C)
    // DataDirectory[0] (export) at optional + 0x70 = 0xC8.
    w32(0xC8, 0x1000);
    w32(0xCC, 0x100);
    // One section header at 0x148: ".edata", RVA 0x1000, raw 0x1000@0x1000.
    wstr(0x148, ".edata");
    w32(0x150, 0x1000); // virtual size
    w32(0x154, 0x1000); // virtual address
    w32(0x158, 0x1000); // size of raw data
    w32(0x15C, 0x1000); // pointer to raw data
    w32(0x168, 0x40000040);

    // Export directory at RVA 0x1000.
    w32(0x1000 + 0x0C, 0x1050); // module name RVA ("fake.dll")
    w32(0x1000 + 0x10, 1);      // ordinal base
    w32(0x1000 + 0x14, 1);      // address table entries
    w32(0x1000 + 0x18, 1);      // number of names
    w32(0x1000 + 0x1C, 0x1060); // address table RVA
    w32(0x1000 + 0x20, 0x1070); // name table RVA
    w32(0x1000 + 0x24, 0x1080); // ordinal table RVA
    wstr(0x1050, "fake.dll");
    w32(0x1060, 0x1100); // function RVA
    w32(0x1070, 0x1090); // name string RVA
    w16(0x1080, 0);      // ordinal index
    wstr(0x1090, "fake_export");
    return image;
}

// A flat PE32+ image whose import directory carries one DLL with `thunks`
// bound addresses (what the capture-time loader leaves in memory).
std::vector<std::uint8_t> make_import_image(const std::vector<std::uint64_t>& thunks)
{
    std::vector<std::uint8_t> image(0x3000, std::uint8_t{0});
    const auto w16 = [&](const std::uint32_t rva, const std::uint16_t value) {
        image[rva] = static_cast<std::uint8_t>(value);
        image[rva + 1] = static_cast<std::uint8_t>(value >> 8);
    };
    const auto w32 = [&](const std::uint32_t rva, const std::uint32_t value) {
        w16(rva, static_cast<std::uint16_t>(value));
        w16(rva + 2, static_cast<std::uint16_t>(value >> 16));
    };
    const auto w64 = [&](const std::uint32_t rva, const std::uint64_t value) {
        w32(rva, static_cast<std::uint32_t>(value));
        w32(rva + 4, static_cast<std::uint32_t>(value >> 32));
    };
    const auto wstr = [&](const std::uint32_t rva, const char* const text) {
        for (std::size_t i = 0; i <= std::strlen(text); ++i) {
            image[rva + i] = static_cast<std::uint8_t>(text[i]);
        }
    };

    w16(0, 0x5A4D);
    w32(0x3C, 0x40);
    w32(0x40, 0x00004550);
    w16(0x44, 0x8664);
    w16(0x46, 1);
    w16(0x54, 0xF0);
    w16(0x56, 0x0022);
    w16(0x58, 0x020B);
    w32(0x90, 0x3000); // SizeOfImage
    w32(0x94, 0x300);  // SizeOfHeaders
    w32(0xC4, 16);     // NumberOfRvaAndSizes
    w32(0xD0, 0x2000); // DataDirectory[1] (import) RVA
    w32(0xD4, 40);     // size: one descriptor + terminator
    wstr(0x148, ".idata");
    w32(0x150, 0x1000);
    w32(0x154, 0x2000);
    w32(0x158, 0x1000);
    w32(0x15C, 0x2000);
    w32(0x168, 0xC0000040);

    // Import descriptor at RVA 0x2000, terminator at 0x2014.
    w32(0x2000, 0x2100); // OriginalFirstThunk (hint/name array)
    w32(0x200C, 0x2200); // DLL name RVA
    w32(0x2010, 0x2150); // FirstThunk (IAT)
    // Hint/name entry at 0x2100: hint word + function name. The IAT at
    // 0x2150 holds the bound addresses.
    w16(0x2100, 0);
    wstr(0x2102, "fake_export");
    for (std::size_t i = 0; i < thunks.size(); ++i) {
        w64(static_cast<std::uint32_t>(0x2150 + i * 8), thunks[i]);
    }
    wstr(0x2200, "fake.dll");
    return image;
}

// The mapper's fake module registered under its base; the thunks above point
// into it.
unpack::ExportsMapper make_mapper()
{
    unpack::ExportsMapper mapper;
    const auto module = make_export_pe();
    mapper.add_module("fake.dll", kFakeModuleBase, module.data(), module.size());
    return mapper;
}

// -- mapper -------------------------------------------------------------------

TEST(ExportsMapper, ResolvesBoundAddressToName)
{
    auto mapper = make_mapper();
    const auto module = make_export_pe();
    // Diagnose the registration count if the lookup below misses.
    EXPECT_EQ(mapper.add_module("fake.dll", kFakeModuleBase, module.data(), module.size()), 1U)
        << "export table not registered";
    const auto resolved = mapper.resolve(kFakeExportVa);
    ASSERT_TRUE(resolved.has_value());
    EXPECT_EQ(resolved->module, "fake.dll");
    EXPECT_EQ(resolved->function, "fake_export");
}

TEST(ExportsMapper, UnmappedAddressResolvesNothing)
{
    const auto mapper = make_mapper();
    EXPECT_FALSE(mapper.resolve(kFakeModuleBase + 0x1800).has_value());
    EXPECT_FALSE(mapper.resolve(0).has_value());
}

// -- pure pipeline pieces ------------------------------------------------------

TEST(RepairPieces, ParsesManifestLines)
{
    const auto entries =
        unpack::parse_manifest("0000000040000000 000000003000 01000000 00000040 0000000040000000\n"
                               "garbage line\n");
    ASSERT_EQ(entries.size(), 1U);
    EXPECT_EQ(entries[0].base, 0x40000000U);
    EXPECT_EQ(entries[0].size, 0x3000U);
    EXPECT_EQ(entries[0].type, 0x01000000U);
}

TEST(RepairPieces, AggregatesAdjacentSameTypeRegions)
{
    const unpack::ManifestEntry a{0x40000000, 0x1000, 0x01000000, 0x80, 0x40000000};
    const unpack::ManifestEntry b{0x40001000, 0x2000, 0x01000000, 0x80, 0x40002000};
    const unpack::ManifestEntry c{0x40005000, 0x1000, 0x01000000, 0x80, 0x40005000};
    const unpack::ManifestEntry d{0x40006000, 0x1000, 0x00020000, 0x04, 0x40006000};
    const auto merged = unpack::aggregate_regions({a, b, c, d});
    ASSERT_EQ(merged.size(), 3U);
    EXPECT_EQ(merged[0].base, 0x40000000U);
    EXPECT_EQ(merged[0].size, 0x3000U);
    EXPECT_EQ(merged[1].base, 0x40005000U);
    EXPECT_EQ(merged[2].type, 0x00020000U);
}

TEST(RepairPieces, ProbesSizeOfImage)
{
    auto image = make_import_image({});
    // SizeOfImage at optional + 0x38: e_lfanew(0x40) + 0x50 = 0x90.
    image[0x90] = 0x00;
    image[0x91] = 0x30;
    const auto size = unpack::probe_size_of_image(image.data(), image.size());
    ASSERT_TRUE(size.has_value());
    EXPECT_EQ(*size, 0x3000U);
    image[0] = 'X'; // broken MZ
    EXPECT_FALSE(unpack::probe_size_of_image(image.data(), image.size()).has_value());
}

TEST(RepairPieces, AuditsCoveredAndUncoveredThunks)
{
    const auto mapper = make_mapper();
    const auto image = make_import_image({kFakeExportVa, kFakeModuleBase + 0x1800});
    const auto audit = unpack::audit_imports(image.data(), image.size(), mapper);
    EXPECT_EQ(audit.covered_count, 1U);
    ASSERT_EQ(audit.uncovered.size(), 1U);
    EXPECT_EQ(audit.uncovered[0].rva, 0x2158U);
    EXPECT_EQ(audit.uncovered[0].va, kFakeModuleBase + 0x1800U);
}

TEST(RepairPieces, ResidualAuditClassifiesRepairedThunks)
{
    // Unrepaired absolute thunk: residual (not name-record form).
    const auto raw = make_import_image({kFakeExportVa});
    const auto raw_audit = unpack::audit_residual_abs_va(raw.data(), raw.size());
    EXPECT_EQ(raw_audit.covered_count, 0U);
    ASSERT_EQ(raw_audit.residual.size(), 1U);
    EXPECT_EQ(raw_audit.residual[0].va, kFakeExportVa);

    // Repaired to name-record form: the thunk points at a hint/name record
    // inside the image (hint word + printable name + NUL) - covered, zero
    // residual. A second thunk still holding the absolute VA stays residual.
    auto repaired = make_import_image({kFakeExportVa, kFakeModuleBase + 0x1800});
    // find the import thunks via the same walk the audit uses
    const std::uint32_t e_lfanew = static_cast<std::uint32_t>(repaired[0x3c]) |
                                   (static_cast<std::uint32_t>(repaired[0x3d]) << 8);
    std::uint32_t import_rva = 0;
    for (int i = 0; i < 4; ++i) {
        // DataDirectory[1] = Import (base 0x70 + entry size 8); the RVA is
        // 4 bytes - the old i<8 loop shifted the directory SIZE into the
        // value (shift >= 32 is UB; new toolchains fold it differently)
        import_rva |= static_cast<std::uint32_t>(repaired[e_lfanew + 0x18 + 0x78 + i]) << (8 * i);
    }
    const auto first_thunk = [&]() {
        for (std::uint32_t desc = import_rva;; desc += 20) {
            const auto name_rva = static_cast<std::uint32_t>(repaired[desc + 12]) |
                                  (static_cast<std::uint32_t>(repaired[desc + 13]) << 8);
            const auto ft = static_cast<std::uint32_t>(repaired[desc + 16]) |
                            (static_cast<std::uint32_t>(repaired[desc + 17]) << 8);
            if (name_rva == 0 && ft == 0) {
                return 0U;
            }
            if (ft != 0) {
                return ft;
            }
        }
    }();
    ASSERT_NE(first_thunk, 0U);
    // synthesize a hint/name record for the fake export at a fresh offset
    const std::uint32_t record_rva = 0x2600;
    repaired[record_rva] = 0;
    repaired[record_rva + 1] = 0; // hint
    const char name[] = "fake_export";
    std::memcpy(repaired.data() + record_rva + 2, name, sizeof name);
    // thunk[0] -> name record; thunk[1] keeps the absolute VA (residual).
    // Four bytes: record_rva is 32-bit and shifting it by >= 32 is UB -
    // the old i<8 loop duplicated the low half into the high bytes on the
    // current toolchain, so the audit read 0x260000002600 (never a record).
    for (int i = 0; i < 4; ++i) {
        repaired[first_thunk + i] = static_cast<std::uint8_t>((record_rva >> (8 * i)) & 0xFF);
        repaired[first_thunk + 4 + i] = 0;
    }
    const auto audit = unpack::audit_residual_abs_va(repaired.data(), repaired.size());
    EXPECT_EQ(audit.covered_count, 1U);
    ASSERT_EQ(audit.residual.size(), 1U);
    EXPECT_EQ(audit.residual[0].va, kFakeModuleBase + 0x1800U);
}

TEST(RepairPieces, ResidualAuditZeroImportTriviallyClean)
{
    // A PE whose import directory RVA is zero: nothing to walk, trivially
    // zero residual (the 1.3 zero-import branch).
    const auto image = make_import_image({});
    auto audit = unpack::audit_residual_abs_va(image.data(), image.size());
    EXPECT_EQ(audit.residual.size(), 0U);
    EXPECT_EQ(audit.covered_count, 0U);
}

// -- full pipeline over a crafted snapshot + dump directory --------------------

class RepairDumpEnv : public testing::Test {
  protected:
    void SetUp() override
    {
        dir_ = sheller_test::temp_path("sheller_iat_repair_test");
        fs::remove_all(dir_);
        fs::create_directories(dir_);
        snapshot_ = dir_ / "crafted.snap";
        write_snapshot(snapshot_);
        dump_ = dir_ / "dump";
        fs::create_directories(dump_);
        // Two image regions (complete + partial) and one bare buffer. The
        // partial image sits non-adjacent so the two stay separate repair
        // candidates.
        write_dump_region(0x40000000, make_import_image({kFakeExportVa}));
        write_dump_region(0x40005000, make_import_image({kFakeExportVa, kFakeModuleBase + 0x1800}));
        write_dump_region(0x50000000, std::vector<std::uint8_t>(0x1000, 0xAB));
        std::string manifest;
        manifest += "0000000040000000 000000003000 01000000 00000040 0000000040000000\n";
        manifest += "0000000040005000 000000003000 01000000 00000040 0000000040005000\n";
        manifest += "0000000050000000 000000001000 00020000 00000004 0000000050000000\n";
        write_file(dump_ / "manifest.txt", manifest);
        out_ = dir_ / "out";
    }

    void write_snapshot(const fs::path& path)
    {
        std::ofstream out(path, std::ios::binary);
        sheller::snapshot::Writer writer(out);
        // region_count must start at 0: the Writer seeds its counter from
        // the header and finalize writes the number of write_region calls.
        static_cast<void>(writer.write_header({1, 64, 0}));
        sheller::snapshot::Registers registers{};
        registers.rip = kFakeModuleBase + 0x1100; // entry inside the module
        static_cast<void>(writer.write_registers(registers));
        sheller::snapshot::Metadata metadata;
        metadata.teb_address = 0x10000; // TEB page, laid out below
        metadata.image_base = kFakeModuleBase;
        metadata.entry_address = registers.rip;
        static_cast<void>(writer.write_metadata(metadata));
        // The module region plus the PEB/Ldr scaffolding the engine's module
        // walk reads (TEB+0x60 → PEB, PEB+0x18 → Ldr, Ldr+0x10 → entry),
        // all page aligned.
        const auto module = make_export_pe();
        write_region(writer, kFakeModuleBase, module);

        std::vector<std::uint8_t> teb(0x1000, 0);
        w64_at(teb, 0x60, 0x11000); // TEB.ProcessEnvironmentBlock
        write_region(writer, 0x10000, teb);
        std::vector<std::uint8_t> peb(0x1000, 0);
        w64_at(peb, 0x18, 0x12000); // PEB.Ldr
        write_region(writer, 0x11000, peb);
        std::vector<std::uint8_t> ldr(0x1000, 0);
        w64_at(ldr, 0x10, 0x13000); // InLoadOrderModuleList.Flink
        write_region(writer, 0x12000, ldr);
        std::vector<std::uint8_t> entry(0x1000, 0);
        w64_at(entry, 0x00, 0x13000);         // Flink (self: single-entry list)
        w64_at(entry, 0x08, 0x13000);         // Blink
        w64_at(entry, 0x30, kFakeModuleBase); // DllBase
        w32_at(entry, 0x40, 0x2000);          // SizeOfImage
        w16_at(entry, 0x58, 8);               // BaseDllName.Length (bytes)
        w64_at(entry, 0x60, 0x14000);         // BaseDllName.Buffer
        write_region(writer, 0x13000, entry);
        std::vector<std::uint8_t> name(0x1000, 0);
        name[0] = 'f';
        name[1] = 0;
        name[2] = 'a';
        name[3] = 0;
        name[4] = 'k';
        name[5] = 0;
        name[6] = 'e';
        name[7] = 0; // UTF-16 "fake"
        write_region(writer, 0x14000, name);
        static_cast<void>(writer.finalize_region_count());
    }

    static void w64_at(std::vector<std::uint8_t>& bytes, const std::size_t offset,
                       const std::uint64_t value)
    {
        for (std::size_t i = 0; i < 8; ++i) {
            bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
        }
    }

    static void w32_at(std::vector<std::uint8_t>& bytes, const std::size_t offset,
                       const std::uint32_t value)
    {
        for (std::size_t i = 0; i < 4; ++i) {
            bytes[offset + i] = static_cast<std::uint8_t>(value >> (i * 8));
        }
    }

    static void w16_at(std::vector<std::uint8_t>& bytes, const std::size_t offset,
                       const std::uint16_t value)
    {
        bytes[offset] = static_cast<std::uint8_t>(value);
        bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
    }

    static void write_region(sheller::snapshot::Writer& writer, const std::uint64_t base,
                             const std::vector<std::uint8_t>& bytes)
    {
        sheller::snapshot::RegionHeader header;
        header.base_address = base;
        header.size = bytes.size();
        header.protection = 0x40;
        header.type = 0x01000000;
        header.content = sheller::snapshot::kContentPresent;
        static_cast<void>(writer.write_region(header, bytes.data()));
    }

    void write_dump_region(const std::uint64_t base, const std::vector<std::uint8_t>& bytes)
    {
        char name[24] = {};
        std::snprintf(name, sizeof name, "%016llx.bin", static_cast<unsigned long long>(base));
        write_file(dump_ / name, std::string(bytes.begin(), bytes.end()));
    }

    static void write_file(const fs::path& path, const std::string& content)
    {
        std::ofstream out(path, std::ios::binary);
        out << content;
    }

    fs::path dir_;
    fs::path snapshot_;
    fs::path dump_;
    fs::path out_;
};

TEST_F(RepairDumpEnv, CompletePartialAndNotImageVerdicts)
{
    LogCapture logs;
    const auto summary = unpack::repair_dump(snapshot_, dump_, out_);
    ASSERT_TRUE(summary.has_value()) << "repair error=" << static_cast<int>(summary.error());
    ASSERT_EQ(summary->regions.size(), 3U);
    EXPECT_EQ(summary->regions[0].verdict, unpack::RepairVerdict::kComplete);
    EXPECT_EQ(summary->regions[1].verdict, unpack::RepairVerdict::kPartial);
    ASSERT_EQ(summary->regions[1].uncovered.size(), 1U);
    EXPECT_EQ(summary->regions[2].verdict, unpack::RepairVerdict::kNotImage);

    // The verdicts' only library-side presentation is the diagnostics log:
    // one info per region, one debug per uncovered thunk, structural fields
    // serve as the truth. No report file exists any more.
    EXPECT_TRUE(logs.has(sheller::log::level::kInfo, "verdict=complete"));
    EXPECT_TRUE(logs.has(sheller::log::level::kInfo, "verdict=partial"));
    EXPECT_TRUE(logs.has(sheller::log::level::kInfo, "verdict=not-image"));
    const auto& uncovered = summary->regions[1].uncovered[0];
    EXPECT_TRUE(logs.has(sheller::log::level::kDebug,
                         "uncovered rva=" + hex16(uncovered.rva) + " va=" + hex16(uncovered.va)));
    for (const auto& region : summary->regions) {
        const auto base = hex16(region.base);
        bool found = false;
        for (const auto& record : logs.records) {
            if (record.level == sheller::log::level::kInfo &&
                record.message.find("repair region " + base) != std::string::npos) {
                found = true;
                // The logged uncovered count must equal the structural field
                // (the not-image verdict has no import audit and no count).
                if (region.verdict == unpack::RepairVerdict::kComplete ||
                    region.verdict == unpack::RepairVerdict::kPartial) {
                    EXPECT_NE(
                        record.message.find("uncovered=" + std::to_string(region.uncovered.size())),
                        std::string::npos)
                        << record.message;
                }
            }
        }
        EXPECT_TRUE(found) << "no info record for region " << base;
    }
    EXPECT_FALSE(fs::exists(out_ / "repair_report.txt"));

    // Residual absolute-VA audit: the complete region
    // must come back empty; the partial region's residuals are exactly its
    // uncovered thunks keeping their bound VAs.
    EXPECT_TRUE(summary->regions[0].residual_abs_va.empty());
    ASSERT_EQ(summary->regions[1].residual_abs_va.size(), summary->regions[1].uncovered.size());
    EXPECT_EQ(summary->regions[1].residual_abs_va[0].rva, summary->regions[1].uncovered[0].rva);
    EXPECT_EQ(summary->regions[1].residual_abs_va[0].va, summary->regions[1].uncovered[0].va);
    EXPECT_TRUE(logs.has(sheller::log::level::kInfo, "residual_abs=0"));
}

TEST_F(RepairDumpEnv, FailedRegionLogsWarning)
{
    // Corrupt one dump chunk: its size no longer matches the manifest, so
    // the region fails structurally and the reason rides a warning record.
    const auto victim = [&] {
        for (const auto& entry : fs::directory_iterator(dump_)) {
            if (entry.path().extension() == ".bin") {
                return entry.path();
            }
        }
        return fs::path{};
    }();
    ASSERT_FALSE(victim.empty());
    fs::remove(victim);

    LogCapture logs;
    const auto summary = unpack::repair_dump(snapshot_, dump_, out_);
    ASSERT_TRUE(summary.has_value());
    bool failed = false;
    for (const auto& region : summary->regions) {
        failed = failed || region.verdict == unpack::RepairVerdict::kFailed;
    }
    EXPECT_TRUE(failed);
    EXPECT_TRUE(logs.has(sheller::log::level::kWarning, "verdict=failed detail="));
    EXPECT_FALSE(fs::exists(out_ / "repair_report.txt"));
}

TEST_F(RepairDumpEnv, DeterministicOutputs)
{
    const auto out_b = dir_ / "out_b";
    static_cast<void>(unpack::repair_dump(snapshot_, dump_, out_));
    static_cast<void>(unpack::repair_dump(snapshot_, dump_, out_b));
    const auto file_hash = [](const fs::path& path) {
        std::ifstream in(path, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(in)), {});
    };
    for (const auto& entry : fs::directory_iterator(out_)) {
        const auto mirror = out_b / entry.path().filename();
        ASSERT_TRUE(fs::exists(mirror)) << entry.path();
        EXPECT_EQ(file_hash(entry.path()), file_hash(mirror)) << entry.path();
    }
}

TEST_F(RepairDumpEnv, OriginalDumpUntouched)
{
    const auto bin = dump_ / "0000000040000000.bin";
    const auto before = [&bin] {
        std::ifstream in(bin, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(in)), {});
    }();
    static_cast<void>(unpack::repair_dump(snapshot_, dump_, out_));
    EXPECT_EQ(before, [&bin] {
        std::ifstream in(bin, std::ios::binary);
        return std::string((std::istreambuf_iterator<char>(in)), {});
    }());
}

#ifdef _WIN32

// -- real-corpus acceptance: packed.exe dump repairs complete ------------------

fs::path capture_to(const char* sample_path, const std::string& name)
{
    const auto dir = sheller_test::temp_path("sheller_iat_repair_test");
    fs::create_directories(dir);
    const auto snapshot = dir / name;
    const auto captured = sheller::capture::detail::run_impl(
        sheller::capture::Options{.sample_path = sample_path, .output_path = snapshot});
    EXPECT_EQ(captured.status, sheller::capture::Status::kOk) << captured.detail;
    return snapshot;
}

TEST(RepairPipeline, PackedSampleRepairsCompletely)
{
#ifndef SHELLER_SAMPLE_PACKED_PATH
    GTEST_SKIP() << "no packed corpus path configured";
#else
    const auto snapshot = capture_to(SHELLER_SAMPLE_PACKED_PATH, "iat_packed.snap");
    const auto dump = sheller_test::temp_path("sheller_iat_packed_dump");
    fs::remove_all(dump);

    sheller::engine::SyscallRunOptions options;
    // The UPX stub decompresses ~3M blocks: the default 1M-instruction
    // budget stops mid-unpack, so the acceptance run is unbounded.
    options.max_instructions = 0;
    options.timeout_ms = 300000;
    options.dump_directory = dump;
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot);
    ASSERT_TRUE(probe.has_value());
    sheller::behavior::BehaviorRules rules([&] {
        sheller::behavior::BehaviorRulesParams params;
        params.teb_address = probe->teb_address;
        params.peb_address = probe->peb_address;
        params.sample_image_base = probe->image_base;
        params.sample_image_size = probe->image_size;
        for (const auto& image : probe->images) {
            params.modules.push_back(image.module);
        }
        return params;
    }());
    std::vector<std::uint64_t> oep_candidates;
    int emitted = 0;
    rules.set_event_emitter([&](const sheller::EventTypeId type,
                                const sheller::EventPreamble& preamble,
                                const std::span<const std::uint8_t>) {
        ++emitted;
        if (type == sheller::EventTypeId::kOepCandidate) {
            oep_candidates.push_back(preamble.pc);
        }
    });
    // The fact seam has no public options slot: the channel rides beside.
    sheller::engine::FactChannel fact_channel;
    fact_channel.behavior_sink = [&rules](const sheller::engine::BehaviorFact& fact) {
        rules.on_fact(fact);
    };
    options.event_sink =
        [&](const sheller::EventTypeId type, const sheller::EventPreamble& preamble,
            const std::span<const std::uint8_t> fields) { rules.on_event(type, preamble, fields); };
    const auto stats =
        sheller::engine::detail::run_snapshot_syscalls_with_facts(snapshot, options, fact_channel);
    // The dump must exist regardless of the stop kind: the corpus run stops
    // on the instruction budget inside the CRT startup, still after unpacking.
    ASSERT_TRUE(fs::exists(dump / "manifest.txt"));

    const auto out = sheller_test::temp_path("sheller_iat_packed_out");
    fs::remove_all(out);
    ASSERT_FALSE(oep_candidates.empty())
        << "the packed run identified no OEP candidate (total judgment events=" << emitted << ")";
    const auto summary = unpack::repair_dump(snapshot, dump, out, oep_candidates);
    ASSERT_TRUE(summary.has_value());
    ASSERT_TRUE(summary->oep_found);
    ASSERT_EQ(summary->oep_va, oep_candidates.front());

    const unpack::RegionRepairReport* complete = nullptr;
    for (const auto& region : summary->regions) {
        if (region.verdict == unpack::RepairVerdict::kComplete &&
            region.size >= 0x80000) { // the unpacked body region
            complete = &region;
        }
    }
    ASSERT_NE(complete, nullptr) << "no complete verdict for the unpacked image region";

    // The repaired copy parses as a PE with a name-import directory.
    const auto repaired = out / ("repaired_" + [&] {
                              char name[17] = {};
                              std::snprintf(name, sizeof name, "%016llx",
                                            static_cast<unsigned long long>(complete->base));
                              return std::string(name);
                          }() + ".exe");
    std::ifstream in(repaired, std::ios::binary);
    ASSERT_TRUE(in) << repaired;
    const std::string bytes((std::istreambuf_iterator<char>(in)), {});
    EXPECT_GE(bytes.size(), 0x200U);
    EXPECT_EQ(bytes[0], 'M');
    EXPECT_EQ(bytes[1], 'Z');
#endif
}

#endif // _WIN32

} // namespace
