// DLL-input route end-to-end (Windows): the acceptance line of the
// The DLL-input acceptance line, pinned against the CLI. capture → unpack on
// the packed corpus must produce a loadable .unp whose entry point matches
// the upx -d reference (0x13E4) with the DLL flag intact, and the replay of
// the captured runner world must print the DllMain marker through
// --guest-stdout - the synthetic load's whole chain in one assertion each.

#include <gtest/gtest.h>

#ifdef _WIN32
#include <sheller/snapshot.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#endif

#include "test_temp.hpp"
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>

namespace {

namespace fs = std::filesystem;

#ifdef _WIN32
constexpr std::string_view kCliCommand = SHELLER_CLI_FILE_NAME;
#else
constexpr std::string_view kCliCommand = "./" SHELLER_CLI_FILE_NAME;
#endif

std::string run_and_capture(std::string_view args)
{
    const auto out_path = sheller_test::temp_path("sheller_dll_e2e_out.txt").string();
    const auto cmd = std::format("{} {} > \"{}\" 2>&1", kCliCommand, args, out_path);
    const auto exit_code = std::system(cmd.c_str());
    std::ifstream file(out_path);
    const std::string output((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
    std::error_code ec;
    fs::remove(out_path, ec);
    return std::format("{}|{}", exit_code, output);
}

#ifdef _WIN32

fs::path packed_dll()
{
    return fs::path{SHELLER_SAMPLE_PACKED_DLL_PATH};
}

std::vector<std::uint8_t> read_bytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::uint32_t entry_rva_of(const std::vector<std::uint8_t>& pe)
{
    const auto e_lfanew =
        static_cast<std::uint32_t>(pe[0x3C]) | (static_cast<std::uint32_t>(pe[0x3D]) << 8);
    return static_cast<std::uint32_t>(pe[e_lfanew + 40]) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 41]) << 8) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 42]) << 16) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 43]) << 24);
}

std::uint16_t characteristics_of(const std::vector<std::uint8_t>& pe)
{
    const auto e_lfanew =
        static_cast<std::uint32_t>(pe[0x3C]) | (static_cast<std::uint32_t>(pe[0x3D]) << 8);
    return static_cast<std::uint16_t>(pe[e_lfanew + 22]) |
           static_cast<std::uint16_t>(pe[e_lfanew + 23] << 8);
}

// The acceptance: capture → unpack on the packed corpus reproduces the
// reference entry point (0x13E4 = the real DllMain) with the DLL flag kept.
TEST(DllE2E, UnpackReproducesReferenceEntryPoint)
{
    const auto dir = sheller_test::temp_path("sheller_dll_e2e");
    fs::create_directories(dir);
    const auto output = dir / "packed.dll.unp";
    const auto result =
        run_and_capture(std::format("unpack \"{}\" -o \"{}\" -b 60M --timeout-ms 300000",
                                    packed_dll().string(), output.string()));
    ASSERT_EQ(result.substr(0, result.find('|')), "0") << result;
    ASSERT_TRUE(fs::exists(output));
    const auto bytes = read_bytes(output);
    ASSERT_GE(bytes.size(), 0x200u);
    EXPECT_EQ(entry_rva_of(bytes), 0x13E4u);
    EXPECT_NE(characteristics_of(bytes) & 0x2000, 0); // IMAGE_FILE_DLL kept
}

// Stop faces on the DLL corpus. The UPX stub's DllMain opens with
// argument-shadow stores and a reason branch before its register saves, so
// the esp scan finds no contiguous push sequence at the re-armed entry and
// esp/esp+xfer are a documented silent miss - the run closes normally. The
// usable stop face is xfer=1: the stub's post-restore jump to the unpacked
// entry is the first counted transfer (the OEP dump stop).
TEST(DllE2E, EspStopIsADocumentedMissAndXfer1IsTheUsableFace)
{
    const auto dir = sheller_test::temp_path("sheller_dll_e2e_stops");
    fs::create_directories(dir);

    const auto esp_out = dir / "esp.dll.unp";
    const auto esp_result =
        run_and_capture(std::format("unpack \"{}\" -o \"{}\" --stop esp -b 60M --timeout-ms 300000",
                                    packed_dll().string(), esp_out.string()));
    EXPECT_NE(esp_result.find("esp target not reached"), std::string::npos) << esp_result;
    EXPECT_NE(esp_result.find("terminated=1 exit=0x5a"), std::string::npos) << esp_result;
    EXPECT_TRUE(fs::exists(esp_out)); // the miss closes the run on its own terms

    const auto xfer_out = dir / "xfer.dll.unp";
    const auto xfer_result = run_and_capture(
        std::format("unpack \"{}\" -o \"{}\" --stop xfer=1 -b 60M --timeout-ms 300000",
                    packed_dll().string(), xfer_out.string()));
    EXPECT_NE(xfer_result.find("xfer target reached (xfers=1)"), std::string::npos) << xfer_result;
    EXPECT_NE(xfer_result.find("terminated=0"), std::string::npos) << xfer_result;
    EXPECT_TRUE(fs::exists(xfer_out)); // the OEP-face dump
}

// The replay chain: the captured runner world, replayed with --guest-stdout,
// prints the DllMain marker - proof the synthetic load reached the real
// DllMain body (the ATTACH mainline) and its NtWriteFile rode the sink.
TEST(DllE2E, ReplayPrintsDllMainMarkerThroughGuestStdout)
{
    const auto dir = sheller_test::temp_path("sheller_dll_e2e_replay");
    fs::create_directories(dir);
    const auto snap = dir / "packed_dll_v2.snap";
    ASSERT_EQ(run_and_capture(
                  std::format("capture \"{}\" -o \"{}\"", packed_dll().string(), snap.string()))
                  .substr(0, 1),
              "0");
    ASSERT_TRUE(fs::exists(snap));
    const auto result = run_and_capture(std::format(
        "run --from-snapshot \"{}\" --guest-stdout -b 60M --timeout-ms 300000", snap.string()));
    EXPECT_NE(result.find("hello world from dllmain"), std::string::npos) << result;
    // the designed finish: the runner stub's ExitProcess after a TRUE return
    EXPECT_NE(result.find("terminated=1 exit=0x5a"), std::string::npos) << result;
}

// Round trip: the run's own --save-snapshot re-arms the same synthetic
// load from the container block on --from-snapshot - the replayed run prints
// the same DllMain marker and finishes the same way (replay is re-enactment).
TEST(DllE2E, SavedSnapshotRoundTripReplaysTheSameSemantics)
{
    const auto dir = sheller_test::temp_path("sheller_dll_e2e_roundtrip");
    fs::create_directories(dir);
    const auto saved = dir / "saved.snap";
    ASSERT_EQ(run_and_capture(
                  std::format(
                      "run \"{}\" --save-snapshot \"{}\" --guest-stdout -b 60M --timeout-ms 300000",
                      packed_dll().string(), saved.string()))
                  .substr(0, 1),
              "0");
    ASSERT_TRUE(fs::exists(saved));
    const auto result = run_and_capture(std::format(
        "run --from-snapshot \"{}\" --guest-stdout -b 60M --timeout-ms 300000", saved.string()));
    EXPECT_NE(result.find("hello world from dllmain"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=1 exit=0x5a"), std::string::npos) << result;
}

#endif // _WIN32

} // namespace
