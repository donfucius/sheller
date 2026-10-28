// DLL-input route, live-capture replay chain (Windows): the captured runner
// world replayed with --guest-stdout must print the DllMain marker (the
// synthetic load reached the real DllMain body and its NtWriteFile rode the
// sink), the run's own saved snapshot must re-enact it, and the esp stop
// must close the unpack normally on its documented miss.
//
// This suite is excluded from shared CI runners: the captured world carries
// per-process entropy from the live loader, and past the OEP that entropy
// steers the payload's CRT init - on runner hardware it crashes before the
// DllMain print, on the author machine it only perturbs data bytes (see the
// code-review-7.3.md record in the change archive; same family as the
// excluded capture_x86_e2e). It runs on the development machine, where all
// three tests are green.

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
    const auto out_path = sheller_test::temp_path("sheller_dll_capture_out.txt").string();
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

// The esp stop face on the packed DLL: the UPX stub's DllMain opens with
// argument-shadow stores and a reason branch before its register saves, so
// the esp scan finds no contiguous push sequence at the re-armed entry and
// esp/esp+xfer are a documented silent miss - the run closes normally and
// the unpack still completes.
TEST(DllCaptureE2E, EspStopMissClosesTheRunNormally)
{
    const auto dir = sheller_test::temp_path("sheller_dll_capture_esp");
    fs::create_directories(dir);
    const auto output = dir / "esp.dll.unp";
    const auto result =
        run_and_capture(std::format("unpack \"{}\" -o \"{}\" --stop esp -b 60M --timeout-ms"
                                    " 300000",
                                    packed_dll().string(), output.string()));
    EXPECT_NE(result.find("esp target not reached"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=1 exit=0x5a"), std::string::npos) << result;
    EXPECT_TRUE(fs::exists(output)); // the miss closes the run on its own terms
}

// The replay chain: the captured runner world, replayed with --guest-stdout,
// prints the DllMain marker - proof the synthetic load reached the real
// DllMain body (the ATTACH mainline) and its NtWriteFile rode the sink.
TEST(DllCaptureE2E, ReplayPrintsDllMainMarkerThroughGuestStdout)
{
    const auto dir = sheller_test::temp_path("sheller_dll_capture_replay");
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
TEST(DllCaptureE2E, SavedSnapshotRoundTripReplaysTheSameSemantics)
{
    const auto dir = sheller_test::temp_path("sheller_dll_capture_roundtrip");
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
