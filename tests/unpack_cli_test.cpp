// CLI-level unpack/run tests: the one-shot unpack subcommand is a thin shell
// over the facade's unpack_sample - Windows captures, other hosts construct a
// v1 container from the sample plus the generated synthetic system modules -
// then both run with a dump, repair the IAT and land the artifacts. Both
// routes execute a world with the sample's Ldr entry and module exports, so
// the packed corpus repairs completely (verdict=complete) and the judgment
// stream is populated. The non-Windows cases also cover the run route's
// container save/replay equality, the missing-directory and PE32 refusals.

// getenv/sscanf carry safe-deprecation notes on MSVC; the parsing is the point.
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <gtest/gtest.h>

#include "container_size_bound.h"
#include "test_temp.hpp"
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#ifndef _WIN32
#include <sys/wait.h>
#endif

namespace {

// POSIX shells do not search the working directory; cmd.exe does. The test's
// working directory is the CLI directory.
#ifdef _WIN32
constexpr std::string_view kCliCommand = SHELLER_CLI_FILE_NAME;
#else
constexpr std::string_view kCliCommand = "./" SHELLER_CLI_FILE_NAME;
#endif

std::string read_file(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), {});
}

// The one-line repair verdict summary the CLI prints from the structured
// field: parse it so the numbers can be checked against each other (and by
// platform expectation).
struct VerdictSummary {
    unsigned long regions{};
    unsigned long complete{};
    unsigned long partial{};
    unsigned long failed{};
    unsigned long not_image{};
    unsigned long uncovered{};
};

std::optional<VerdictSummary> parse_verdict_line(const std::string& output)
{
    const auto at = output.find("sheller unpack: repair regions=");
    if (at == std::string::npos) {
        return std::nullopt;
    }
    VerdictSummary summary;
    const auto parsed = std::sscanf(output.c_str() + at,
                                    "sheller unpack: repair regions=%lu complete=%lu partial=%lu "
                                    "failed=%lu not-image=%lu uncovered=%lu",
                                    &summary.regions, &summary.complete, &summary.partial,
                                    &summary.failed, &summary.not_image, &summary.uncovered);
    if (parsed != 6) {
        return std::nullopt;
    }
    return summary;
}

// Number of files in `dir` whose name ends with the suffix - the "one report
// on disk" assertion.
std::size_t count_files_ending(const std::filesystem::path& dir, const std::string_view suffix)
{
    std::size_t count = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        const auto name = entry.path().filename().string();
        if (entry.is_regular_file() && name.ends_with(suffix)) {
            ++count;
        }
    }
    return count;
}

// Envelope invariant for a JSON artifact the CLI wrote: three consecutive
// quote characters never occur in this renderer's output. Every string field
// goes through the escaper, so a value's closing quote is always followed by
// a comma, a colon or a brace - and an embedded quote arrives as \". A stray
// quote from a render defect is exactly what produces the sequence.
constexpr std::string_view kQuoteRun = R"(""")";

TEST(UnpackCli, OneShotProducesImageAndOneReport)
{
    namespace fs = std::filesystem;
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto out = sheller_test::temp_path("sheller_unpack_cli_test") / "packed.exe.unp";
    fs::remove_all(out.parent_path());
    fs::create_directories(out.parent_path());
    const auto out_str = out.string();

    const auto cmd = std::string(kCliCommand) + " unpack \"" + sample.string() + "\" -o \"" +
                     out_str + "\" --event-level full";
    const auto cap = sheller_test::temp_path("sheller_unpack_cli_out.txt");
    const std::string full = cmd + " > \"" + cap.string() + "\" 2>&1";
    const auto rc = std::system(full.c_str());
    const std::string output = read_file(cap);

    EXPECT_EQ(rc, 0) << output;
    ASSERT_TRUE(fs::exists(out)) << output;
    std::ifstream unp(out, std::ios::binary);
    char mz[2] = {};
    unp.read(mz, 2);
    EXPECT_EQ(std::memcmp(mz, "MZ", 2), 0);

    // The verdicts are structured and summarized on stdout in one line; the
    // numbers have to agree with each other. Both routes execute a world with
    // the sample's Ldr entry and module exports, so the image region repairs
    // completely.
    const auto summary = parse_verdict_line(output);
    ASSERT_TRUE(summary.has_value()) << output;
    EXPECT_EQ(summary->regions,
              summary->complete + summary->partial + summary->failed + summary->not_image)
        << output;
    EXPECT_GT(summary->complete, 0UL) << output;

    // The retired file face stays retired: no .reports/ directory and no
    // repair_report.txt anywhere in the output directory.
    EXPECT_FALSE(fs::exists(out_str + ".reports")) << output;
    EXPECT_FALSE(fs::exists(fs::path(out_str).parent_path() / "repair_report.txt")) << output;

    // The behavior report renders beside the image from the run's artifacts;
    // the top level is exactly {"events": ...}.
    ASSERT_TRUE(fs::exists(out_str + ".report.json")) << output;
    const std::string behavior_text = read_file(out_str + ".report.json");
    EXPECT_NE(behavior_text.find("\"events\":{\"counts\":{"), std::string::npos);
    EXPECT_EQ(behavior_text.find("\"signals\":"), std::string::npos) << behavior_text;
    EXPECT_EQ(behavior_text.find(kQuoteRun), std::string::npos) << "the report envelope is broken";
    EXPECT_EQ(count_files_ending(out.parent_path(), ".report.json"), 1U) << output;

    // The full-level report carries the ledger window inside the one artifact
    // - never an empty stream from a flag that collects the tier and drops it.
    // How much the retained window covers varies by route, so what is pinned
    // here is that instruction-level entries are present, the loss key states
    // the retention contract, and no companion file lands beside the image.
    EXPECT_NE(behavior_text.find("\"loss\":{\"dropped\":"), std::string::npos) << behavior_text;
    EXPECT_NE(behavior_text.find("\"type\":\"block-exec\""), std::string::npos) << behavior_text;
    EXPECT_NE(behavior_text.find("\"tid\":"), std::string::npos) << behavior_text;
    EXPECT_FALSE(fs::exists(out_str + ".timeline.json")) << output;
    EXPECT_FALSE(fs::exists(out_str + ".timeline.json.calls.json")) << output;
    EXPECT_FALSE(fs::exists(out_str + ".timeline.json.stubcalls.json")) << output;

    // No intermediate snapshot file exists without --save-snapshot.
    EXPECT_FALSE(fs::exists(out_str + ".snap"));
}

TEST(UnpackCli, MissingBudgetUsesTheShortWallClockAndSaysSo)
{
    namespace fs = std::filesystem;
    const auto missing = sheller_test::temp_path("sheller_unpack_cli_missing_sample");
    fs::remove(missing);
    const auto cap = sheller_test::temp_path("sheller_unpack_cli_hint.txt");
    const auto run = [&](const std::string& args) {
        const std::string cmd = std::string(kCliCommand) + " unpack \"" + missing.string() + "\" " +
                                args + " > \"" + cap.string() + "\" 2>&1";
        const auto rc = std::system(cmd.c_str());
        return std::pair{rc, read_file(cap)};
    };

    // No budget, no timeout: the wall clock is the 30 s default and the hint
    // names it before the run starts. The missing sample keeps this cheap.
    const auto [rc, output] = run("");
    EXPECT_NE(rc, 0) << output;
    EXPECT_NE(output.find("no -b/--budget given"), std::string::npos) << output;
    EXPECT_NE(output.find("default 30000 ms wall clock"), std::string::npos) << output;

    // An explicit budget silences the hint; an explicit timeout is reported
    // as the requested value instead of the default.
    const auto [budget_rc, budget_output] = run("-b 1M");
    EXPECT_NE(budget_rc, 0) << budget_output;
    EXPECT_EQ(budget_output.find("no -b/--budget given"), std::string::npos) << budget_output;

    const auto [timeout_rc, timeout_output] = run("--timeout-ms 5000");
    EXPECT_NE(timeout_rc, 0) << timeout_output;
    EXPECT_NE(timeout_output.find("requested 5000 ms wall clock"), std::string::npos)
        << timeout_output;

    // --stop xfer= does not move the default: the same short wall clock is named.
    const auto [xfer_rc, xfer_output] = run("--stop xfer=1");
    EXPECT_NE(xfer_rc, 0) << xfer_output;
    EXPECT_NE(xfer_output.find("default 30000 ms wall clock"), std::string::npos) << xfer_output;
}

TEST(UnpackCli, XferStopReachesTheOepTransfer)
{
    namespace fs = std::filesystem;
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_unpack_cli_xfer");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto out = dir / "packed_xfer.unp";
    const auto cap = dir / "cli.out";
    // The UPX stub decompresses millions of blocks before the OEP jump, so
    // the acceptance command gives the instruction budget explicitly.
    const std::string cmd = std::string(kCliCommand) + " unpack \"" + sample.string() + "\" -o \"" +
                            out.string() + "\" --stop xfer=1 -b 50M --timeout-ms 300000";
    const std::string full = cmd + " > \"" + cap.string() + "\" 2>&1";
    const auto rc = std::system(full.c_str());
    const std::string output = read_file(cap);

    EXPECT_EQ(rc, 0) << output;
    EXPECT_NE(output.find("xfer target reached (xfers=1)"), std::string::npos) << output;
    EXPECT_NE(output.find("terminated=0"), std::string::npos) << output;
    ASSERT_TRUE(fs::exists(out)) << output;
    EXPECT_TRUE(fs::exists(out.string() + ".report.json")) << output;
}

TEST(UnpackCli, XferMissPrintsTheHintAndStillUnpacks)
{
    namespace fs = std::filesystem;
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_unpack_cli_xfer_miss");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto out = dir / "packed_xfer_miss.unp";
    const auto cap = dir / "cli.out";
    const std::string cmd = std::string(kCliCommand) + " unpack \"" + sample.string() + "\" -o \"" +
                            out.string() + "\" --stop xfer=5 -b 50M --timeout-ms 300000";
    const std::string full = cmd + " > \"" + cap.string() + "\" 2>&1";
    const auto rc = std::system(full.c_str());
    const std::string output = read_file(cap);

    EXPECT_EQ(rc, 0) << output;
    EXPECT_NE(output.find("xfer target 5 not reached (xfers=1)"), std::string::npos) << output;
    ASSERT_TRUE(fs::exists(out)) << output;
}

TEST(UnpackCli, EspXferStopStampsTheOepEntry)
{
    // The unpacking stop: armed on the confirmed restore, stopped at the
    // delivery transfer - the OEP candidate the repair stamps into the
    // written image's entry point. The RVA is the plain-unpack reference
    // value for this corpus (the payload's own entry, verified against the
    // acceptance image).
    namespace fs = std::filesystem;
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_unpack_cli_esp_xfer");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto out = dir / "packed_esp_xfer.unp";
    const auto cap = dir / "cli.out";
    const std::string cmd = std::string(kCliCommand) + " unpack \"" + sample.string() + "\" -o \"" +
                            out.string() + "\" --stop esp+xfer -b 50M --timeout-ms 300000";
    const std::string full = cmd + " > \"" + cap.string() + "\" 2>&1";
    const auto rc = std::system(full.c_str());
    const std::string output = read_file(cap);

    EXPECT_EQ(rc, 0) << output;
    EXPECT_NE(output.find("esp target armed; xfer target reached (xfers=1)"), std::string::npos)
        << output;
    EXPECT_NE(output.find("(rva 0x213dc) stamped"), std::string::npos) << output;
    ASSERT_TRUE(fs::exists(out)) << output;
}

TEST(UnpackCli, EspStopWithoutTheArmLeavesTheEntryUnstamped)
{
    // Bare esp stops inside the confirmed restore, before the payload jump:
    // no transfer is observed, no OEP candidate fires, and the written image
    // keeps the stub's entry point - the image is complete and the imports
    // are repaired, but the entry is the caller's job to know (that is what
    // the arm form is for).
    namespace fs = std::filesystem;
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_unpack_cli_esp_bare");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto out = dir / "packed_esp_bare.unp";
    const auto cap = dir / "cli.out";
    const std::string cmd = std::string(kCliCommand) + " unpack \"" + sample.string() + "\" -o \"" +
                            out.string() + "\" --stop esp -b 50M --timeout-ms 300000";
    const std::string full = cmd + " > \"" + cap.string() + "\" 2>&1";
    const auto rc = std::system(full.c_str());
    const std::string output = read_file(cap);

    EXPECT_EQ(rc, 0) << output;
    EXPECT_NE(output.find("esp target reached (stack restore confirmed)"), std::string::npos)
        << output;
    EXPECT_EQ(output.find("stamped"), std::string::npos) << output;
    ASSERT_TRUE(fs::exists(out)) << output;
}

TEST(UnpackCli, ReportOverrideWritesOnlyThere)
{
    namespace fs = std::filesystem;
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_unpack_cli_override");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto out = dir / "packed.exe.unp";
    const auto report = dir / "custom.report.json";

    const auto cmd = std::string(kCliCommand) + " unpack \"" + sample.string() + "\" -o \"" +
                     out.string() + "\" --report \"" + report.string() + "\"";
    const auto cap = dir / "cli.out";
    const std::string full = cmd + " > \"" + cap.string() + "\" 2>&1";
    const auto rc = std::system(full.c_str());
    const std::string output = read_file(cap);

    EXPECT_EQ(rc, 0) << output;
    ASSERT_TRUE(fs::exists(report)) << output;
    EXPECT_FALSE(fs::exists(out.string() + ".report.json")) << output;
    EXPECT_EQ(count_files_ending(dir, ".report.json"), 1U) << output;
    const std::string text = read_file(report);
    EXPECT_NE(text.find("\"events\":{\"counts\":{"), std::string::npos);
    EXPECT_NE(text.find("\"loss\":{\"dropped\":null,\"truncated\":null}"), std::string::npos)
        << text; // default semantic level: no ledger built
    EXPECT_FALSE(fs::exists(out.string() + ".reports")) << output;
}

#ifndef _WIN32

TEST(UnpackCli, RunSampleSavesTheContainerAndReplaysIt)
{
    namespace fs = std::filesystem;
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_run_cli_crafted");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto snap = dir / "run.snap";
    const auto first = dir / "first.report.json";
    const auto second = dir / "second.report.json";
    const auto run = [&](const std::string& args) {
        const auto cap = dir / "cli.out";
        const std::string cmd =
            std::string(kCliCommand) + " " + args + " > \"" + cap.string() + "\" 2>&1";
        const auto rc = std::system(cmd.c_str());
        return std::pair{rc, read_file(cap)};
    };

    const auto [save_rc, save_out] =
        run("run \"" + sample.string() + "\" --save-snapshot \"" + snap.string() +
            "\" --report \"" + first.string() + "\" -b 1M");
    EXPECT_EQ(save_rc, 0) << save_out;
    ASSERT_TRUE(fs::exists(snap)) << save_out;
    // The saved bytes are the executed container and obey the derived bound.
    EXPECT_LE(fs::file_size(snap), sheller::test::kContainerSizeBound);

    const auto [replay_rc, replay_out] = run(
        "run \"" + snap.string() + "\" --from-snapshot --report \"" + second.string() + "\" -b 1M");
    EXPECT_EQ(replay_rc, 0) << replay_out;
    ASSERT_TRUE(fs::exists(second)) << replay_out;
    // The replayed container produces the same report as the construction
    // route: one v1 format, synthetic Ldr semantics rebuilt from the bytes.
    EXPECT_EQ(read_file(first), read_file(second));

    // Without --save-snapshot the pass-through writes no intermediate
    // snapshot anywhere in the output directory.
    const auto plain = dir / "plain";
    fs::create_directories(plain);
    const auto [plain_rc, plain_out] = run("run \"" + sample.string() + "\" --report \"" +
                                           (plain / "r.json").string() + "\" -b 1M");
    EXPECT_EQ(plain_rc, 0) << plain_out;
    for (const auto& entry : fs::directory_iterator(plain)) {
        EXPECT_FALSE(entry.path().filename().string().ends_with(".snap")) << entry.path();
    }
}

TEST(UnpackCli, RunWithoutSyntheticModulesFailsWithExitTwo)
{
    namespace fs = std::filesystem;
    const fs::path cli = fs::current_path() / SHELLER_CLI_FILE_NAME;
    ASSERT_TRUE(fs::exists(cli)) << cli;
    const auto dir = sheller_test::temp_path("sheller_run_cli_nosynth");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto copied = dir / SHELLER_CLI_FILE_NAME;
    fs::copy_file(cli, copied, fs::copy_options::overwrite_existing);
    const auto cap = dir / "out.txt";
    const std::string cmd = std::string(kCliCommand).substr(0, 0) + "\"" + copied.string() +
                            "\" run \"" + std::string(SHELLER_SAMPLE_PACKED_PATH) + "\" > \"" +
                            cap.string() + "\" 2>&1";
    const auto rc = std::system(cmd.c_str());
    ASSERT_TRUE(WIFEXITED(rc));
    EXPECT_EQ(WEXITSTATUS(rc), 2);
    const std::string output = read_file(cap);
    EXPECT_NE(output.find("synthetic modules not found"), std::string::npos) << output;
}

TEST(UnpackCli, X86SampleInputIsRejectedExplicitly)
{
    namespace fs = std::filesystem;
    const fs::path sample = fs::path(SYNTH_MODULE_DIR) / "ntdll.x86.dll";
    ASSERT_TRUE(fs::exists(sample)) << sample.string();
    const auto dir = sheller_test::temp_path("sheller_x86_cli");
    fs::remove_all(dir);
    fs::create_directories(dir);
    const auto run = [&](const std::string& args) {
        const auto cap = dir / "cli.out";
        const std::string cmd =
            std::string(kCliCommand) + " " + args + " > \"" + cap.string() + "\" 2>&1";
        const auto rc = std::system(cmd.c_str());
        return std::pair{rc, read_file(cap)};
    };

    const auto report = dir / "x86.report.json";
    const auto [run_rc, run_out] =
        run("run \"" + sample.string() + "\" --report \"" + report.string() + "\"");
    EXPECT_NE(run_rc, 0) << run_out;
    EXPECT_NE(run_out.find("32-bit sample input"), std::string::npos) << run_out;
    ASSERT_TRUE(fs::exists(report)) << run_out;
    EXPECT_NE(read_file(report).find("\"counts\":{}"), std::string::npos);

    const auto out = dir / "x86.unp";
    const auto [unpack_rc, unpack_out] =
        run("unpack \"" + sample.string() + "\" -o \"" + out.string() + "\"");
    EXPECT_NE(unpack_rc, 0) << unpack_out;
    EXPECT_NE(unpack_out.find("32-bit sample input"), std::string::npos) << unpack_out;
    EXPECT_FALSE(fs::exists(out));
    EXPECT_FALSE(fs::exists(out.string() + ".report.json"));

    // The same sample on a CLI without the synthetic directory fails on the
    // other condition, with different text: the two are distinguishable.
    const fs::path cli = fs::current_path() / SHELLER_CLI_FILE_NAME;
    const auto bare = dir / "bare";
    fs::create_directories(bare);
    const auto copied = bare / SHELLER_CLI_FILE_NAME;
    fs::copy_file(cli, copied, fs::copy_options::overwrite_existing);
    const auto cap = bare / "out.txt";
    const std::string cmd = "\"" + copied.string() + "\" run \"" + sample.string() + "\" > \"" +
                            cap.string() + "\" 2>&1";
    const auto rc = std::system(cmd.c_str());
    EXPECT_NE(rc, 0);
    const std::string missing_out = read_file(cap);
    EXPECT_NE(missing_out.find("synthetic modules not found"), std::string::npos) << missing_out;
    EXPECT_EQ(missing_out.find("32-bit sample input"), std::string::npos) << missing_out;
}

#endif // !_WIN32

// --stop goal family on the unpack face: the parse-level failure faces never
// reach a run, so they hold everywhere; the goals themselves are the run
// face's (covered by cli_run_test with the portable fixtures).
TEST(UnpackCli, StopGoalFailureFacesAreUsageErrors)
{
    const auto run = [](const std::string& args) {
        const auto cap = sheller_test::temp_path("sheller_unpack_cli_stop.txt");
        const std::string cmd =
            std::string(kCliCommand) + " " + args + " > \"" + cap.string() + "\" 2>&1";
        const auto rc = std::system(cmd.c_str());
        return std::pair{rc, read_file(cap)};
    };

    // a typo'd goal and a non-integer after `xfer=`
    const auto typo = run("unpack sheller_missing_sample.exe --stop eps");
    EXPECT_NE(typo.first, 0) << typo.second;
    EXPECT_NE(typo.second.find("expected a stop goal: xfer=<n>, esp or esp+xfer"),
              std::string::npos)
        << typo.second;
    const auto nonint = run("unpack sheller_missing_sample.exe --stop xfer=abc");
    EXPECT_NE(nonint.first, 0) << nonint.second;
    EXPECT_NE(nonint.second.find("expected a stop goal: xfer=<n>, esp or esp+xfer"),
              std::string::npos)
        << nonint.second;

    // the sugar spelling retired: the option is an unknown argument, the same
    // face the retired --timeline spelling gets on the run subcommand
    const auto retired = run("unpack sheller_missing_sample.exe --xfer 1");
    EXPECT_NE(retired.first, 0) << retired.second;
    EXPECT_NE(retired.second.find("--xfer"), std::string::npos) << retired.second;

    // two --stop goals in one invocation
    const auto mutex = run("unpack sheller_missing_sample.exe --stop esp --stop esp+xfer");
    EXPECT_NE(mutex.first, 0) << mutex.second;

    // the subcommand's own help names all three goals
    const auto help = run("unpack --help");
    EXPECT_EQ(help.first, 0) << help.second;
    EXPECT_NE(help.second.find("xfer=<n>"), std::string::npos) << help.second;
    EXPECT_NE(help.second.find("esp+xfer"), std::string::npos) << help.second;
}

} // namespace
