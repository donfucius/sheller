// Shared interface library smoke: the dynamic route. This target links
// sheller_shared and nothing else from the core, and includes public headers
// only - so every name it touches crossed a real library boundary. The CLI
// subprocess suites prove the library loads; only a direct call proves a symbol
// is exported and callable, on both platforms.
//
// Inputs are split by purpose. The synthetic golden is the snapshot-format
// sentinel negative sample, not a runnable input (its 16-byte region trips the
// engine's 4KB mapping gate), and snapshot::Writer is not exported, so this
// side cannot craft a snapshot at all. What it can do:
//   * drive all six entries and read their failure mapping - portable, no
//     corpus needed (the three negative samples below);
//   * drive a real run through the exports - Windows chains capture::run into
//     analyze over the hello sample; elsewhere the loader route against the
//     generated synthetic modules, which are mandatory there: without them the
//     run fails as a capture-class error, a shape that reads exactly like a
//     platform boundary and would hide a real link/visibility defect. There is
//     no portable snapshot to craft on the non-Windows side, so the positive
//     there is the loader run itself: `unpack_sample` lands a .unp, while
//     `analyze` - which has no dump stage to absorb the corpus's crash stop -
//     reports that stop as a run failure carrying its stats.
//
// The log face is checked through its round trip: the export set carries the
// setter only (log::write and the level helpers stay internal to the static
// core), the engine raises one kDebug record at the start of every run
// (src/engine/run.cpp, where both run routes converge), and the record has to
// cross back out to the sink the *host* installed through the DLL. That record
// is the only diagnostic the library raises today; this is the seam that proves
// the sink state lives on this side of the boundary.

#include <sheller/analysis.h>
#include <sheller/capture.h>
#include <sheller/export.h>
#include <sheller/log.h>
#include <sheller/version.h>

#include <gtest/gtest.h>

#include "test_temp.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <format>
#include <fstream>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace {

namespace fs = std::filesystem;

// The six product entries as function pointers. Resolving them at all is part
// of the check: a SHELLER_API that expands to nothing on one platform turns
// this target into a link error rather than a green skip.
using PathAnalyze = std::expected<sheller::AnalysisArtifacts, sheller::AnalysisFailure> (*)(
    const fs::path&, const sheller::AnalysisOptions&);
using BytesAnalyze = std::expected<sheller::AnalysisArtifacts, sheller::AnalysisFailure> (*)(
    const std::vector<std::uint8_t>&, const sheller::AnalysisOptions&);
using UnpackEntry = sheller::UnpackOutcome (*)(const fs::path&, const sheller::UnpackOptions&);
using CaptureEntry = sheller::capture::Result (*)(const sheller::capture::Options&);
using SinkEntry = void (*)(sheller::log::sink, sheller::log::level);
using VersionEntry = std::string_view (*)();

const PathAnalyze path_analyze = &sheller::analyze;
const BytesAnalyze bytes_analyze = &sheller::analyze;
const UnpackEntry unpack_entry = &sheller::unpack_sample;
const CaptureEntry capture_entry = &sheller::capture::run;
const SinkEntry sink_entry = &sheller::log::set_sink;
const VersionEntry version_entry = &sheller::unicorn_version_string;

sheller::AnalysisOptions snapshot_options()
{
    sheller::AnalysisOptions options;
    options.input_kind = sheller::AnalysisInputKind::kSnapshot;
    return options;
}

// "major.minor" as the runtime query spells it - a shape check, not a pin: the
// linked unicorn version moves with the vcpkg manifest.
bool looks_like_major_minor(const std::string_view value)
{
    const auto dot = value.find('.');
    if (dot == std::string_view::npos || dot == 0 || dot + 1 >= value.size()) {
        return false;
    }
    return std::all_of(value.begin(), value.end(),
                       [](const char c) { return c == '.' || (c >= '0' && c <= '9'); });
}

} // namespace

// All six resolve and answer on both platforms: a platform capability difference
// shows up in return values, never as a link or load failure.
TEST(SharedApi, SixEntriesResolveAndAnswer)
{
    const auto version = version_entry();
    EXPECT_TRUE(looks_like_major_minor(version)) << version;

    // Forced snapshot routing: an unreadable file is a snapshot-IO failure. On
    // kAuto the same path goes to the sample route and answers kCapture (a
    // missing input is not provably a snapshot) - MissingSnapshotPathIsSnapshotIo
    // and the auto-route face are pinned separately below.
    const auto options = snapshot_options();
    const auto missing = sheller_test::temp_path("sheller_shared_api_test") / "absent.snap";
    const auto by_path = path_analyze(missing, options);
    ASSERT_FALSE(by_path.has_value());
    EXPECT_EQ(by_path.error().kind, sheller::AnalysisFailure::Kind::kSnapshotIo);

    const sheller::AnalysisOptions auto_options;
    const std::vector<std::uint8_t> not_a_snapshot{'M', 'Z', 0x90, 0x00};
    const auto by_bytes = bytes_analyze(not_a_snapshot, auto_options);
    ASSERT_FALSE(by_bytes.has_value());
    EXPECT_EQ(by_bytes.error().kind, sheller::AnalysisFailure::Kind::kCapture);

    const auto dir = sheller_test::temp_path("sheller_shared_api_test");
    fs::create_directories(dir);
    sheller::UnpackOptions unpack_options;
    unpack_options.output = dir / "absent.unp";
    const auto unpacked = unpack_entry(dir / "definitely_absent.exe", unpack_options);
    ASSERT_TRUE(unpacked.failure.has_value());
    EXPECT_EQ(unpacked.failure->kind, sheller::AnalysisFailure::Kind::kCapture);

    sheller::capture::Options capture_options;
    capture_options.sample_path = dir / "definitely_absent.exe";
    capture_options.output_path = dir / "absent.snap";
    const auto captured = capture_entry(capture_options);
#ifndef _WIN32
    // The platform boundary is a refusal with a reason, not a crash and not an
    // empty result: the other five entries above already proved usable.
    EXPECT_EQ(captured.status, sheller::capture::Status::kUnsupportedPlatform);
    EXPECT_FALSE(captured.detail.empty());
#else
    EXPECT_EQ(captured.status, sheller::capture::Status::kSampleNotFound);
    EXPECT_FALSE(captured.detail.empty());
#endif

    // The setter is the log half of the export face; installing a sink must not
    // disturb the rest. The bytes entry above never reaches a run (non-snapshot
    // bytes are refused before the engine starts), so it stays silent here by
    // construction - the round trip is LogSinkInstalledThroughTheExport... below.
    sink_entry([](sheller::log::level, std::string_view) {}, sheller::log::level::kDebug);
    const auto after_sink = bytes_analyze(not_a_snapshot, auto_options);
    ASSERT_FALSE(after_sink.has_value());
    EXPECT_EQ(after_sink.error().kind, sheller::AnalysisFailure::Kind::kCapture);
    sink_entry({}, sheller::log::level::kWarning); // back to the silent default
}

// The state self-consistency check behind the one-binary-one-route rule, made
// assertable by the one diagnostic the engine raises: install a sink through the
// exported setter, run the route this host has, and read the record back. The
// emitter lives inside this library (run.cpp, statically linked in here) and the
// threshold it checks is the same process-global the exported setter writes - a
// binary carrying two copies of that state, the shape the rule forbids, would go
// empty here.
namespace {
// The sink is process-global and the recording lambda below captures a local: an
// early return between install and restore (any ASSERT_*) would leave the state
// pointing into a dead frame, and every later case in this binary would write
// through it. Restoring from a destructor makes that unreachable.
struct silent_on_exit {
    silent_on_exit() = default;
    silent_on_exit(const silent_on_exit&) = delete;
    silent_on_exit& operator=(const silent_on_exit&) = delete;
    ~silent_on_exit()
    {
        sheller::log::set_sink({}, sheller::log::level::kWarning);
    }
};
} // namespace

TEST(SharedApi, LogSinkInstalledThroughTheExportReceivesEngineRecords)
{
    sheller::AnalysisOptions options;
#ifdef _WIN32
    const fs::path sample = SHELLER_SAMPLE_HELLO_PATH;
#else
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    options.run.max_instructions = 0; // unbounded: see the loader-route case
    options.run.synthetic_system_modules = true;
    options.run.synthetic_module_dir = SYNTH_MODULE_DIR;
#endif
    ASSERT_TRUE(fs::exists(sample)) << sample.string();

    std::vector<std::string> records;
    sheller::log::set_sink(
        [&](const sheller::log::level sev, const std::string_view message) {
            records.push_back(std::format("{} {}", static_cast<int>(sev), message));
        },
        sheller::log::level::kDebug);
    const silent_on_exit restore;

    // What this case pins is the record, not the run verdict: the analyze faces
    // are pinned by their own tests above and below.
    static_cast<void>(sheller::analyze(sample, options));

    const auto start = std::ranges::find_if(records, [](const std::string& record) {
        return record.find("engine run start") != std::string::npos;
    });
    ASSERT_NE(start, records.end()) << "records seen: " << records.size();
    // kDebug is level 0: the level and the threshold both crossed the boundary
    // intact, not just the text.
    EXPECT_TRUE(start->starts_with("0 ")) << *start;
    EXPECT_NE(start->find("entry=0x"), std::string::npos) << *start;
    // One record per run: the emitter sits at the point where both run routes
    // converge, so a second one would mean the guest was entered twice.
    EXPECT_EQ(std::ranges::count(records, *start), 1);
}

// The three portable negative faces: the failure kinds must survive the export
// boundary unchanged (the facade's mapping, reached through the product names).
TEST(SharedApi, GoldenSentinelIsRejectedAsSnapshotIo)
{
    sheller::AnalysisOptions options;
    const auto result = sheller::analyze(fs::path(SHELLER_FACADE_GOLDEN), options);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kSnapshotIo);
    EXPECT_NE(result.error().message.find("4KB"), std::string::npos);
}

TEST(SharedApi, NonSnapshotBytesAreRefused)
{
    sheller::AnalysisOptions options;
    const std::vector<std::uint8_t> garbage{0xDE, 0xAD, 0xBE, 0xEF};
    const auto result = sheller::analyze(garbage, options);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kCapture);
}

TEST(SharedApi, MissingSnapshotPathIsSnapshotIo)
{
    const auto options = snapshot_options();
    const auto missing = sheller_test::temp_path("sheller_shared_api_test") / "nope.snap";
    const auto result = sheller::analyze(missing, options);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kSnapshotIo);
}

#ifndef _WIN32

// Construction is the only way a non-Windows host runs a fresh sample, and it
// needs the synthetic system modules: without them the run fails as a
// capture-class error, a shape that reads exactly like a platform boundary and
// would hide a real defect in the export face.
TEST(SharedApi, AnalyzeSampleThroughTheLoaderRouteExecutes)
{
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    const fs::path synth = SYNTH_MODULE_DIR;
    ASSERT_TRUE(fs::exists(sample)) << sample.string();
    ASSERT_TRUE(fs::exists(synth)) << "synthetic modules not generated: " << synth.string();

    sheller::AnalysisOptions options;
    // Unbounded instruction budget (0): the same shape the unpack face runs,
    // and the documented end of this route is the crash stop, not a budget
    // expiry - at the 1M default this input stops with "budget expired"
    // (measured), which would test the wrong boundary.
    options.run.max_instructions = 0;
    options.run.synthetic_system_modules = true;
    options.run.synthetic_module_dir = synth;
    const auto result = sheller::analyze(sample, options);
    // The guest crashing here is the corpus's expected shape on the synthetic
    // stubs (an unmodeled spot, not a defect of this route): the packed
    // payload's post-OEP CRT init faults. What differs between the two entries
    // is who absorbs the stop - analyze has no dump stage, so a non-terminating
    // run is a run failure carrying the partial stats; unpack_sample keeps going
    // when the run left a dump to repair (src/api/unpack.cpp only fails as kRun
    // if the manifest is missing), which is why the same stop lands a .unp
    // below. Both sides are pinned here on purpose: what this case proves is
    // that the engine really ran across the library boundary (millions of
    // blocks, the crash named, artifacts attached) rather than refusing at a
    // platform edge.
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kRun);
    EXPECT_NE(result.error().message.find("crashed"), std::string::npos) << result.error().message;
    ASSERT_TRUE(result.error().run.has_value());
    EXPECT_GT(result.error().run->stats.blocks, 0U);
    EXPECT_FALSE(result.error().run->stats.terminated);
    // The container probe feeds the behavior tier: this route is no longer
    // the zero-signal boundary, so artifacts are instrumented even though the
    // run itself ends in the payload's post-OEP crash.
    EXPECT_TRUE(result.error().artifacts.instrumented);
}

TEST(SharedApi, UnpackSampleThroughTheLoaderRoute)
{
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    const fs::path synth = SYNTH_MODULE_DIR;
    ASSERT_TRUE(fs::exists(sample));
    ASSERT_TRUE(fs::exists(synth));

    const auto dir = sheller_test::temp_path("sheller_shared_api_test");
    fs::create_directories(dir);
    sheller::UnpackOptions options;
    options.output = dir / "packed_linux.unp";
    options.synthetic_module_dir = synth;
    const auto outcome = sheller::unpack_sample(sample, options);
    ASSERT_FALSE(outcome.failure.has_value()) << outcome.failure->message;
    ASSERT_TRUE(fs::exists(options.output));
    std::ifstream unp(options.output, std::ios::binary);
    char magic[2] = {};
    unp.read(magic, 2);
    EXPECT_EQ(std::string_view(magic, 2), "MZ");
    EXPECT_TRUE(outcome.artifacts.instrumented);
}

TEST(SharedApi, CaptureRunRefusesOffWindows)
{
    const auto dir = sheller_test::temp_path("sheller_shared_api_test");
    sheller::capture::Options options;
    options.sample_path = fs::path(SHELLER_SAMPLE_PACKED_PATH);
    options.output_path = dir / "refused.snap";
    const auto result = sheller::capture::run(options);
    EXPECT_EQ(result.status, sheller::capture::Status::kUnsupportedPlatform);
    EXPECT_NE(result.detail.find("Windows"), std::string::npos) << result.detail;
    EXPECT_FALSE(fs::exists(options.output_path));
}

#else

// Two exports chained: the product surface has to carry a real run end to end,
// not only its failure mapping. capture::run writes the snapshot, analyze reads
// it back - hello sample, the same corpus capture_syscall_sample feeds the
// static-side suites.
TEST(SharedApi, CaptureRunThenAnalyzePathLandsArtifacts)
{
    const auto dir = sheller_test::temp_path("sheller_shared_api_test");
    fs::create_directories(dir);
    const auto snapshot = dir / "hello.snap";

    sheller::capture::Options capture_options;
    capture_options.sample_path = SHELLER_SAMPLE_HELLO_PATH;
    capture_options.output_path = snapshot;
    const auto captured = sheller::capture::run(capture_options);
    ASSERT_EQ(captured.status, sheller::capture::Status::kOk) << captured.detail;
    ASSERT_TRUE(fs::exists(snapshot));

    sheller::AnalysisOptions options;
    const auto result = sheller::analyze(snapshot, options);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    ASSERT_TRUE(result->run_stats.has_value());
    EXPECT_TRUE(result->run_stats->terminated);
}

// Real capture cost: unpack_sample spawns packed.exe under the loader before
// replaying it, so this is a seconds-scale case - the same expense
// unpack_cli_test already carries, and ctest runs it in parallel with the rest.
TEST(SharedApi, UnpackSampleProducesAnUnpackedImage)
{
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    ASSERT_TRUE(fs::exists(sample)) << sample.string();

    const auto dir = sheller_test::temp_path("sheller_shared_api_test");
    fs::create_directories(dir);
    sheller::UnpackOptions options;
    options.output = dir / "packed.unp";
    const auto outcome = sheller::unpack_sample(sample, options);
    ASSERT_FALSE(outcome.failure.has_value()) << outcome.failure->message;
    ASSERT_TRUE(fs::exists(options.output));
    std::ifstream unp(options.output, std::ios::binary);
    char magic[2] = {};
    unp.read(magic, 2);
    EXPECT_EQ(std::string_view(magic, 2), "MZ");
}

#endif

// Concurrent calls across the boundary. The static core's own concurrency
// case is tests/concurrency_test.cpp; what this adds is the path through the shared
// library: several threads unpacking at once while two more replace the process-wide
// log sink under them. That mixture is the contract's awkward corner - the sink state
// is one mutex-guarded object reached from both sides of the DLL - so the run threads
// write records while the sink threads swap the callback they would be written to.
//
// What is asserted is shape, not content: every unpack produced an image, the version
// entry still answers afterwards, and the process is still here to say so. A corrupted
// sink install or a torn record shows up as a hang or a crash, which is the failure
// this case exists to catch.
TEST(SharedApi, ConcurrentUnpacksUnderAChurningSink)
{
    constexpr int kRunners = 4;
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    ASSERT_TRUE(fs::exists(sample)) << sample.string();

    std::atomic<int> images{0};
    std::atomic<int> installs{0};
    std::atomic<bool> stop{false};
    std::mutex error_mutex;
    std::string last_error;

    std::vector<std::thread> sinkers;
    sinkers.reserve(2);
    for (int i = 0; i < 2; ++i) {
        sinkers.emplace_back([&] {
            while (!stop.load()) {
                sink_entry([](sheller::log::level, std::string_view) {},
                           sheller::log::level::kDebug);
                ++installs;
                std::this_thread::sleep_for(std::chrono::microseconds(200));
            }
        });
    }

    std::vector<std::thread> runners;
    runners.reserve(kRunners);
    for (int i = 0; i < kRunners; ++i) {
        runners.emplace_back([&, i] {
            const auto dir =
                sheller_test::temp_path("sheller_shared_api_test") / ("conc_" + std::to_string(i));
            std::error_code ec;
            fs::create_directories(dir, ec);
            sheller::UnpackOptions options;
            options.output = dir / "packed.unp";
            options.synthetic_module_dir = SYNTH_MODULE_DIR;
            const auto outcome = unpack_entry(sample, options);
            if (outcome.failure.has_value()) {
                std::lock_guard<std::mutex> lock(error_mutex);
                last_error = outcome.failure->message;
                return;
            }
            std::error_code size_ec;
            if (fs::file_size(options.output, size_ec) > 0) {
                ++images;
            }
        });
    }
    for (auto& runner : runners) {
        runner.join();
    }
    stop.store(true);
    for (auto& sinker : sinkers) {
        sinker.join();
    }

    {
        std::lock_guard<std::mutex> lock(error_mutex);
        EXPECT_EQ(images.load(), kRunners) << last_error;
    }
    // The sink threads were running while the unpacks logged, so a zero here would
    // mean the churn never happened and the case proved nothing about it.
    EXPECT_GT(installs.load(), 0);
    EXPECT_TRUE(looks_like_major_minor(version_entry()));
}
