// Analysis facade tests: direct sheller_api linkage over the portable
// routes. The synthetic golden snapshot and the crafted in-test snapshots
// cover the CI-runnable face: magic routing, the three failure kinds, the
// semantic tier, the timeline tier (with real ring eviction on the spin
// fixture), the host subscription (mask + throw guard), the facade-owned
// sink slots, and the guest-output discard default - the last one at the
// facade and at the engine entry (run_snapshot_syscalls) side by side, because
// the engine is where the default lives and the facade is allowed to hand it a
// sink. The capture-route faces (sample analysis, save_snapshot, unpack) are
// Windows-gated; the local corpus assertions live in the EXCLUDE_FROM_ALL
// analysis_facade_local_corpus target (see tests/README.md).

// _dup/_open on Windows carry nonstandard-name deprecation notes, and the
// host-stream fixture in tests/host_stream_capture.h is the fd dance that needs
// them silenced. Its defines must precede every include (gtest pulls <io.h> first
// on Windows), which is why they sit here rather than only inside that header.
#ifdef _WIN32
#define _CRT_NONSTDC_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "log_detail.h"
#include "wiring.h"

#include "container_size_bound.h"
#include <sheller/analysis.h>
#include <sheller/events.h>
#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include "host_stream_capture.h"
#include "test_temp.hpp"

#include "snapshot_fixture.h"
#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <utility>
#include <vector>

namespace {

namespace facade = sheller::api::detail;
namespace fs = std::filesystem;

// The crafted-snapshot fixture now lives in tests/snapshot_fixture.h (shared with
// tests/engine_trace_test.cpp); these declarations keep the names unqualified here.
using sheller_test::craft_snapshot;
using sheller_test::fixture_metadata;
using sheller_test::fixture_registers;
using sheller_test::kBufferVa;
using sheller_test::kFixtureRflags;
using sheller_test::kImageBase;
using sheller_test::kMemImage;
using sheller_test::kMemPrivate;
using sheller_test::kPageExecuteReadwrite;
using sheller_test::kPageReadwrite;
using sheller_test::kRegionSize;
using sheller_test::kStackRegionBase;
using sheller_test::kStackVa;
using sheller_test::kTerminateCode;
using sheller_test::kTwoWriteCode;
using sheller_test::kWriteCode;
using sheller_test::StandardStreamCapture;
using sheller_test::terminate_snapshot;
using sheller_test::two_write_buffer;
using sheller_test::two_write_snapshot_bytes;
using sheller_test::write_snapshot_bytes;

} // namespace

namespace {

struct DecodedEvent {
    sheller::EventTypeId type{};
    sheller::EventPreamble preamble{};
};

std::vector<DecodedEvent> decode_tlv(const std::vector<std::uint8_t>& tlv)
{
    std::vector<DecodedEvent> events;
    std::size_t cursor = 0;
    while (cursor < tlv.size()) {
        const auto view = sheller::read_event(std::span<const std::uint8_t>{tlv}.subspan(cursor));
        if (!view.has_value()) {
            ADD_FAILURE() << "malformed TLV stream at byte " << cursor;
            break;
        }
        const auto preamble = sheller::read_preamble(view->payload);
        if (!preamble.has_value()) {
            ADD_FAILURE() << "malformed TLV preamble at byte " << cursor;
            break;
        }
        events.push_back({view->type, *preamble});
        cursor += view->total_size;
    }
    return events;
}

} // namespace

// ---- name-table attribution (public resolvers) ---------------------------

TEST(NameTableAttribution, RegionClassesModulesAndSections)
{
    // The single attribution implementation, shared by the artifacts the
    // library fills (SemanticEvent::from_module / to_module / api_module,
    // StubCall::module_name) and whatever a host renders from the timeline
    // tier. The region-class sentinel segment renders the class in both tiers
    // (snapshot 0xFF0x and runtime 0xFF1x share the name), unclassified slots
    // (0xFF00, the legacy 0xFFFF) and out-of-range indexes fall back to
    // "runtime", and below the segment the wire grid holds: index 0 is the
    // headers pseudo-section, index 1 the first real section.
    sheller::TimelineNameTable names;
    names.modules = {"sample.exe"};
    names.sections = {{"headers", ".text"}};
    EXPECT_EQ(sheller::module_name_of(names, 0xFF01), "private-exec");
    EXPECT_EQ(sheller::module_name_of(names, 0xFF11), "private-exec");
    EXPECT_EQ(sheller::module_name_of(names, 0xFF02), "private-data");
    EXPECT_EQ(sheller::module_name_of(names, 0xFF12), "private-data");
    EXPECT_EQ(sheller::module_name_of(names, 0xFF03), "mapped");
    EXPECT_EQ(sheller::module_name_of(names, 0xFF13), "mapped");
    EXPECT_EQ(sheller::module_name_of(names, 0xFF00), "runtime");
    EXPECT_EQ(sheller::module_name_of(names, 0xFFFF), "runtime");
    EXPECT_EQ(sheller::module_name_of(names, 0), "sample.exe");
    EXPECT_EQ(sheller::module_name_of(names, 0x7FFF), "runtime");
    // Sentinel landings render bare: the class is the whole attribution, no
    // module!section composite (whatever the section slot carries).
    EXPECT_EQ(sheller::section_name_of(names, 0xFF11, 0xFFFF), "private-exec");
    EXPECT_EQ(sheller::section_name_of(names, 0xFF12, 0x1234), "private-data");
    EXPECT_EQ(sheller::section_name_of(names, 0xFF13, 0xFFFF), "mapped");
    EXPECT_EQ(sheller::section_name_of(names, 0xFF00, 0xFFFF), "runtime");
    EXPECT_EQ(sheller::section_name_of(names, 0, 0), "sample.exe!headers");
    EXPECT_EQ(sheller::section_name_of(names, 0, 1), "sample.exe!.text");
    EXPECT_EQ(sheller::section_name_of(names, 0, 0xFFFF), "sample.exe!runtime");
    EXPECT_EQ(sheller::section_name_of(names, 0x7FFF, 0), "runtime");
}

TEST(NameTableAttribution, SentinelAndOutOfRangeIndexesKeepNameShapedSpellings)
{
    // The contract StubCall::module_name rides on: a sentinel or out-of-range
    // index resolves to a spelling, never to an empty string a host would have
    // to substitute - which is how the report's "module!name" keys once
    // degraded to the raw index. Swept over the whole u16 index space because
    // the segments are index-range rules, not per-index cases.
    sheller::TimelineNameTable names;
    names.modules = {"sample.exe", "kernel32.dll"};
    names.sections = {{"headers", ".text"}, {"headers"}};
    const sheller::TimelineNameTable bare;
    for (std::uint32_t wide = 0; wide < 0x10000; ++wide) {
        const auto index = static_cast<std::uint16_t>(wide);
        EXPECT_FALSE(sheller::module_name_of(names, index).empty()) << index;
        EXPECT_FALSE(sheller::module_name_of(bare, index).empty()) << index;
        EXPECT_FALSE(sheller::section_name_of(names, index, 0).empty()) << index;
    }
}

// ---- routing ------------------------------------------------------

TEST(AnalysisFacade, SnapshotBytesReplayAndCarryArtifacts)
{
    sheller::AnalysisOptions options;
    const auto result = facade::analyze_bytes_impl(terminate_snapshot(), options);
    ASSERT_TRUE(result.has_value());
    const auto& artifacts = result.value();
    EXPECT_TRUE(artifacts.instrumented);
    EXPECT_TRUE(artifacts.note.empty());
    ASSERT_TRUE(artifacts.run_stats.has_value());
    EXPECT_TRUE(artifacts.run_stats->terminated);
    EXPECT_EQ(artifacts.run_stats->exit_code, 0x1234u);
    // Semantic tier: the single guest-contract terminate syscall in
    // function form with its resolved synthetic mnemonic. The syscall is no
    // longer necessarily the last record - a judgment emitted for it lands
    // after it - so find it by type.
    ASSERT_GE(artifacts.semantic_events.size(), 1u);
    EXPECT_EQ(artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kSyscall)], 1u);
    const sheller::SemanticEvent* last_syscall = nullptr;
    for (const auto& event : artifacts.semantic_events) {
        if (event.type == sheller::EventTypeId::kSyscall) {
            last_syscall = &event;
        }
    }
    ASSERT_NE(last_syscall, nullptr);
    EXPECT_EQ(last_syscall->syscall_number, 0x1002u);
    EXPECT_EQ(last_syscall->syscall_name, "NtTerminateProcess");
    // Timeline tier was off: nothing built, no artifact.
    EXPECT_TRUE(artifacts.timeline_tlv.empty());
    EXPECT_EQ(artifacts.timeline_dropped, 0u);
}

TEST(AnalysisFacade, SnapshotFileInputRoutesOnMagic)
{
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    const auto path = dir / "terminate.snap";
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(terminate_snapshot().data()),
              static_cast<std::streamsize>(terminate_snapshot().size()));
    out.close();

    sheller::AnalysisOptions options;
    const auto result = facade::analyze_path_impl(path, options);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_TRUE(result->instrumented);

    // Forced sample routing on a snapshot file fails as a capture would -
    // it is never second-guessed into a replay.
    sheller::AnalysisOptions forced;
    forced.input_kind = sheller::AnalysisInputKind::kSample;
    const auto mismatch = facade::analyze_path_impl(path, forced);
    ASSERT_FALSE(mismatch.has_value());
    EXPECT_EQ(mismatch.error().kind, sheller::AnalysisFailure::Kind::kCapture);
    EXPECT_NE(mismatch.error().message.find("sample routing was selected"), std::string::npos);
}

TEST(AnalysisFacade, SnapshotFileMissingIsSnapshotIo)
{
    const auto missing = sheller_test::temp_path("sheller_facade_test") / "absent.snap";
    sheller::AnalysisOptions options;
    options.input_kind = sheller::AnalysisInputKind::kSnapshot;
    const auto result = facade::analyze_path_impl(missing, options);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kSnapshotIo);
    EXPECT_FALSE(result.error().artifacts.run_stats.has_value());
}

TEST(AnalysisFacade, PathRouteStreamsAndMatchesBytesRoute)
{
    // W5 net: file inputs go through the engine's streaming reader (no
    // whole-file buffer) and land on the exact same artifacts as the bytes
    // entry - deterministic replay, identical wiring, identical joins.
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    const auto path = dir / "terminate.snap";
    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(terminate_snapshot().data()),
                  static_cast<std::streamsize>(terminate_snapshot().size()));
    }

    sheller::AnalysisOptions options;
    options.timeline = true;
    const auto via_path = facade::analyze_path_impl(path, options);
    const auto via_bytes = facade::analyze_bytes_impl(terminate_snapshot(), options);
    ASSERT_TRUE(via_path.has_value()) << via_path.error().message;
    ASSERT_TRUE(via_bytes.has_value()) << via_bytes.error().message;
    EXPECT_EQ(via_path->instrumented, via_bytes->instrumented);
    EXPECT_EQ(via_path->event_counts, via_bytes->event_counts);
    ASSERT_EQ(via_path->semantic_events.size(), via_bytes->semantic_events.size());
    for (std::size_t i = 0; i < via_path->semantic_events.size(); ++i) {
        EXPECT_EQ(via_path->semantic_events[i].seq, via_bytes->semantic_events[i].seq);
        EXPECT_EQ(via_path->semantic_events[i].wire_seq, via_bytes->semantic_events[i].wire_seq);
        EXPECT_EQ(via_path->semantic_events[i].type, via_bytes->semantic_events[i].type);
    }
    ASSERT_TRUE(via_path->run_stats.has_value());
    ASSERT_TRUE(via_bytes->run_stats.has_value());
    EXPECT_EQ(via_path->run_stats->blocks, via_bytes->run_stats->blocks);
    EXPECT_EQ(via_path->run_stats->syscalls, via_bytes->run_stats->syscalls);
    // The timeline tier joins identically through the streamed route.
    EXPECT_EQ(decode_tlv(via_path->timeline_tlv).size(),
              decode_tlv(via_bytes->timeline_tlv).size());
    EXPECT_EQ(via_path->timeline_dropped, via_bytes->timeline_dropped);
}

TEST(AnalysisFacade, SnapshotBytesInvalidIsSnapshotIo)
{
    std::vector<std::uint8_t> garbage{0xDE, 0xAD, 0xBE, 0xEF};
    sheller::AnalysisOptions options;
    options.input_kind = sheller::AnalysisInputKind::kSnapshot;
    const auto result = facade::analyze_bytes_impl(garbage, options);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kSnapshotIo);
}

TEST(AnalysisFacade, SampleBytesRefusedThisBatch)
{
    // A PE-looking blob is not a snapshot: capture-class failure naming the
    // P1 boundary (the bytes entry takes snapshot bytes only).
    std::vector<std::uint8_t> sample{'M', 'Z', 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04};
    sheller::AnalysisOptions options;
    const auto auto_result = facade::analyze_bytes_impl(sample, options);
    ASSERT_FALSE(auto_result.has_value());
    EXPECT_EQ(auto_result.error().kind, sheller::AnalysisFailure::Kind::kCapture);
    EXPECT_NE(auto_result.error().message.find("snapshot bytes"), std::string::npos);

    sheller::AnalysisOptions forced;
    forced.input_kind = sheller::AnalysisInputKind::kSample;
    const auto forced_result = facade::analyze_bytes_impl(sample, forced);
    ASSERT_FALSE(forced_result.has_value());
    EXPECT_EQ(forced_result.error().kind, sheller::AnalysisFailure::Kind::kCapture);
}

// ---- failure faces --------------------------------------------------

TEST(AnalysisFacade, BudgetExhaustedIsRunFailureWithArtifacts)
{
    // Self-jump spin: every block emits a block-exec event, so the failed
    // run still carries events, counts and partial statistics.
    auto spin = craft_snapshot({0xEB, 0xFE});
    sheller::AnalysisOptions options;
    options.run.max_instructions = 200000;
    const auto result = facade::analyze_bytes_impl(spin, options);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kRun);
    ASSERT_TRUE(result.error().run.has_value());
    EXPECT_EQ(result.error().run->error, sheller::engine::SyscallRunError::kBudgetExhausted);
    EXPECT_GT(
        result.error()
            .artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kBlockExec)],
        0u);
    ASSERT_TRUE(result.error().artifacts.run_stats.has_value());
    EXPECT_FALSE(result.error().artifacts.run_stats->terminated);
}

// ---- burn-loop fast-forward -------------------------------------------

TEST(AnalysisFacade, NestedCounterLoopIsFastForwarded)
{
    // Outer 16 x inner 0x100000 counter loop: without the skip this burns the
    // budget, and the hot ring keeps the outer blocks alongside the inner
    // cycle - the exit block of the inner loop is an outer block, not a ring
    // exit. The probe has to judge the forced exit against the cycle it
    // observed and cache the skip under the block where it proved it.
    std::vector<std::uint8_t> code{
        0x48, 0xC7, 0xC3, 0x10, 0x00, 0x00, 0x00, // mov rbx, 0x10
        0x48, 0xC7, 0xC1, 0x00, 0x00, 0x10, 0x00, // mov rcx, 0x100000
        0x48, 0x8D, 0x49, 0xFF,                   // lea rcx,[rcx-1]
        0x48, 0x85, 0xC9,                         // test rcx,rcx
        0x75, 0xF7,                               // jne inner
        0x48, 0xFF, 0xCB,                         // dec rbx
        0x75, 0xEB,                               // jne outer
    };
    code.insert(code.end(), kTerminateCode.begin(), kTerminateCode.end());
    const auto snapshot = craft_snapshot(code);

    sheller::AnalysisOptions options;
    options.run.max_instructions = 500000;
    const auto result = facade::analyze_bytes_impl(snapshot, options);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    const auto& artifacts = result.value();
    ASSERT_TRUE(artifacts.run_stats.has_value());
    EXPECT_TRUE(artifacts.run_stats->terminated);
    EXPECT_EQ(artifacts.run_stats->exit_code, 0x1234U);
    const auto skips =
        artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kLoopSkip)];
    EXPECT_GE(skips, 1U) << "the nested counter loop was not fast-forwarded";
    const auto skip = std::ranges::find_if(artifacts.semantic_events, [](const auto& event) {
        return event.type == sheller::EventTypeId::kLoopSkip;
    });
    ASSERT_NE(skip, artifacts.semantic_events.end());
    EXPECT_GE(skip->aux, 8000U); // the ring count that triggered the probe
    EXPECT_GE(skip->pc, kImageBase);
    EXPECT_LT(skip->pc, kImageBase + code.size());
}

TEST(AnalysisFacade, GoldenLayoutSentinelIsRejectedAsSnapshotIo)
{
    // The synthetic golden is the snapshot FORMAT sentinel: its 16-byte
    // region violates the engine's 4KB mapping gate, so the rebuild stage
    // rejects it before any run - a snapshot-IO failure whose artifacts say
    // "never instrumented" (the probe shares the rebuild, so the run could
    // not have happened either).
    const fs::path golden = SHELLER_FACADE_GOLDEN;
    ASSERT_TRUE(fs::exists(golden));
    sheller::AnalysisOptions options;
    const auto result = facade::analyze_path_impl(golden, options);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kSnapshotIo);
    EXPECT_NE(result.error().message.find("snapshot"), std::string::npos);
    EXPECT_FALSE(result.error().artifacts.instrumented);
    EXPECT_FALSE(result.error().artifacts.run_stats.has_value());
    EXPECT_TRUE(result.error().artifacts.semantic_events.empty());
    EXPECT_TRUE(result.error().artifacts.oep_candidates.empty());
}

// ---- timeline tier ----------------------------------------------------

TEST(AnalysisFacade, TimelineWindowEvictionWithExactCounts)
{
    auto spin = craft_snapshot({0xEB, 0xFE});
    sheller::AnalysisOptions options;
    options.run.max_instructions = 200000; // ~200k blocks: past the 65536 ring
    options.timeline = true;
    const auto result = facade::analyze_bytes_impl(spin, options);
    // Budget stop: the run failure still carries the timeline artifacts.
    ASSERT_FALSE(result.has_value());
    const auto& artifacts = result.error().artifacts;
    const auto block_execs =
        artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kBlockExec)];
    ASSERT_GT(block_execs, 65536u);
    // Every event crossing the tee is recorded once: block-exec plus the
    // forwarded facts and judgments. The counts are whole-run exact while the
    // window evicted, so dropped = total recorded - ring capacity.
    std::uint64_t total = 0;
    for (const auto count : artifacts.event_counts) {
        total += count;
    }
    EXPECT_EQ(artifacts.timeline_dropped, total - 65536);
    EXPECT_EQ(decode_tlv(artifacts.timeline_tlv).size(), 65536u);
    // Empty module set: every name lookup resolves to the runtime sentinel.
    EXPECT_TRUE(artifacts.timeline_names.modules.empty());
}

TEST(AnalysisFacade, WireSeqJoinsTheTimelineTier)
{
    sheller::AnalysisOptions options;
    options.timeline = true;
    const auto result = facade::analyze_bytes_impl(terminate_snapshot(), options);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    const auto& artifacts = result.value();
    const auto tlv_events = decode_tlv(artifacts.timeline_tlv);
    ASSERT_FALSE(tlv_events.empty());
    ASSERT_FALSE(artifacts.semantic_events.empty());
    // Every semantic record's wire_seq lands on the same event in the TLV
    // stream: same ledger ordinal, same type, same tid/pc.
    for (const auto& event : artifacts.semantic_events) {
        ASSERT_GE(event.wire_seq, 1u);
        ASSERT_LE(event.wire_seq, tlv_events.size());
        const auto& joined = tlv_events[event.wire_seq - 1];
        EXPECT_EQ(joined.preamble.seq, event.wire_seq);
        EXPECT_EQ(joined.type, event.type);
        EXPECT_EQ(joined.preamble.tid, event.tid);
        EXPECT_EQ(joined.preamble.pc, event.pc);
    }
    // The two numbering spaces stay distinct: seq is gapless 1..N over the
    // semantic records only, wire_seq counts the whole stream - by the time
    // the first syscall crossed, the entry block had already consumed a
    // wire number.
    for (std::size_t i = 0; i < artifacts.semantic_events.size(); ++i) {
        EXPECT_EQ(artifacts.semantic_events[i].seq, i + 1);
    }
    EXPECT_GT(artifacts.semantic_events.back().wire_seq, artifacts.semantic_events.back().seq);
}

TEST(AnalysisFacade, TimelineOffProducesNoTier)
{
    auto spin = craft_snapshot({0xEB, 0xFE});
    sheller::AnalysisOptions options;
    options.run.max_instructions = 200000;
    const auto result = facade::analyze_bytes_impl(spin, options);
    ASSERT_FALSE(result.has_value());
    const auto& artifacts = result.error().artifacts;
    EXPECT_TRUE(artifacts.timeline_tlv.empty());
    EXPECT_TRUE(artifacts.timeline_names.modules.empty());
    EXPECT_TRUE(artifacts.timeline_names.sections.empty());
    EXPECT_EQ(artifacts.timeline_dropped, 0u);
    EXPECT_EQ(artifacts.timeline_truncated, 0u);
    // Counts stay exact regardless of the tier.
    EXPECT_GT(artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kBlockExec)],
              0u);
}

// ---- event stream tee -------------------------------------------------

TEST(AnalysisFacade, ForwardedFactsAndJudgmentsShareTheOneCursor)
{
    // A fact and an event with their judgments: every crossing consumes the
    // one whole-run number, the forwarded fact reaches counts + semantic tier
    // + ledger, and the judgments drain right after their cause.
    sheller::behavior::BehaviorRulesParams params;
    params.sample_image_base = 0x400000;
    params.sample_image_size = 0x10000;
    sheller::behavior::BehaviorRules rules(params);
    sheller::TimelineNameTable names;
    names.sample_image_range = {0x400000, 0x410000};
    names.module_ranges = {{0x400000, 0x410000}, {0x800000, 0x1000000}};
    facade::SemanticCollector collector(names);
    sheller::behavior::EventTally tally;
    sheller::behavior::EventLedger ledger;
    std::vector<std::pair<sheller::EventTypeId, std::uint64_t>> observed;
    facade::EventStream stream(
        &rules, tally, collector, &ledger,
        [&observed](const sheller::EventTypeId type, const sheller::EventPreamble& preamble,
                    std::span<const std::uint8_t>) { observed.emplace_back(type, preamble.seq); },
        ~std::uint64_t{0});

    sheller::engine::BehaviorFact write;
    write.kind = sheller::engine::BehaviorFact::Kind::kMemWrite;
    write.pc = 0x700000;
    write.addr = 0x900000;
    write.size = 1;
    write.writer_sample_code = true;
    stream.on_behavior_fact(write); // forwarded as mem-write (seq 1)

    const sheller::EventPreamble block{.seq = 0, .tid = 3, .pc = 0x900010};
    stream.on_engine_event(sheller::EventTypeId::kBlockExec, block, {}); // seq 2
    // The block lands on the first-written runtime page: SMC + OEP.

    ASSERT_EQ(observed.size(), 4U);
    EXPECT_EQ(observed[0].first, sheller::EventTypeId::kMemWrite);
    EXPECT_EQ(observed[0].second, 1U);
    EXPECT_EQ(observed[1].first, sheller::EventTypeId::kBlockExec);
    EXPECT_EQ(observed[1].second, 2U);
    EXPECT_EQ(observed[2].first, sheller::EventTypeId::kSmcExecute);
    EXPECT_EQ(observed[2].second, 3U);
    EXPECT_EQ(observed[3].first, sheller::EventTypeId::kOepCandidate);
    EXPECT_EQ(observed[3].second, 4U);

    EXPECT_EQ(tally.count_of(sheller::EventTypeId::kMemWrite), 1U);
    EXPECT_EQ(tally.count_of(sheller::EventTypeId::kBlockExec), 1U);
    EXPECT_EQ(tally.count_of(sheller::EventTypeId::kSmcExecute), 1U);
    EXPECT_EQ(tally.count_of(sheller::EventTypeId::kOepCandidate), 1U);
    ASSERT_EQ(ledger.size(), 4U);
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        EXPECT_EQ(ledger.entry(i).preamble.seq, i + 1);
    }

    // Default-column delivery: the forwarded fact and the low-frequency
    // judgment are records; the window-side block and smc events are not.
    const auto semantic = collector.take();
    ASSERT_EQ(semantic.size(), 2U);
    EXPECT_EQ(semantic[0].type, sheller::EventTypeId::kMemWrite);
    EXPECT_EQ(semantic[0].wire_seq, 1U);
    EXPECT_EQ(semantic[0].address, 0x900000U);
    EXPECT_EQ(semantic[1].type, sheller::EventTypeId::kOepCandidate);
    EXPECT_EQ(semantic[1].wire_seq, 4U);
}

TEST(AnalysisFacade, MemAccessDetailOnlyForSampleCodeSystemAccesses)
{
    // The default detail keeps a page access only when it targets a loaded
    // module other than the sample image. For mem-write the payload's writer
    // flag must also mark sample code; mem-read facts already cross the seam
    // only for sample-side readers. Everything else stays counts/ledger-only.
    sheller::behavior::BehaviorRulesParams params;
    params.sample_image_base = 0x400000;
    params.sample_image_size = 0x10000;
    sheller::behavior::BehaviorRules rules(params);
    sheller::TimelineNameTable names;
    names.sample_image_range = {0x400000, 0x410000};
    names.module_ranges = {{0x400000, 0x410000}, {0x800000, 0x1000000}};
    facade::SemanticCollector collector(names);
    sheller::behavior::EventTally tally;
    sheller::behavior::EventLedger ledger;
    std::vector<sheller::EventTypeId> observed;
    facade::EventStream stream(
        &rules, tally, collector, &ledger,
        [&observed](const sheller::EventTypeId type, const sheller::EventPreamble&,
                    std::span<const std::uint8_t>) { observed.push_back(type); },
        ~std::uint64_t{0});

    const auto emit_access = [&stream](const sheller::EventTypeId kind, const std::uint64_t pc,
                                       const std::uint64_t address, const bool sample_writer) {
        sheller::engine::BehaviorFact fact;
        fact.kind = kind == sheller::EventTypeId::kMemRead
                        ? sheller::engine::BehaviorFact::Kind::kMemRead
                        : sheller::engine::BehaviorFact::Kind::kMemWrite;
        fact.pc = pc;
        fact.addr = address;
        fact.size = 1;
        fact.writer_sample_code = sample_writer;
        stream.on_behavior_fact(fact);
    };
    emit_access(sheller::EventTypeId::kMemWrite, 0x401000, 0x800010, true);  // detail
    emit_access(sheller::EventTypeId::kMemWrite, 0x800000, 0x800020, false); // counts only
    emit_access(sheller::EventTypeId::kMemWrite, 0x401000, 0x402000, true);  // counts only
    emit_access(sheller::EventTypeId::kMemWrite, 0x401000, 0x100000, true);  // counts only
    emit_access(sheller::EventTypeId::kMemRead, 0x401000, 0x800030, true);   // detail
    emit_access(sheller::EventTypeId::kMemRead, 0x401000, 0x402000, true);   // counts only
    emit_access(sheller::EventTypeId::kMemRead, 0x401000, 0x100000, true);   // counts only

    const auto semantic = collector.take();
    ASSERT_EQ(semantic.size(), 2U);
    EXPECT_EQ(semantic[0].type, sheller::EventTypeId::kMemWrite);
    EXPECT_EQ(semantic[0].address, 0x800010U);
    EXPECT_EQ(semantic[1].type, sheller::EventTypeId::kMemRead);
    EXPECT_EQ(semantic[1].address, 0x800030U);
    EXPECT_EQ(tally.count_of(sheller::EventTypeId::kMemWrite), 4U);
    EXPECT_EQ(tally.count_of(sheller::EventTypeId::kMemRead), 3U);
    EXPECT_EQ(ledger.count_of(sheller::EventTypeId::kMemWrite), 4U);
    EXPECT_EQ(ledger.count_of(sheller::EventTypeId::kMemRead), 3U);
    EXPECT_EQ(observed.size(), 7U);
}

// ---- host subscription ------------------------------------------------

TEST(AnalysisFacade, MaskFiltersInstructionLevel)
{
    auto spin = craft_snapshot({0xEB, 0xFE});
    sheller::AnalysisOptions options;
    options.run.max_instructions = 50000;
    // Semantic bits only: block-exec (type 3) never crosses to the host.
    options.event_type_mask = (1u << static_cast<unsigned>(sheller::EventTypeId::kSyscall)) |
                              (1u << static_cast<unsigned>(sheller::EventTypeId::kXfer));
    std::atomic<int> calls{0};
    options.event_observer = [&calls](sheller::EventTypeId type, const sheller::EventPreamble&,
                                      std::span<const std::uint8_t>) {
        ++calls;
        EXPECT_EQ(type, sheller::EventTypeId::kSyscall); // would fail the mask
    };
    const auto result = facade::analyze_bytes_impl(spin, options);
    ASSERT_FALSE(result.has_value()); // budget stop, as designed
    EXPECT_EQ(calls.load(), 0);
    EXPECT_GT(
        result.error()
            .artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kBlockExec)],
        0u);
}

TEST(AnalysisFacade, MaskSelectsSemanticBits)
{
    sheller::AnalysisOptions options;
    options.event_type_mask = 1u << static_cast<unsigned>(sheller::EventTypeId::kSyscall);
    std::atomic<int> calls{0};
    options.event_observer = [&calls](sheller::EventTypeId type, const sheller::EventPreamble&,
                                      std::span<const std::uint8_t>) {
        EXPECT_EQ(type, sheller::EventTypeId::kSyscall);
        ++calls;
    };
    const auto result = facade::analyze_bytes_impl(terminate_snapshot(), options);
    ASSERT_TRUE(result.has_value());
    // Exactly the one syscall crossed; block-exec events stayed internal.
    EXPECT_EQ(calls.load(), 1);
}

TEST(AnalysisFacade, ThrowingObserverDoesNotKillTheRun)
{
    auto spin = craft_snapshot({0xEB, 0xFE});
    sheller::AnalysisOptions options;
    options.run.max_instructions = 50000;
    options.event_type_mask = ~0ull;
    options.event_observer = [](sheller::EventTypeId, const sheller::EventPreamble&,
                                std::span<const std::uint8_t>) {
        throw std::runtime_error{"host contract violated"};
    };
    const auto result = facade::analyze_bytes_impl(spin, options);
    // The run completed (its budget stop surfaced as always); the process
    // did not terminate.
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().run->error, sheller::engine::SyscallRunError::kBudgetExhausted);
}

// The same discipline on the other host callback the library invokes: the log
// sink. The record that reaches it here is the engine's own run-start record, so
// the containment is exercised on the path a host actually takes rather than by
// calling log::write from a test - and the assertions that follow are the run's,
// because "the host survived" and "the run still converged" are the two claims a
// diagnostic channel has to keep separate.
TEST(AnalysisFacade, ThrowingLogSinkDoesNotKillTheRun)
{
    std::atomic<int> entered{0};
    sheller::log::detail::set_sink_impl(
        [&entered](const sheller::log::level, const std::string_view) {
            ++entered;
            throw std::runtime_error{"host contract violated"};
        },
        sheller::log::level::kDebug);
    // The log state is the one process-global: hand it back quiet so the cases
    // after this one are not measured against a throwing sink.
    struct sink_reset {
        ~sink_reset()
        {
            sheller::log::detail::set_sink_impl({}, sheller::log::level::kWarning);
        }
    } reset;

    sheller::AnalysisOptions options;
    const auto result = facade::analyze_bytes_impl(write_snapshot_bytes(), options);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    // Not vacuous: without this the case would pass while nothing ever threw.
    EXPECT_GT(entered.load(), 0) << "the run reached the log facade " << entered.load()
                                 << " times - the sink never saw a record";
    // Dropping the record changed nothing observable: the same snapshot with no
    // sink installed reports the same syscall count in its artifacts.
    EXPECT_EQ(result->event_counts[static_cast<std::size_t>(sheller::EventTypeId::kSyscall)], 2u);
}

TEST(AnalysisFacade, HostEventSinkSlotDoesNotHijackWiring)
{
    int host_calls = 0;
    sheller::AnalysisOptions options;
    options.run.event_sink = [&host_calls](sheller::EventTypeId, const sheller::EventPreamble&,
                                           std::span<const std::uint8_t>) { ++host_calls; };
    const auto result = facade::analyze_bytes_impl(terminate_snapshot(), options);
    ASSERT_TRUE(result.has_value());
    // The three internal slots are facade-owned: the host's setting never
    // fired, and the wiring still produced its artifacts.
    EXPECT_EQ(host_calls, 0);
    EXPECT_FALSE(result->semantic_events.empty());
    EXPECT_EQ(result->event_counts[static_cast<std::size_t>(sheller::EventTypeId::kSyscall)], 1u);
}

TEST(AnalysisFacade, AllThreeInternalSlotsAreFacadeOwned)
{
    std::atomic<int> host_calls{0};
    sheller::AnalysisOptions options;
    options.run.event_sink = [&host_calls](sheller::EventTypeId, const sheller::EventPreamble&,
                                           std::span<const std::uint8_t>) { ++host_calls; };
    options.run.stub_sink = [&host_calls](std::uint16_t, std::string_view, std::uint64_t) {
        ++host_calls;
    };
    // The third internal slot (the fact sink) has no public options field at
    // all anymore - the channel is built by the wiring and passed beside the
    // options (src/engine/behavior_fact.h) - so "not hijackable" is enforced
    // by the type system, not by overwriting.
    const auto result = facade::analyze_bytes_impl(terminate_snapshot(), options);
    ASSERT_TRUE(result.has_value());
    // None of the settable slots crossed; the internal wiring produced everything.
    EXPECT_EQ(host_calls.load(), 0);
    EXPECT_FALSE(result->semantic_events.empty());
    EXPECT_TRUE(result->instrumented);
    EXPECT_EQ(result->event_counts[static_cast<std::size_t>(sheller::EventTypeId::kSyscall)], 1u);
}

TEST(AnalysisFacade, BehaviorReportOptOutIsCheapButKeepsObserver)
{
    sheller::AnalysisOptions options;
    options.behavior_report = false;
    options.event_type_mask = 1u << static_cast<unsigned>(sheller::EventTypeId::kSyscall);
    std::atomic<int> calls{0};
    options.event_observer = [&calls](sheller::EventTypeId type, const sheller::EventPreamble&,
                                      std::span<const std::uint8_t>) {
        EXPECT_EQ(type, sheller::EventTypeId::kSyscall);
        ++calls;
    };
    const auto result = facade::analyze_bytes_impl(terminate_snapshot(), options);
    ASSERT_TRUE(result.has_value());
    // Success with empty behavior artifacts and the opt-out note: the run is
    // real, only the judgment tier is off. The observer still crosses - tee
    // semantics are never suppressed by an un-instrumented run.
    EXPECT_FALSE(result->instrumented);
    EXPECT_NE(result->note.find("disabled by the host"), std::string::npos);
    EXPECT_TRUE(result->semantic_events.empty());
    EXPECT_TRUE(result->oep_candidates.empty());
    EXPECT_EQ(result->event_counts[static_cast<std::size_t>(sheller::EventTypeId::kSyscall)], 0u);
    EXPECT_EQ(result->semantic_dropped, 0u);
    ASSERT_TRUE(result->run_stats.has_value());
    EXPECT_TRUE(result->run_stats->terminated);
    EXPECT_EQ(calls.load(), 1);
}

// ---- guest output -----------------------------------------------------

TEST(AnalysisFacade, GuestOutputReachesAnExplicitSink)
{
    sheller::AnalysisOptions options;
    std::string received;
    options.run.write_sink = [&received](const std::uint8_t* data, std::size_t size) {
        received.append(reinterpret_cast<const char*>(data), size);
    };
    const auto result = facade::analyze_bytes_impl(write_snapshot_bytes(), options);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(received, "hi\n");
    EXPECT_EQ(result->event_counts[static_cast<std::size_t>(sheller::EventTypeId::kSyscall)], 2u);
}

TEST(AnalysisFacade, GuestOutputDefaultsToDiscard)
{
    sheller::AnalysisOptions options; // no write_sink: the engine's former
                                      // stdout default must not be reached
    StandardStreamCapture capture;
    const auto result = facade::analyze_bytes_impl(write_snapshot_bytes(), options);
    const auto host_stdout = capture.stdout_text();
    const auto host_stderr = capture.stderr_text();
    ASSERT_TRUE(result.has_value()) << result.error().message;
    EXPECT_EQ(host_stdout, std::string{});
    EXPECT_EQ(host_stderr, std::string{});
}

// The same pair one level down, at the engine entry the host calls directly. The
// facade cases above cannot cover this: they run through the wiring, and the
// wiring used to install a sink of its own precisely so that the engine's stdout
// default would not be reached. Deleting that lambda is only safe while the
// discard default lives in the engine, and these two cases are what says so.
TEST(EngineGuestOutput, SinkReceivesGuestBytesInEmissionOrder)
{
    sheller::engine::SyscallRunOptions options;
    std::vector<std::string> chunks;
    options.write_sink = [&chunks](const std::uint8_t* data, const std::size_t size) {
        chunks.emplace_back(reinterpret_cast<const char*>(data), size);
    };
    const auto stats = sheller::engine::run_snapshot_syscalls(two_write_snapshot_bytes(), options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    // Two calls, each delivered whole, in the order the guest wrote them. A sink
    // that was handed the joined bytes, or the two in reverse, fails here.
    EXPECT_EQ(chunks, (std::vector<std::string>{"ab", "ok\n"}));
}

TEST(EngineGuestOutput, NoSinkWritesNothingToTheHostStandardStreams)
{
    const auto snapshot = two_write_snapshot_bytes();
    sheller::engine::SyscallRunOptions options; // no write_sink
    StandardStreamCapture capture;
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    const auto host_stdout = capture.stdout_text();
    const auto host_stderr = capture.stderr_text();
    // The run still takes both writes and terminates - the bytes go nowhere, but
    // the guest is not told the stream broke.
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->syscalls, 3u);
    EXPECT_EQ(host_stdout, std::string{});
    EXPECT_EQ(host_stderr, std::string{});
}

// A canonical text per event: the engine hands out (type, preamble, fields), and
// two runs have to agree on every one of them for the discard default to be the
// non-event the spec claims it is.
std::string event_row(const sheller::EventTypeId type, const sheller::EventPreamble& preamble,
                      const std::span<const std::uint8_t> fields)
{
    std::ostringstream row;
    row << static_cast<int>(type) << '/' << preamble.seq << '/' << preamble.tid << '/';
    for (const auto byte : fields) {
        row << static_cast<int>(byte) << ' ';
    }
    return row.str();
}

TEST(EngineGuestOutput, DroppingTheBytesLeavesStatsAndEventStreamUnchanged)
{
    // The spec scenario says the discarded run has the same run statistics and the
    // same event stream as the delivered one - "the bytes are dropped, nothing else
    // is". Comparing the two runs side by side is the only way to know that the
    // discard is not quietly short-circuiting the handler.
    const auto& snapshot = two_write_snapshot_bytes();
    std::size_t delivered{};
    std::vector<std::string> delivered_events;
    sheller::engine::SyscallRunOptions with_sink;
    with_sink.write_sink = [&delivered](const std::uint8_t*, const std::size_t size) {
        delivered += size;
    };
    with_sink.event_sink = [&delivered_events](const sheller::EventTypeId type,
                                               const sheller::EventPreamble& preamble,
                                               const std::span<const std::uint8_t> fields) {
        delivered_events.push_back(event_row(type, preamble, fields));
    };
    const auto sunk = sheller::engine::run_snapshot_syscalls(snapshot, with_sink);

    std::vector<std::string> dropped_events;
    sheller::engine::SyscallRunOptions without_sink;
    without_sink.event_sink = [&dropped_events](const sheller::EventTypeId type,
                                                const sheller::EventPreamble& preamble,
                                                const std::span<const std::uint8_t> fields) {
        dropped_events.push_back(event_row(type, preamble, fields));
    };
    const auto dropped = sheller::engine::run_snapshot_syscalls(snapshot, without_sink);

    ASSERT_TRUE(sunk.has_value()) << sheller::engine::syscall_run_error_message(sunk.error().error);
    ASSERT_TRUE(dropped.has_value())
        << sheller::engine::syscall_run_error_message(dropped.error().error);
    EXPECT_EQ(delivered, 5U); // "ab" + "ok\n", so the delivered run really delivered
    EXPECT_FALSE(delivered_events.empty());
    EXPECT_EQ(dropped->terminated, sunk->terminated);
    EXPECT_EQ(dropped->exit_code, sunk->exit_code);
    EXPECT_EQ(dropped->blocks, sunk->blocks);
    EXPECT_EQ(dropped->syscalls, sunk->syscalls);
    EXPECT_EQ(dropped->rejects, sunk->rejects);
    EXPECT_EQ(dropped->exceptions, sunk->exceptions);
    EXPECT_EQ(dropped_events, delivered_events);
}

// The guest-output callback's throw rule, end to end on a real run: the write it
// threw on is the only thing lost. Portable on purpose - the crafted snapshot
// needs neither the capture route (Windows-only) nor a corpus file (kept out of
// git), so this is the POSIX half of a rule the contract states for both
// platforms. The counters are what keep it honest: without them, a run where the
// callback was never reached would look exactly like a run where it was reached,
// threw, and was contained.
TEST(EngineGuestOutput, AThrowingSinkLosesThatWriteAndLeavesTheRunAlone)
{
    const auto& snapshot = two_write_snapshot_bytes();

    const auto collect_events = [](std::vector<std::string>* into) {
        return [into](const sheller::EventTypeId type, const sheller::EventPreamble& preamble,
                      const std::span<const std::uint8_t> fields) {
            into->push_back(event_row(type, preamble, fields));
        };
    };

    // Reference run: the same sink, not throwing. Its chunks and its event rows
    // are what the throwing run is compared against.
    std::vector<std::string> quiet_chunks;
    std::vector<std::string> quiet_events;
    sheller::engine::SyscallRunStats quiet_stats{};
    {
        sheller::engine::SyscallRunOptions options;
        options.write_sink = [&quiet_chunks](const std::uint8_t* data, const std::size_t size) {
            quiet_chunks.emplace_back(reinterpret_cast<const char*>(data), size);
        };
        options.event_sink = collect_events(&quiet_events);
        StandardStreamCapture capture{"guest_sink_quiet"};
        const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
        ASSERT_TRUE(stats.has_value())
            << sheller::engine::syscall_run_error_message(stats.error().error);
        quiet_stats = *stats;
        EXPECT_EQ(capture.stdout_text(), std::string{});
        EXPECT_EQ(capture.stderr_text(), std::string{});
    }
    ASSERT_EQ(quiet_chunks, (std::vector<std::string>{"ab", "ok\n"}))
        << "the reference run has to deliver both writes before it can be a reference";
    ASSERT_FALSE(quiet_events.empty());

    // The run under test: the first delivery throws.
    std::vector<std::string> throwing_chunks;
    std::vector<std::string> throwing_events;
    sheller::engine::SyscallRunStats throwing_stats{};
    int entered = 0;
    int thrown = 0;
    {
        sheller::engine::SyscallRunOptions options;
        options.write_sink = [&](const std::uint8_t* data, const std::size_t size) {
            ++entered;
            if (entered == 1) {
                ++thrown;
                throw std::runtime_error("the host's write sink is broken");
            }
            throwing_chunks.emplace_back(reinterpret_cast<const char*>(data), size);
        };
        options.event_sink = collect_events(&throwing_events);
        StandardStreamCapture capture{"guest_sink_throwing"};
        const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
        // The run still came back through the entry point rather than ending the
        // process - which on POSIX is the whole content of the rule, since the
        // frame above the trampoline is unicorn's syscall helper and has no
        // unwind info to give back.
        ASSERT_TRUE(stats.has_value())
            << sheller::engine::syscall_run_error_message(stats.error().error);
        throwing_stats = *stats;
        // A dropped write is not an excuse to print about it: no fallback echo,
        // no diagnostic, on either stream.
        EXPECT_EQ(capture.stdout_text(), std::string{});
        EXPECT_EQ(capture.stderr_text(), std::string{});
    }

    // (1) The throw really happened, once, and the callback was really reached
    // for every write.
    EXPECT_EQ(entered, 2);
    EXPECT_EQ(thrown, 1);
    // (2) Only that write's bytes are lost; the one after it still arrives at the
    // same sink, in guest order.
    EXPECT_EQ(throwing_chunks, (std::vector<std::string>{"ok\n"}));
    // (3) The run converged to the same verdict and the guest could not tell:
    // same statistics, and the same event stream row for row.
    EXPECT_TRUE(throwing_stats.terminated);
    EXPECT_EQ(throwing_stats.exit_code, quiet_stats.exit_code);
    EXPECT_EQ(throwing_stats.blocks, quiet_stats.blocks);
    EXPECT_EQ(throwing_stats.syscalls, quiet_stats.syscalls);
    EXPECT_EQ(throwing_stats.rejects, quiet_stats.rejects);
    EXPECT_EQ(throwing_stats.exceptions, quiet_stats.exceptions);
    EXPECT_EQ(throwing_events, quiet_events);
}

// The ruler for the two silence claims above. Without it, "zero bytes on both
// streams" would be equally satisfied by a fixture that never redirected
// anything, and the assertion would be about the capture instead of about the
// library. Here the host writes from inside the callback, mid-run, with the
// window already open - so the fixture demonstrably catches bytes produced at
// exactly the point where a fallback echo would appear.
TEST(EngineGuestOutput, TheStreamCaptureDoesSeeBytesWrittenFromInsideTheCallback)
{
    const auto& snapshot = two_write_snapshot_bytes();
    sheller::engine::SyscallRunOptions options;
    options.write_sink = [](const std::uint8_t* data, const std::size_t size) {
        std::fwrite(data, 1, size, stdout);
        std::fflush(stdout);
    };
    StandardStreamCapture capture{"guest_sink_control"};
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);
    EXPECT_EQ(capture.stdout_text(), "abok\n")
        << "bytes the host writes from inside the callback have to be caught by this"
           " fixture, or the empty-stream assertions above are not testing what they say";
    EXPECT_EQ(capture.stderr_text(), std::string{});
}

// ---- engine xfer stop -------------------------------------------------

// The crafted two-section fixture reaches its single xfer after a counter
// loop, so a tiny wall clock is crossed inside the leg the xfer ends. These
// cases are portable: no capture route and no corpus file.
TEST(EngineXferStop, StopsBeforeTheLandingBlockAndDumps)
{
    const auto dir = sheller_test::temp_path("sheller_xfer_stop") / "run";
    fs::remove_all(dir);
    std::uint64_t block_events = 0;
    std::uint64_t last_block_pc = 0;
    sheller::engine::SyscallRunOptions options;
    options.xfer_number = 1;
    options.dump_directory = dir;
    options.event_sink = [&](const sheller::EventTypeId type,
                             const sheller::EventPreamble& preamble,
                             const std::span<const std::uint8_t>) {
        if (type == sheller::EventTypeId::kBlockExec) {
            ++block_events;
            last_block_pc = preamble.pc;
        }
    };

    const auto stats =
        sheller::engine::run_snapshot_syscalls(sheller_test::xfer_delay_snapshot_bytes(), options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error)
        << " blocks=" << stats.error().stats.blocks;
    EXPECT_FALSE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0U);
    EXPECT_EQ(stats->syscalls, 0U); // the terminate syscall in text2 never ran
    EXPECT_EQ(stats->xfers, 1U);
    EXPECT_TRUE(stats->xfer_stop);
    // Every counted block produced its block-exec, including the landing
    // block, and the landing block is the last one the hook saw.
    EXPECT_EQ(block_events, stats->blocks);
    EXPECT_EQ(last_block_pc, sheller_test::kXferText2Va);
    EXPECT_TRUE(fs::exists(dir / "manifest.txt"));
}

TEST(EngineXferStop, UnboundedBudgetAndClockStillStopAtTheTarget)
{
    // The one configuration where the leg loop's explicit break is the only
    // thing between the stop and the landing block: with no instruction budget
    // there is no leg-count accounting left to end the run, and with no wall
    // clock there is no leg-boundary expiry either. Every other case here is
    // caught by one of those two first, so this is the case that goes red when
    // the break is missing or moves behind a trailing continue - the guest then
    // runs on through the landing block and the same transfer is counted again
    // on the re-entry.
    sheller::engine::SyscallRunOptions options;
    options.xfer_number = 1;
    options.max_instructions = 0;
    options.timeout_ms = 0;

    const auto stats =
        sheller::engine::run_snapshot_syscalls(sheller_test::xfer_delay_snapshot_bytes(), options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);
    EXPECT_FALSE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0U);
    EXPECT_EQ(stats->syscalls, 0U); // the landing block never ran
    EXPECT_EQ(stats->xfers, 1U);    // and its re-entry never re-counted
    EXPECT_TRUE(stats->xfer_stop);
}

TEST(EngineXferStop, CountsAndStopsWithoutAnEventSink)
{
    sheller::engine::SyscallRunOptions options;
    options.xfer_number = 1;

    const auto stats =
        sheller::engine::run_snapshot_syscalls(sheller_test::xfer_delay_snapshot_bytes(), options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);
    EXPECT_FALSE(stats->terminated);
    EXPECT_EQ(stats->syscalls, 0U);
    EXPECT_EQ(stats->xfers, 1U);
    EXPECT_TRUE(stats->xfer_stop);
    EXPECT_GT(stats->blocks, 0U);
}

TEST(EngineXferStop, MissingTargetFallsBackToNormalTermination)
{
    sheller::engine::SyscallRunOptions options;
    options.xfer_number = 2; // the fixture has exactly one transfer

    const auto stats =
        sheller::engine::run_snapshot_syscalls(sheller_test::xfer_delay_snapshot_bytes(), options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x1234U);
    EXPECT_EQ(stats->syscalls, 1U);
    EXPECT_EQ(stats->xfers, 1U);
    EXPECT_FALSE(stats->xfer_stop);
}

TEST(EngineXferStop, InstructionBudgetArrivingFirstWins)
{
    sheller::engine::SyscallRunOptions options;
    options.xfer_number = 1;
    options.max_instructions = 100000; // the delay loop has not finished

    const auto stats =
        sheller::engine::run_snapshot_syscalls(sheller_test::xfer_delay_snapshot_bytes(), options);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kBudgetExhausted);
    EXPECT_FALSE(stats.error().stats.xfer_stop);
    EXPECT_EQ(stats.error().stats.xfers, 0U);
}

TEST(EngineXferStop, BlockBudgetArrivingFirstWins)
{
    sheller::engine::SyscallRunOptions options;
    options.xfer_number = 1;
    // The block budget ends the leg early; the instruction budget's leg
    // accounting is what then ends the run (the documented existing shape).
    options.max_blocks = 100;

    const auto stats =
        sheller::engine::run_snapshot_syscalls(sheller_test::xfer_delay_snapshot_bytes(), options);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kBudgetExhausted);
    EXPECT_FALSE(stats.error().stats.xfer_stop);
    EXPECT_EQ(stats.error().stats.xfers, 0U);
}

TEST(EngineXferStop, XferStopVetoesTheRecomputedWallClock)
{
    // The loop's guest-visible write makes the probe admit it as compute and
    // re-arm further out, so the delay is cut across several legs and the
    // transfer lands in the last one. Each of those legs leaves through the
    // probe's continue, which sits ahead of the leg-boundary wall clock, and
    // the last one leaves through the xfer break - also ahead of it. The only
    // clock reading in the whole run is therefore the finish-time
    // recomputation, which is exactly what the veto overrides.
    const auto dir = sheller_test::temp_path("sheller_xfer_stop") / "mid_leg";
    fs::remove_all(dir);
    sheller::engine::SyscallRunOptions options;
    options.xfer_number = 1;
    options.max_instructions = 0;
    options.timeout_ms = 1;
    options.dump_directory = dir;

    const auto stats =
        sheller::engine::run_snapshot_syscalls(sheller_test::xfer_delay_snapshot_bytes(), options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error);
    EXPECT_TRUE(stats->xfer_stop);
    EXPECT_FALSE(stats->terminated);
    EXPECT_EQ(stats->syscalls, 0U);
    EXPECT_TRUE(fs::exists(dir / "manifest.txt"));
}

TEST(EngineXferStop, WallClockArrivingFirstIsStillATimeout)
{
    // The spin guest never transfers, so the xfer target stays unreached and
    // the wall clock keeps its usual no-dump failure.
    const auto dir = sheller_test::temp_path("sheller_xfer_stop") / "timeout";
    fs::remove_all(dir);
    sheller::engine::SyscallRunOptions options;
    options.xfer_number = 1;
    options.max_instructions = 0;
    options.timeout_ms = 200;
    options.dump_directory = dir;

    const auto stats =
        sheller::engine::run_snapshot_syscalls(sheller_test::craft_snapshot({0xEB, 0xFE}), options);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kTimeout);
    EXPECT_FALSE(stats.error().stats.xfer_stop);
    EXPECT_EQ(stats.error().stats.xfers, 0U);
    EXPECT_FALSE(fs::exists(dir));
}

TEST(EngineXferStop, AnalyzeRouteCarriesTheStopInRunStats)
{
    sheller::AnalysisOptions options;
    options.run.xfer_number = 1;

    const auto result =
        facade::analyze_bytes_impl(sheller_test::xfer_delay_snapshot_bytes(), options);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    ASSERT_TRUE(result->run_stats.has_value());
    EXPECT_TRUE(result->run_stats->xfer_stop);
    EXPECT_EQ(result->run_stats->xfers, 1U);
    EXPECT_FALSE(result->run_stats->terminated);
}

TEST(EngineXferStop, DumpIsByteIdenticalAcrossReplays)
{
    const auto root = sheller_test::temp_path("sheller_xfer_stop") / "replay";
    fs::remove_all(root);
    const auto run_dump = [](const std::filesystem::path& out) {
        sheller::engine::SyscallRunOptions options;
        options.xfer_number = 1;
        options.dump_directory = out;
        const auto stats = sheller::engine::run_snapshot_syscalls(
            sheller_test::xfer_delay_snapshot_bytes(), options);
        EXPECT_TRUE(stats.has_value())
            << sheller::engine::syscall_run_error_message(stats.error().error);
    };
    run_dump(root / "a");
    run_dump(root / "b");

    const auto read_tree = [](const std::filesystem::path& dir) {
        std::vector<std::pair<std::string, std::string>> entries;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(dir)) {
            std::ifstream in(entry.path(), std::ios::binary);
            entries.emplace_back(entry.path().filename().string(),
                                 std::string((std::istreambuf_iterator<char>(in)), {}));
        }
        std::sort(entries.begin(), entries.end());
        return entries;
    };
    const auto left = read_tree(root / "a");
    const auto right = read_tree(root / "b");
    ASSERT_FALSE(left.empty());
    EXPECT_EQ(left, right);
}

// ---- unpack_sample ----------------------------------------------------

#ifndef _WIN32
TEST(AnalysisFacade, UnpackLoaderRouteOnLinux)
{
    // The constructed container runs the packed corpus through its synthetic
    // module pages, dumps on the deterministic post-OEP stop, and finishes
    // through the same engine-native repair the Windows route uses - the
    // container is both the executed world and the repair input, and its Ldr
    // table makes the repair verdict complete.
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    ASSERT_TRUE(fs::exists(sample));
    const fs::path synth = SYNTH_MODULE_DIR;
    ASSERT_TRUE(fs::exists(synth)) << "synthetic modules not generated: " << synth.string();
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    sheller::UnpackOptions options;
    options.output = dir / "packed_linux.unp";
    options.synthetic_module_dir = synth;
    const auto outcome = facade::unpack_sample_impl(sample, options);
    // The packed payload's post-OEP CRT init crashes on the synthetic stubs
    // (the documented loader-route shape); the crash is a deterministic stop
    // that dumps, so the pipeline still repairs and lands the artifacts with
    // the stop recorded in the note.
    ASSERT_FALSE(outcome.failure.has_value()) << outcome.failure->message;
    ASSERT_TRUE(fs::exists(outcome.output));
    std::ifstream unp(outcome.output, std::ios::binary);
    char mz[2] = {};
    unp.read(mz, 2);
    EXPECT_EQ(std::memcmp(mz, "MZ", 2), 0);
    EXPECT_TRUE(outcome.artifacts.instrumented);
    ASSERT_TRUE(outcome.artifacts.run_stats.has_value());
    EXPECT_FALSE(outcome.artifacts.run_stats->terminated);
    EXPECT_NE(outcome.artifacts.note.find("run stopped"), std::string::npos);
    // The container carries the sample's Ldr entry and the synthetic module
    // exports: the image region repairs completely with no uncovered thunk.
    ASSERT_TRUE(outcome.repair.has_value());
    bool any_complete = false;
    for (const auto& region : outcome.repair->regions) {
        if (region.verdict != sheller::unpack::RepairVerdict::kComplete) {
            continue;
        }
        any_complete = true;
        EXPECT_TRUE(region.uncovered.empty());
        EXPECT_EQ(region.residual_abs_va.size(), region.uncovered.size());
    }
    EXPECT_TRUE(any_complete);
    EXPECT_FALSE(fs::exists(dir / "reports"));
}

TEST(AnalysisFacade, NonWindowsMissingSyntheticDirectoryIsCaptureFailure)
{
    // The sample route refuses without the module directory; the failure is
    // the capture class the CLI turns into exit 2 on the sample path.
    sheller::AnalysisOptions options;
    const auto result = facade::analyze_path_impl(SHELLER_SAMPLE_PACKED_PATH, options);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kCapture);
    EXPECT_EQ(result.error().capture_status, sheller::capture::Status::kCaptureFailed);
    EXPECT_NE(result.error().message.find("synthetic system modules not found"), std::string::npos);
    EXPECT_FALSE(result.error().artifacts.run_stats.has_value());
}

TEST(AnalysisFacade, X86SampleInputIsRejectedBeforeExecution)
{
    const fs::path sample = fs::path(SYNTH_MODULE_DIR) / "ntdll.x86.dll";
    ASSERT_TRUE(fs::exists(sample)) << sample.string();
    sheller::AnalysisOptions options;
    options.run.synthetic_system_modules = true;
    options.run.synthetic_module_dir = SYNTH_MODULE_DIR;
    const auto result = facade::analyze_path_impl(sample, options);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kCapture);
    EXPECT_EQ(result.error().capture_status, sheller::capture::Status::kNotX64Pe);
    EXPECT_NE(result.error().message.find("32-bit sample input"), std::string::npos);
    EXPECT_FALSE(result.error().artifacts.run_stats.has_value());

    const auto dir = sheller_test::temp_path("sheller_facade_x86");
    fs::create_directories(dir);
    sheller::UnpackOptions unpack_options;
    unpack_options.output = dir / "x86.unp";
    unpack_options.synthetic_module_dir = SYNTH_MODULE_DIR;
    const auto outcome = facade::unpack_sample_impl(sample, unpack_options);
    ASSERT_TRUE(outcome.failure.has_value());
    EXPECT_EQ(outcome.failure->kind, sheller::AnalysisFailure::Kind::kCapture);
    EXPECT_EQ(outcome.failure->capture_status, sheller::capture::Status::kNotX64Pe);
    EXPECT_NE(outcome.failure->message.find("32-bit sample input"), std::string::npos);
    EXPECT_FALSE(fs::exists(unpack_options.output));

    // The other condition names itself differently: the two are
    // distinguishable by class and text.
    sheller::AnalysisOptions missing;
    const auto missing_result = facade::analyze_path_impl(sample, missing);
    ASSERT_FALSE(missing_result.has_value());
    EXPECT_EQ(missing_result.error().capture_status, sheller::capture::Status::kCaptureFailed);
    EXPECT_NE(missing_result.error().message.find("synthetic system modules not found"),
              std::string::npos);
}

TEST(AnalysisFacade, CraftedSaveSnapshotFitsTheDerivedBound)
{
    const auto dir = sheller_test::temp_path("sheller_facade_bound");
    fs::create_directories(dir);
    const auto saved = dir / "crafted.snap";
    sheller::AnalysisOptions options;
    options.run.synthetic_system_modules = true;
    options.run.synthetic_module_dir = SYNTH_MODULE_DIR;
    options.run.max_instructions = 200000; // deterministic early stop
    options.save_snapshot = saved;
    static_cast<void>(facade::analyze_path_impl(SHELLER_SAMPLE_PACKED_PATH, options));
    ASSERT_TRUE(fs::exists(saved));
    EXPECT_LE(fs::file_size(saved), sheller::test::kContainerSizeBound);

    const auto not_saved = dir / "not_saved.snap";
    sheller::AnalysisOptions plain;
    plain.run.synthetic_system_modules = true;
    plain.run.synthetic_module_dir = SYNTH_MODULE_DIR;
    plain.run.max_instructions = 200000;
    static_cast<void>(facade::analyze_path_impl(SHELLER_SAMPLE_PACKED_PATH, plain));
    EXPECT_FALSE(fs::exists(not_saved));
}
#else
TEST(AnalysisFacade, UnpackMissingSampleIsCaptureFailure)
{
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    sheller::UnpackOptions options;
    options.work_dir = dir / "work_missing";
    options.output = dir / "missing.unp";
    const auto outcome = facade::unpack_sample_impl(dir / "definitely_absent.exe", options);
    ASSERT_TRUE(outcome.failure.has_value());
    EXPECT_EQ(outcome.failure->kind, sheller::AnalysisFailure::Kind::kCapture);
    EXPECT_TRUE(outcome.output.empty());
}

TEST(AnalysisFacade, UnpackPackedPipelineProducesRequestedArtifacts)
{
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    sheller::UnpackOptions options;
    options.output = dir / "packed.unp";
    const auto outcome = facade::unpack_sample_impl(sample, options);
    ASSERT_FALSE(outcome.failure.has_value()) << outcome.failure->message;
    ASSERT_TRUE(fs::exists(outcome.output));
    std::ifstream unp(outcome.output, std::ios::binary);
    char mz[2] = {};
    unp.read(mz, 2);
    EXPECT_EQ(std::memcmp(mz, "MZ", 2), 0);
    // The verdicts are structured now; no report file exists anywhere.
    ASSERT_TRUE(outcome.repair.has_value());
    ASSERT_FALSE(outcome.repair->regions.empty());
    bool any_complete = false;
    for (const auto& region : outcome.repair->regions) {
        if (region.verdict == sheller::unpack::RepairVerdict::kComplete) {
            any_complete = true;
            EXPECT_TRUE(region.residual_abs_va.empty());
        }
    }
    EXPECT_TRUE(any_complete);
    EXPECT_FALSE(fs::exists(dir / "reports"));
    EXPECT_TRUE(outcome.oep_found);
    EXPECT_TRUE(fs::exists(outcome.work_dir) == false); // generated dir cleaned after success
    // Defaults: no timeline tier, no intermediate snapshot file.
    EXPECT_TRUE(outcome.artifacts.timeline_tlv.empty());
    // Behavior artifacts from the run: the OEP candidate matches the stamp.
    EXPECT_EQ(outcome.artifacts.oep_candidates.size(), 1u);
}

TEST(AnalysisFacade, UnpackWorkDirsUniqueUnderConcurrency)
{
    // Packed exercises the whole pipeline to success (hello never dirties
    // its image, so its dump carries no repairable region) - two full runs
    // in flight, each staging in its own process-unique directory.
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    fs::path first_dir;
    fs::path second_dir;
    auto run_unpack = [&](fs::path* sink) {
        sheller::UnpackOptions options;
        options.output =
            dir / ("hello_" + std::to_string(reinterpret_cast<std::uintptr_t>(sink)) + ".unp");
        const auto outcome = facade::unpack_sample_impl(sample, options);
        EXPECT_FALSE(outcome.failure.has_value()) << outcome.failure->message;
        *sink = outcome.work_dir;
    };
    std::thread first([&] { run_unpack(&first_dir); });
    std::thread second([&] { run_unpack(&second_dir); });
    first.join();
    second.join();
    EXPECT_FALSE(first_dir.empty());
    EXPECT_FALSE(second_dir.empty());
    // Process-unique staging: two concurrent calls never share a directory.
    EXPECT_NE(first_dir, second_dir);
    EXPECT_NE(first_dir.filename(), "sheller_unpack");
}

TEST(AnalysisFacade, SampleAnalysisSavesSnapshotOnlyWhenRequested)
{
    // The capture route: the save path gets the capture's exact bytes, and
    // no snapshot file exists without the request.
    const fs::path sample = SHELLER_SAMPLE_HELLO_PATH;
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    const auto saved = dir / "hello_saved.snap";

    sheller::AnalysisOptions save_options;
    save_options.save_snapshot = saved;
    const auto result = facade::analyze_path_impl(sample, save_options);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    ASSERT_TRUE(fs::exists(saved));
    std::ifstream in(saved, std::ios::binary);
    std::array<char, 8> magic{};
    in.read(magic.data(), static_cast<std::streamsize>(magic.size()));
    const std::string_view magic_view{magic.data(), magic.size()};
    EXPECT_EQ(magic_view, "SHELLSNP");

    const auto not_saved = dir / "hello_unsaved.snap";
    sheller::AnalysisOptions default_options;
    const auto plain = facade::analyze_path_impl(sample, default_options);
    ASSERT_TRUE(plain.has_value()) << plain.error().message;
    EXPECT_FALSE(fs::exists(not_saved));
}

TEST(AnalysisFacade, SaveSnapshotWriteFailureIsCaptureClass)
{
    const fs::path sample = SHELLER_SAMPLE_HELLO_PATH;
    sheller::AnalysisOptions options;
    // A path under a nonexistent directory cannot be written.
    options.save_snapshot =
        sheller_test::temp_path("sheller_facade_test") / "no" / "such" / "dir" / "x.snap";
    const auto result = facade::analyze_path_impl(sample, options);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, sheller::AnalysisFailure::Kind::kCapture);
    EXPECT_EQ(result.error().capture_status, sheller::capture::Status::kWriteFailed);
    EXPECT_NE(result.error().message.find("snapshot"), std::string::npos);
}

TEST(AnalysisFacade, UnpackRepairFailureCarriesArtifactsAndCleansUp)
{
    // hello terminates cleanly but never dirties its own image, so the dump
    // has no repairable region: the repair stage fails visibly, the run's
    // artifacts ride both outcome shapes, and the generated work directory
    // does not outlive the failed call.
    const fs::path sample = SHELLER_SAMPLE_HELLO_PATH;
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    sheller::UnpackOptions options;
    options.output = dir / "hello.unp";
    const auto outcome = facade::unpack_sample_impl(sample, options);
    ASSERT_TRUE(outcome.failure.has_value());
    EXPECT_EQ(outcome.failure->kind, sheller::AnalysisFailure::Kind::kRun);
    EXPECT_NE(outcome.failure->message.find("repairable image region"), std::string::npos);
    EXPECT_TRUE(outcome.output.empty());
    // W2 net: the outcome's own artifacts block is filled (not just the
    // failure's copy) and says the instrumentation was real.
    EXPECT_TRUE(outcome.artifacts.instrumented);
    EXPECT_TRUE(outcome.failure->artifacts.instrumented);
    ASSERT_TRUE(outcome.artifacts.run_stats.has_value());
    EXPECT_TRUE(outcome.artifacts.run_stats->terminated);
    // W3 net: the generated staging directory was cleaned up on failure.
    EXPECT_FALSE(fs::exists(outcome.work_dir));
}

TEST(AnalysisFacade, UnpackBudgetOverridesBoundTheRun)
{
    // The host's budget fields flow into the run: a wall-clock bound far
    // below the packed decompression (~3 s) stops the run as a timeout with
    // partial statistics, and no dump follows - the repair stage never
    // starts.
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    sheller::UnpackOptions options;
    options.output = dir / "packed_bounded.unp";
    options.timeout_ms = 100;
    const auto outcome = facade::unpack_sample_impl(sample, options);
    ASSERT_TRUE(outcome.failure.has_value());
    EXPECT_EQ(outcome.failure->kind, sheller::AnalysisFailure::Kind::kRun);
    EXPECT_NE(outcome.failure->message.find("timeout"), std::string::npos);
    ASSERT_TRUE(outcome.failure->run.has_value());
    EXPECT_EQ(outcome.failure->run->error, sheller::engine::SyscallRunError::kTimeout);
    EXPECT_GT(outcome.failure->run->stats.blocks, 0u);
    // Partial statistics ride both artifact shapes; nothing was written.
    ASSERT_TRUE(outcome.artifacts.run_stats.has_value());
    EXPECT_GT(outcome.artifacts.run_stats->blocks, 0u);
    EXPECT_TRUE(outcome.output.empty());
    EXPECT_FALSE(fs::exists(options.output));
    EXPECT_FALSE(fs::exists(outcome.work_dir));
}

TEST(AnalysisFacade, UnpackXferStopKeepsThePipelineSuccessful)
{
    // The OEP jump closes the unpack run as a success: the outcome carries no
    // failure, the stop is visible in run_stats, and dump/repair still land
    // the image.
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    sheller::UnpackOptions options;
    options.output = dir / "packed_xfer.unp";
    options.xfer_number = 1;
    options.max_instructions = 50000000;
    options.timeout_ms = 300000;
    const auto outcome = facade::unpack_sample_impl(sample, options);
    ASSERT_FALSE(outcome.failure.has_value()) << outcome.failure->message;
    ASSERT_TRUE(outcome.artifacts.run_stats.has_value());
    EXPECT_TRUE(outcome.artifacts.run_stats->xfer_stop);
    EXPECT_FALSE(outcome.artifacts.run_stats->terminated);
    EXPECT_EQ(outcome.artifacts.run_stats->xfers, 1U);
    EXPECT_TRUE(fs::exists(outcome.output));
}

TEST(AnalysisFacade, UnpackXferStopVetoesTheWallClockMidLeg)
{
    // The delay sample's loop is cut across legs by the admit-compute probe, so
    // the crossing into text2 ends a leg the 1ms wall clock was already crossed
    // before - and no leg-boundary clock check runs in between. A finish-time
    // timeout would discard the dump and leave repair with nothing; the xfer
    // stop must still land the image.
    const fs::path sample = SHELLER_SAMPLE_XFER_DELAY_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "delay xfer sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    sheller::UnpackOptions options;
    options.output = dir / "xfer_delay.unp";
    options.xfer_number = 1;
    options.max_instructions = 0;
    options.timeout_ms = 1;
    const auto outcome = facade::unpack_sample_impl(sample, options);
    ASSERT_FALSE(outcome.failure.has_value()) << outcome.failure->message;
    ASSERT_TRUE(outcome.artifacts.run_stats.has_value());
    EXPECT_TRUE(outcome.artifacts.run_stats->xfer_stop);
    EXPECT_FALSE(outcome.artifacts.run_stats->terminated);
    EXPECT_EQ(outcome.artifacts.run_stats->syscalls, 0U);
    EXPECT_TRUE(fs::exists(outcome.output));
}

TEST(AnalysisFacade, UnpackTimelineAndSaveSnapshotDeliver)
{
    // P2 facade increment (P1 review W4): the timeline option lights the ledger
    // slot (the packed run far exceeds the ring, so the loss counter is
    // nonzero), and --save-snapshot writes the exact bytes the run consumed.
    // Defaults keep both silent.
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    if (!fs::exists(sample)) {
        GTEST_SKIP() << "packed sample not present on this host";
    }
    const auto dir = sheller_test::temp_path("sheller_facade_test");
    fs::create_directories(dir);
    sheller::UnpackOptions options;
    options.output = dir / "packed_tl.unp";
    options.timeline = true;
    options.save_snapshot = dir / "packed_mid.snap";
    const auto outcome = facade::unpack_sample_impl(sample, options);
    ASSERT_FALSE(outcome.failure.has_value()) << outcome.failure->message;
    EXPECT_FALSE(outcome.artifacts.timeline_tlv.empty());
    EXPECT_GT(outcome.artifacts.timeline_dropped, 0u);
    ASSERT_TRUE(fs::exists(options.save_snapshot));
    std::ifstream mid(options.save_snapshot, std::ios::binary);
    char magic[8] = {};
    mid.read(magic, sizeof magic);
    const std::string_view magic_view{magic, sizeof magic};
    EXPECT_EQ(magic_view, "SHELLSNP");
}
#endif

TEST(UnpackSelection, RequiresDllCoverageAndKeepsSamplePartial)
{
    using sheller::unpack::RegionRepairReport;
    using sheller::unpack::RepairVerdict;
    std::vector<RegionRepairReport> regions{{.base = 0x180000000,
                                             .size = 0x2000,
                                             .verdict = RepairVerdict::kPartial,
                                             .uncovered = {},
                                             .residual_abs_va = {},
                                             .detail = {}},
                                            {.base = 0x7ff000000000,
                                             .size = 0x2000,
                                             .verdict = RepairVerdict::kComplete,
                                             .uncovered = {},
                                             .residual_abs_va = {},
                                             .detail = {}}};
    EXPECT_EQ(facade::select_unpack_region(regions, 0x180000000, true), &regions[0]);
    regions[0].verdict = RepairVerdict::kFailed;
    EXPECT_EQ(facade::select_unpack_region(regions, 0x180000000, true), nullptr);
    EXPECT_EQ(facade::select_unpack_region(regions, 0x180000000, false), &regions[1]);
    EXPECT_EQ(facade::select_unpack_region({}, 0x180000000, true), nullptr);
}

TEST(NameTableAttribution, RuntimeRegistrationsRenderTransfersAcrossRetryIndexes)
{
    sheller::TimelineNameTable names;
    names.modules.emplace_back("runner.exe");
    names.sections.push_back({"headers"});
    facade::SemanticCollector collector(names);
    sheller::behavior::EventTally tally;
    sheller::behavior::BehaviorRules rules(sheller::behavior::BehaviorRulesParams{});
    facade::EventStream stream(&rules, tally, collector, nullptr, {}, ~std::uint64_t{0});
    sheller::engine::SyscallRunOptions run;
    const auto facts = facade::install_behavior_sinks(run, stream, &names);
    ASSERT_TRUE(facts.module_sink);
    sheller::engine::mem_region::ModuleImage image;
    std::memcpy(image.module.name.data(), "arrived.dll", 12);
    image.module.base = 0x180000000;
    image.module.size = 0x3000;
    image.header_bytes.resize(0x400);
    const auto w16 = [&](std::size_t at, std::uint16_t v) {
        std::memcpy(image.header_bytes.data() + at, &v, sizeof v);
    };
    const auto w32 = [&](std::size_t at, std::uint32_t v) {
        std::memcpy(image.header_bytes.data() + at, &v, sizeof v);
    };
    w16(0, 0x5A4D);
    w32(0x3C, 0x40);
    w32(0x40, 0x4550);
    w16(0x46, 1);
    w16(0x54, 0xF0);
    w16(0x58, 0x20B);
    w32(0x78, 0x1000);
    w32(0x90, 0x3000);
    w32(0x94, 0x400);
    std::memcpy(image.header_bytes.data() + 0x148, ".text", 6);
    w32(0x150, 0x1000);
    w32(0x154, 0x1000);
    w32(0x158, 0x1000);
    w32(0x16C, 0x60000020);
    for (std::uint8_t index : std::array<std::uint8_t, 2>{12, 13}) {
        image.module.base += 0x10000;
        facts.module_sink(index, image);
        const std::array<std::uint8_t, 8> fields{index, 0, 1, 0, index, 0, 1, 0};
        run.event_sink(sheller::EventTypeId::kXfer, {}, fields);
    }
    const auto events = collector.take();
    ASSERT_EQ(events.size(), 2U);
    for (const auto& event : events) {
        EXPECT_EQ(event.from_module, "arrived.dll");
        EXPECT_EQ(event.to_module, "arrived.dll");
        EXPECT_EQ(event.from_section, ".text");
        EXPECT_EQ(event.to_section, ".text");
    }
    EXPECT_EQ(names.modules[0], "runner.exe");
    EXPECT_EQ(names.modules[12], "arrived.dll");
    EXPECT_EQ(names.modules[13], "arrived.dll");
}
