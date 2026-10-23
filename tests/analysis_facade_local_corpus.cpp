// Local-corpus equivalence for the analysis facade (EXCLUDE_FROM_ALL: NOT
// built by default). The pinned faces live here because the corpora are
// local: the instoll capture is gitignored local corpus, and the packed
// sample needs a Windows capture host. CI's facade smoke runs on the
// synthetic golden via analysis_facade_test instead.
//
// Build and run explicitly for review:
//   cmake --build --preset windows-release --target analysis_facade_local_corpus
//   build\windows-release\tests\Release\analysis_facade_local_corpus.exe
//
// instoll path: the analyzed run30 capture from the compile definition,
// overridable with the SHELLER_INSTOLL_SNAP environment variable.
//
// Pinned faces (unified event stream):
//   instoll: 57077 block-exec + 5 syscall (3 rejected) + 1 rdtsc + 0 xfer
//            + 16 mem-write + 180211 sample-code; the default stream is 6
//            records (5 syscall + rdtsc), rdtsc's ordinal 87324; the 16
//            mem-write instances stay in counts (none is a sample-code write
//            into a system module); the window fills and evicts.
//   packed:  1 xfer (the OEP jump), exactly 1 oep-candidate event.

// getenv carries a safe-deprecation note on MSVC; the override is the point.
// The define must precede every include (the sheller headers pull <cstdlib>).
#ifdef _WIN32
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "wiring.h"
#include <sheller/analysis.h>
#include <sheller/events.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace {

namespace facade = sheller::api::detail;
namespace fs = std::filesystem;

fs::path instoll_snapshot()
{
    if (const char* env = std::getenv("SHELLER_INSTOLL_SNAP"); env != nullptr) {
        return fs::path{env};
    }
    return fs::path{SHELLER_INSTOLL_SNAPSHOT};
}

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
        EXPECT_TRUE(view.has_value());
        if (!view.has_value()) {
            break;
        }
        const auto preamble = sheller::read_preamble(view->payload);
        EXPECT_TRUE(preamble.has_value());
        if (!preamble.has_value()) {
            break;
        }
        events.push_back({view->type, *preamble});
        cursor += view->total_size;
    }
    return events;
}

} // namespace

TEST(LocalCorpus, InstollEventCountsAndOrderArePinned)
{
    const auto snapshot = instoll_snapshot();
    if (!fs::exists(snapshot)) {
        GTEST_SKIP() << "instoll snapshot not present on this host (" << snapshot.string() << ")";
    }
    sheller::AnalysisOptions options;
    // Full-run equivalence: unlimited instruction budget (the default 1M
    // stops mid-run with a truncated face), generous wall clock.
    options.run.max_instructions = 0;
    options.run.timeout_ms = 600000;
    options.timeline = true;
    const auto result = facade::analyze_path_impl(snapshot, options);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    const auto& artifacts = result.value();

    // Arming an unreachable target leaves the run alone. The load-bearing part
    // is the agreement between the counter and the emitted xfer events: the
    // counter skips burn-loop probe speculation while the emitter does not, so
    // equality pins that no probe crossed an attribution-identity boundary on
    // this corpus (instoll has no transfer at all).
    sheller::AnalysisOptions with_xfer = options;
    with_xfer.run.xfer_number = 2;
    const auto with_target = facade::analyze_path_impl(snapshot, with_xfer);
    ASSERT_TRUE(with_target.has_value()) << with_target.error().message;
    ASSERT_TRUE(with_target->run_stats.has_value());
    EXPECT_FALSE(with_target->run_stats->xfer_stop);
    EXPECT_EQ(with_target->run_stats->xfers, 0u);
    EXPECT_EQ(with_target->event_counts[static_cast<std::size_t>(sheller::EventTypeId::kXfer)], 0u);

    EXPECT_TRUE(artifacts.instrumented);
    ASSERT_TRUE(artifacts.run_stats.has_value());
    EXPECT_TRUE(artifacts.run_stats->terminated);
    EXPECT_EQ(artifacts.run_stats->rejects, 3u);

    EXPECT_EQ(artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kBlockExec)],
              57077u);
    EXPECT_EQ(artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kSyscall)], 5u);
    EXPECT_EQ(artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kRdtsc)], 1u);
    EXPECT_EQ(artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kXfer)], 0u);

    // Semantic tier: the default column contains the timing probe and the
    // syscalls. All 16 page writes are sample/stack/private targets or have a
    // non-sample writer, so they stay in counts (the system-DLL/sample-writer
    // pair is the pinned exception). The rdtsc's whole-run ordinal moved with
    // the forwarded instruction stream (the sample-code events are window-side
    // but still consume numbers): 87324.
    ASSERT_EQ(artifacts.semantic_events.size(), 6u);
    const sheller::SemanticEvent* rdtsc = nullptr;
    const sheller::SemanticEvent* last_syscall = nullptr;
    std::size_t mem_writes = 0;
    for (const auto& event : artifacts.semantic_events) {
        if (event.type == sheller::EventTypeId::kMemWrite) {
            ++mem_writes;
        }
        if (event.type == sheller::EventTypeId::kRdtsc) {
            rdtsc = &event;
        }
        if (event.type == sheller::EventTypeId::kSyscall) {
            last_syscall = &event;
        }
    }
    ASSERT_NE(rdtsc, nullptr);
    EXPECT_EQ(artifacts.semantic_events[0].type, sheller::EventTypeId::kRdtsc);
    EXPECT_EQ(rdtsc->wire_seq, 87324u);
    EXPECT_EQ(mem_writes, 0u);
    EXPECT_EQ(artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kMemWrite)],
              16u);
    ASSERT_NE(last_syscall, nullptr);
    EXPECT_EQ(last_syscall->syscall_name, "NtTerminateThread");

    // instoll carries no OEP candidate (no walk, no probes on this path).
    EXPECT_TRUE(artifacts.oep_candidates.empty());

    // The window fills with the window-side stream (sample-code dominates),
    // so the ring evicts; the default records still render from the semantic
    // tier. Loss is the ledger's exact eviction count.
    std::uint64_t total = 0;
    for (const auto count : artifacts.event_counts) {
        total += count;
    }
    EXPECT_EQ(artifacts.timeline_dropped, total - 65536);
    const auto tlv_events = decode_tlv(artifacts.timeline_tlv);
    ASSERT_EQ(tlv_events.size(), 65536u);
    for (const auto& event : artifacts.semantic_events) {
        ASSERT_GE(event.wire_seq, 1u);
        const auto joined = std::ranges::find_if(tlv_events, [&](const DecodedEvent& entry) {
            return entry.preamble.seq == event.wire_seq;
        });
        if (joined == tlv_events.end()) {
            continue; // evicted from the ring; the semantic tier still carries it
        }
        EXPECT_EQ(joined->type, event.type);
        EXPECT_EQ(joined->preamble.tid, event.tid);
        EXPECT_EQ(joined->preamble.pc, event.pc);
    }
}

#ifdef _WIN32
TEST(LocalCorpus, PackedJudgmentsArePinned)
{
    const fs::path sample = SHELLER_SAMPLE_PACKED_PATH;
    ASSERT_TRUE(fs::exists(sample));
    sheller::AnalysisOptions options;
    // The UPX stub decompresses several million blocks: unlimited budget
    // (see the packed-corpus note in iat_repair_test) and a generous clock.
    options.run.max_instructions = 0;
    options.run.timeout_ms = 600000;
    options.timeline = true;
    const auto result = facade::analyze_path_impl(sample, options);
    ASSERT_TRUE(result.has_value()) << result.error().message;
    const auto& artifacts = result.value();

    // The OEP transfer is the only one, so a target of 2 is never reached and
    // the run keeps its normal shape. As with instoll, the load-bearing pin is
    // xfers == the emitted xfer event count: the counter skips burn-loop probe
    // speculation while the emitter does not, so that agreement is the evidence
    // that no probe crossed an attribution-identity boundary on this corpus.
    // The payload's own block/event totals vary between processes
    // (host-dependent work), which is why only this pair is pinned here.
    sheller::AnalysisOptions with_xfer = options;
    with_xfer.run.xfer_number = 2;
    const auto with_target = facade::analyze_path_impl(sample, with_xfer);
    ASSERT_TRUE(with_target.has_value()) << with_target.error().message;
    ASSERT_TRUE(with_target->run_stats.has_value());
    EXPECT_FALSE(with_target->run_stats->xfer_stop);
    EXPECT_EQ(with_target->run_stats->xfers, 1u);
    EXPECT_EQ(with_target->event_counts[static_cast<std::size_t>(sheller::EventTypeId::kXfer)], 1u);

    EXPECT_TRUE(artifacts.instrumented);
    // The unpack pipeline's OEP: exactly one oep-candidate event, and the
    // candidate list mirrors it.
    int oep_events = 0;
    for (const auto& event : artifacts.semantic_events) {
        if (event.type == sheller::EventTypeId::kOepCandidate) {
            ++oep_events;
        }
    }
    EXPECT_EQ(oep_events, 1);
    EXPECT_EQ(artifacts.oep_candidates.size(), 1u);
    // The edge rules' showcase: exactly one xfer, the OEP jump.
    EXPECT_EQ(artifacts.event_counts[static_cast<std::size_t>(sheller::EventTypeId::kXfer)], 1u);

    // The timeline tier resolves the xfer endpoints through the name table:
    // packed.exe sections UPX1 -> UPX0 (the OEP jump; section names ride
    // the PE section table raw - only module names fold to lowercase).
    const auto& events = artifacts.semantic_events;
    bool saw_xfer = false;
    for (const auto& event : events) {
        if (event.type == sheller::EventTypeId::kXfer) {
            saw_xfer = true;
            EXPECT_EQ(event.from_module, "packed.exe");
            EXPECT_EQ(event.from_section, "UPX1");
            EXPECT_EQ(event.to_module, "packed.exe");
            EXPECT_EQ(event.to_section, "UPX0");
        }
    }
    EXPECT_TRUE(saw_xfer);
}
#endif
