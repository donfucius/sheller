// Event-stream baseline tests: every deterministic-
// termination corpus sample gets one digest over the relocation-normalized
// event stream, so a recaptured snapshot (fresh ASLR layout) still matches
// the committed golden. Portable: the XXH64 anchor vectors run on every
// platform; the corpus comparisons need the Windows capture route.

#include "capture_detail.h"
#include "event_ledger.h"
#include "probe_params.hpp"
#include "wiring.h"

#include <sheller/events.h>
#include <sheller/snapshot.h>
#include <sheller/syscallrun.h>
#include <xxhash.h>

#include <gtest/gtest.h>

#ifdef _WIN32
#include <sheller/capture.h>
#endif

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <utility>
#include <vector>

namespace {

namespace ev = sheller;
namespace behavior = sheller::behavior;
namespace fs = std::filesystem;

TEST(EventBaselineHash, Xxh64AnchorVector)
{
    // The empty-stream digest from the xxHash spec anchors the integration;
    // digest stability is what the committed baselines rely on.
    EXPECT_EQ(XXH64(nullptr, 0, 0), 0xef46db3751d8e999ULL);
}

TEST(EventBaselineHash, DistinctStreamsGetDistinctDigests)
{
    const behavior::EventLedger a;
    const behavior::EventLedger b;
    const std::vector<std::uint8_t> one{1, 2, 3};
    const std::vector<std::uint8_t> two{1, 2, 4};
    const auto da = XXH64(one.data(), one.size(), 0);
    const auto db = XXH64(two.data(), two.size(), 0);
    EXPECT_NE(da, db);
}

#ifdef _WIN32

void append_le(std::vector<std::uint8_t>& out, const std::uint64_t value, const std::size_t bytes)
{
    for (std::size_t i = 0; i < bytes; ++i) {
        out.push_back(static_cast<std::uint8_t>(value >> (8 * i)));
    }
}

// Canonical stream: [type u16][seq u64][tid u32][pc-entry u64][field_count u8]
// [fields], with block-exec's addr field made entry-relative. Non-address
// payload (the syscall number) stays as produced - it carries no layout.
// The syscall event's argument words do carry layout (a caller register can
// hold an image or stack address, whose low half moves with ASLR), so the
// canonical projection keeps only the leading number.
std::vector<std::uint8_t> normalized_stream(const behavior::EventLedger& ledger,
                                            const std::uint64_t entry_base)
{
    std::vector<std::uint8_t> out;
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        const auto item = ledger.entry(i);
        append_le(out, static_cast<std::uint64_t>(item.type), 2);
        append_le(out, item.preamble.seq, 8);
        append_le(out, item.preamble.tid, 4);
        append_le(out, item.preamble.pc - entry_base, 8);

        std::vector<std::uint8_t> fields(item.type_fields.begin(), item.type_fields.end());
        if (item.type == ev::EventTypeId::kBlockExec && fields.size() >= sizeof(std::uint64_t)) {
            const std::uint64_t addr = ev::le::load_le64(fields.data());
            for (std::size_t byte = 0; byte < sizeof(std::uint64_t); ++byte) {
                fields[byte] = static_cast<std::uint8_t>((addr - entry_base) >> (8 * byte));
            }
        }
        if (item.type == ev::EventTypeId::kSyscall && fields.size() > sizeof(std::uint32_t)) {
            fields.resize(sizeof(std::uint32_t));
        }
        // Forwarded facts and judgments carry addresses that move with ASLR
        // independently of the entry point (stack, heap, system modules):
        // zero them, keep the type/order/pc pins and the non-address judgment
        // fields (subtype, annotation). Payload round-trips are covered by
        // event_ledger_test.
        if ((item.type == ev::EventTypeId::kMemRead || item.type == ev::EventTypeId::kMemWrite) &&
            fields.size() >= ev::kMemAccessFixedBytes) {
            std::fill(fields.begin(), fields.end(), std::uint8_t{0});
        }
        if (ev::is_judgment_event(item.type) && fields.size() >= ev::kJudgmentFixedBytes) {
            std::fill(fields.begin(), fields.begin() + ev::kJudgmentAuxOffset + 8, std::uint8_t{0});
        }
        append_le(out, fields.size(), 1);
        out.insert(out.end(), fields.begin(), fields.end());
    }
    return out;
}

std::string stream_digest(const behavior::EventLedger& ledger, const std::uint64_t entry_base)
{
    const auto stream = normalized_stream(ledger, entry_base);
    return std::format("{:016x}", XXH64(stream.data(), stream.size(), 0));
}

// Corpus runner: capture once, run with a ledger sink, return the digest
// inputs. Budget-exhausted termination is deterministic and
// therefore baseline-eligible like a normal exit.
struct BaselineRun {
    behavior::EventLedger ledger;
    std::uint64_t entry_base{};
    bool completed{};
};

BaselineRun run_corpus(const char* sample_path, const std::string& snapshot_name,
                       const bool expect_budget_exhausted)
{
    const auto dir = fs::temp_directory_path() / "sheller_event_baseline";
    fs::create_directories(dir);
    const auto snapshot = dir / snapshot_name;
    const auto captured = sheller::capture::detail::run_impl(
        sheller::capture::Options{.sample_path = sample_path, .output_path = snapshot});
    EXPECT_EQ(captured.status, sheller::capture::Status::kOk) << captured.detail;

    // The snapshot's entry address anchors the relocation normalization.
    std::ifstream in(snapshot, std::ios::binary);
    sheller::snapshot::Reader reader{in};
    const auto header = reader.read_header();
    const auto registers = reader.read_registers();
    const auto metadata = reader.read_metadata();
    EXPECT_TRUE(header.has_value());
    EXPECT_TRUE(registers.has_value());
    EXPECT_TRUE(metadata.has_value());

    BaselineRun run;
    if (!metadata.has_value()) {
        return run;
    }
    run.entry_base = metadata->entry_address;

    // The baseline covers the delivered stream, not just the engine's raw
    // events: the production tee forwards window facts and drains the rules'
    // judgments, and every crossing takes the one whole-run sequence number.
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot);
    EXPECT_TRUE(probe.has_value());
    if (!probe.has_value()) {
        return run;
    }
    sheller::behavior::BehaviorRules rules(behavior_params_from_probe(*probe));
    sheller::TimelineNameTable names;
    sheller::api::detail::SemanticCollector collector(names);
    sheller::behavior::EventTally tally;
    sheller::api::detail::EventStream stream(&rules, tally, collector, &run.ledger, {}, 0);

    sheller::engine::SyscallRunOptions options;
    const sheller::engine::FactChannel facts =
        sheller::api::detail::install_behavior_sinks(options, stream);
    if (expect_budget_exhausted) {
        options.max_instructions = 100000;
    }
    const auto stats =
        sheller::engine::detail::run_snapshot_syscalls_with_facts(snapshot, options, facts);
    if (expect_budget_exhausted) {
        EXPECT_FALSE(stats.has_value());
        EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kBudgetExhausted);
        run.completed = !stats.has_value() && stats.error().stats.blocks > 0;
    } else {
        EXPECT_TRUE(stats.has_value());
        EXPECT_TRUE(stats->terminated);
        run.completed = stats.has_value() && stats->terminated;
    }
    return run;
}

TEST(EventBaseline, CorpusDigestsMatchGoldens)
{
    // The digest pins the sample binary's LINKED shape, and Debug/Release
    // links legitimately differ (the /O2 link merges basic blocks, so the
    // same source produces a different block sequence). The golden is per
    // config, regenerated per build tree via SHELLER_REGEN_EVENT_BASELINE.
#if defined(_DEBUG)
    constexpr auto kGoldenConfig = "debug";
#else
    constexpr auto kGoldenConfig = "release";
#endif
    const auto golden_name = [&](const char* name) {
        return std::format("event_stream_{}.{}.xxh64", name, kGoldenConfig);
    };

    const auto hello = run_corpus(SHELLER_SAMPLE_HELLO_PATH, "baseline_hello.snap", false);
    const auto deny = run_corpus(SHELLER_SAMPLE_DENY_PATH, "baseline_deny.snap", false);
    const auto spin = run_corpus(SHELLER_SAMPLE_SPIN_PATH, "baseline_spin.snap", true);
    ASSERT_TRUE(hello.completed);
    ASSERT_TRUE(deny.completed);
    ASSERT_TRUE(spin.completed);

    const std::pair<const char*, std::string> digests[]{
        {"hello", stream_digest(hello.ledger, hello.entry_base)},
        {"deny", stream_digest(deny.ledger, deny.entry_base)},
        {"spin", stream_digest(spin.ledger, spin.entry_base)},
    };

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996) // getenv is fine in a test
#endif
    const char* const regenerate = std::getenv("SHELLER_REGEN_EVENT_BASELINE");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (regenerate != nullptr && *regenerate != '\0') {
        for (const auto& [name, digest] : digests) {
            std::ofstream out(std::format("{}/{}", regenerate, golden_name(name)), std::ios::trunc);
            out << digest << '\n';
            ASSERT_TRUE(out) << "cannot write baseline: " << name;
        }
        GTEST_SKIP() << "baselines regenerated at " << regenerate;
    }

    for (const auto& [name, digest] : digests) {
        const auto path = std::format("{}/{}", SHELLER_EVENT_GOLDEN_DIR, golden_name(name));
        std::ifstream golden(path);
        ASSERT_TRUE(golden) << "baseline missing: " << path
                            << " (regenerate via SHELLER_REGEN_EVENT_BASELINE)";
        std::string expected((std::istreambuf_iterator<char>(golden)),
                             std::istreambuf_iterator<char>());
        while (!expected.empty() && (expected.back() == '\n' || expected.back() == '\r')) {
            expected.pop_back();
        }
        EXPECT_EQ(digest, expected) << "event stream drifted for " << name;
    }
}

TEST(EventBaseline, RecapturedSnapshotDigestsEqual)
{
    // Two independent captures -> two ASLR layouts; the entry-relative
    // normalization must collapse them onto the same digest. This is what
    // makes the committed baselines machine- and build-independent.
    const auto a = run_corpus(SHELLER_SAMPLE_HELLO_PATH, "relayout_a.snap", false);
    const auto b = run_corpus(SHELLER_SAMPLE_HELLO_PATH, "relayout_b.snap", false);
    ASSERT_TRUE(a.completed);
    ASSERT_TRUE(b.completed);
    EXPECT_EQ(stream_digest(a.ledger, a.entry_base), stream_digest(b.ledger, b.entry_base));
}

#endif // _WIN32

} // namespace
