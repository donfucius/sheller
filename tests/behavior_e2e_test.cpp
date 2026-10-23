// Behavior e2e: capture the synthetic read-mode sample, run it through the
// engine with the facade's real event stream tee attached, and assert the
// judgment events - plus the determinism contract (same snapshot, same
// report).
//
// The rig below uses the production EventStream (src/api/wiring.cpp): one
// whole-run cursor, fact forwarding and the judgment drain, so these cases
// exercise the same numbering and delivery path the CLI gets.

#include "behavior_rules.h"
#include "capture_detail.h"
#include "event_ledger.h"
#include "probe_params.hpp"
#include "report_events.h"
#include "wiring.h"

#include <sheller/capture.h>
#include <sheller/syscallrun.h>

#include "../engine/rebuild_probe.h"

#include <gtest/gtest.h>

#include "render_test_util.hpp"

#include <cstdint>
#include <filesystem>
#include <functional>
#include <span>
#include <string>
#include <vector>

namespace fs = std::filesystem;

namespace {

fs::path capture_to(const char* sample_path, const std::string& name)
{
    const auto dir = fs::temp_directory_path() / "sheller_behavior_e2e";
    fs::create_directories(dir);
    const auto snapshot = dir / name;
    const auto captured = sheller::capture::detail::run_impl(
        sheller::capture::Options{.sample_path = sample_path, .output_path = snapshot});
    EXPECT_EQ(captured.status, sheller::capture::Status::kOk) << captured.detail;
    return snapshot;
}

// Bit mask selecting every judgment id: the host tap in these cases cares
// about judgments, not raw traffic.
constexpr std::uint64_t kJudgmentMask =
    ((std::uint64_t{1} << (static_cast<std::size_t>(sheller::EventTypeId::kKusdAccess) + 1)) - 1) &
    ~((std::uint64_t{1} << static_cast<std::size_t>(sheller::EventTypeId::kPebWalk)) - 1);

// One delivered judgment, decoded from the wire payload the observer gets.
// The payload span is only valid for the duration of the callback, so every
// field (the annotation included) is copied out here.
struct RecordedJudgment {
    sheller::EventTypeId type{};
    sheller::EventPreamble preamble{};
    std::uint64_t address{};
    std::uint64_t aux{};
    std::uint32_t subtype{};
    std::string api;
};

struct HostLog {
    std::vector<RecordedJudgment> judgments;

    void observe(const sheller::EventTypeId type, const sheller::EventPreamble& preamble,
                 const std::span<const std::uint8_t> fields)
    {
        if (!sheller::is_judgment_event(type)) {
            return;
        }
        const auto decoded = sheller::read_judgment(fields);
        if (!decoded.has_value()) {
            return;
        }
        judgments.push_back(RecordedJudgment{type, preamble, decoded->fields.address,
                                             decoded->fields.aux, decoded->fields.subtype,
                                             std::string{decoded->fields.api}});
    }

    [[nodiscard]] bool has(const sheller::EventTypeId type) const
    {
        return count(type) != 0;
    }

    [[nodiscard]] std::size_t count(const sheller::EventTypeId type) const
    {
        std::size_t out = 0;
        for (const auto& judgment : judgments) {
            out += judgment.type == type ? 1 : 0;
        }
        return out;
    }

    [[nodiscard]] std::string dump() const
    {
        std::string out;
        for (const auto& judgment : judgments) {
            out += sheller::event_type_name(judgment.type);
            out += ':' + std::to_string(judgment.preamble.seq);
            out += ':' + std::to_string(judgment.preamble.tid);
            out += ':' + std::to_string(judgment.preamble.pc);
            out += ':' + std::to_string(judgment.address);
            out += ':' + std::to_string(judgment.aux);
            out += ':' + std::to_string(judgment.subtype);
            out += ':';
            out += judgment.api;
            out += '\n';
        }
        return out;
    }
};

// The production tee around the rules layer, a tally, a semantic collector
// and a ledger - exactly the CLI's internal wiring. The names table must
// outlive the collector (it holds a reference).
struct RunRig {
    explicit RunRig(sheller::behavior::BehaviorRulesParams params)
        : rules(std::move(params)), collector(names)
    {
    }

    std::expected<sheller::engine::SyscallRunStats, sheller::engine::SyscallRunFailure>
    run(const fs::path& snapshot, const std::uint32_t timeout_ms = 30000)
    {
        sheller::api::detail::EventStream stream(
            &rules, tally, collector, &ledger,
            [this](const sheller::EventTypeId type, const sheller::EventPreamble& preamble,
                   const std::span<const std::uint8_t> fields) {
                host.observe(type, preamble, fields);
            },
            kJudgmentMask);
        sheller::engine::SyscallRunOptions options;
        const sheller::engine::FactChannel facts =
            sheller::api::detail::install_behavior_sinks(options, stream);
        options.timeout_ms = timeout_ms;
        return sheller::engine::detail::run_snapshot_syscalls_with_facts(snapshot, options, facts);
    }

    sheller::behavior::BehaviorRules rules;
    sheller::TimelineNameTable names;
    sheller::api::detail::SemanticCollector collector;
    sheller::behavior::EventTally tally;
    sheller::behavior::EventLedger ledger;
    HostLog host;
};

} // namespace

TEST(BehaviorE2E, SampleTriggersReadModeJudgments)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_BEHAVIOR_PATH, "behavior.snap");
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot);
    ASSERT_TRUE(probe.has_value());

    RunRig rig(behavior_params_from_probe(*probe));
    const auto stats = rig.run(snapshot);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x1234U);

    // the entry chain: PEB walk, the BeingDebugged probe, the call-pop pair,
    // and the unregistered direct syscall
    EXPECT_TRUE(rig.host.has(sheller::EventTypeId::kPebWalk));
    EXPECT_TRUE(rig.host.has(sheller::EventTypeId::kGetPc));
    EXPECT_TRUE(rig.host.has(sheller::EventTypeId::kDirectSyscall));
    EXPECT_TRUE(rig.host.has(sheller::EventTypeId::kAntiDebug));
    // the sample only issues direct syscalls: nothing lands in ntdll stubs
    EXPECT_FALSE(rig.host.has(sheller::EventTypeId::kIndirectSyscall));
}

TEST(BehaviorE2E, NestedDelayLoopIsFastForwarded)
{
    // Outer 16 x inner 100000h counter delay, then terminate. The default 1M
    // instruction budget cannot reach the terminate syscall unless the
    // burn-loop fast-forward skips the inner loop and the cached exit covers
    // the outer re-entries; the loop-skip event is the regression guard.
    const auto snapshot = capture_to(SHELLER_SAMPLE_DELAY_PATH, "behavior_delay.snap");
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot);
    ASSERT_TRUE(probe.has_value());

    RunRig rig(behavior_params_from_probe(*probe));
    const auto stats = rig.run(snapshot);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x1234U);
    EXPECT_TRUE(rig.host.has(sheller::EventTypeId::kLoopSkip));
    EXPECT_LT(stats->blocks, 100000U);
}

TEST(BehaviorE2E, TimelineRendersAttributedEventStream)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_BEHAVIOR_PATH, "behavior_timeline.snap");
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot);
    ASSERT_TRUE(probe.has_value());

    RunRig rig(behavior_params_from_probe(*probe));
    const auto stats = rig.run(snapshot);
    ASSERT_TRUE(stats.has_value());

    sheller::TimelineNameTable names;
    for (const auto& image : probe->images) {
        names.modules.emplace_back(image.module.name.data());
        names.sections.emplace_back(); // this sample's sections stay unnamed
    }
    names.syscalls.emplace(0xBEEF, "NtSmokeTest");
    const auto json = render_full_events(rig.ledger, names);

    // every event made it: the two syscalls are contract facts; the
    // block-exec count is the sample binary's codegen shape (it has already
    // moved once with the toolchain) - pin the floor, not the shape
    EXPECT_EQ(rig.ledger.count_of(sheller::EventTypeId::kSyscall), 2U);
    const auto blocks = rig.ledger.count_of(sheller::EventTypeId::kBlockExec);
    EXPECT_GE(blocks, 1U);
    // Forwarded facts and judgment events ride the same ring now.
    EXPECT_GE(rig.ledger.size(), blocks + 2U);
    EXPECT_NE(json.find("\"type\":\"block-exec\""), std::string::npos);
    EXPECT_NE(json.find("\"type\":\"syscall\""), std::string::npos);
    EXPECT_NE(json.find("\"num\":\"0xbeef\""), std::string::npos);
    EXPECT_NE(json.find("\"api\":\"NtSmokeTest\""), std::string::npos);
    // determinism: byte-identical re-render
    EXPECT_EQ(json, render_full_events(rig.ledger, names));
}

TEST(BehaviorE2E, DeterministicJudgmentStreamAcrossRuns)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_BEHAVIOR_PATH, "behavior_determinism.snap");
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot);
    ASSERT_TRUE(probe.has_value());

    const auto run = [&] {
        RunRig rig(behavior_params_from_probe(*probe));
        static_cast<void>(rig.run(snapshot));
        return rig.host.dump();
    };
    const auto first = run();
    const auto second = run();
    EXPECT_EQ(first, second);
    EXPECT_FALSE(first.empty());
}

TEST(BehaviorE2E, ReportEventsBindToLedgerAndRepeatByteIdentically)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_BEHAVIOR_PATH, "behavior_report.snap");
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot);
    ASSERT_TRUE(probe.has_value());

    const auto run_wired = [&](RunRig& rig) {
        static_cast<void>(rig.run(snapshot));
        return "{\"events\":" + sheller::cli::render_events_section(artifacts_for(rig.tally)) + "}";
    };

    RunRig rig(behavior_params_from_probe(*probe));
    const auto report = run_wired(rig);

    // binding: the report's counting source equals the ledger's cumulative
    // per-type counts for every known type, and each nonzero count is spelled
    // in the rendered events section
    const auto events = sheller::cli::render_events_section(artifacts_for(rig.tally));
    for (std::size_t id = 0; id < sheller::kEventTypeCount; ++id) {
        const auto type = static_cast<sheller::EventTypeId>(id);
        ASSERT_EQ(rig.tally.count_of(type), rig.ledger.count_of(type)) << "event type id " << id;
        const auto count = rig.ledger.count_of(type);
        if (count != 0) {
            EXPECT_NE(events.find(std::string(sheller::kEventTypeNames[id]) +
                                  "\":" + std::to_string(count)),
                      std::string::npos)
                << "event type id " << id;
        }
    }
    EXPECT_NE(report.find("{\"events\":{\"counts\":{"), std::string::npos);
    EXPECT_EQ(report.find("\"signals\""), std::string::npos);

    // same snapshot, fresh collectors: byte-identical report
    RunRig rig2(behavior_params_from_probe(*probe));
    EXPECT_EQ(report, run_wired(rig2));
}

TEST(BehaviorE2E, VehSampleProducesHandlerJudgments)
{
    // the VEH sample registers its handler through the real ntdll and takes
    // two faults: the registration call straight out of sample code and the
    // staged handler callbacks both carry attribution now
    const auto snapshot = capture_to(SHELLER_SAMPLE_SEH_VEH_PATH, "behavior_veh.snap");
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot);
    ASSERT_TRUE(probe.has_value());

    RunRig rig(behavior_params_from_probe(*probe));
    const auto stats = rig.run(snapshot);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5678U);

    // the registration call came straight out of the sample:
    // exception-handler-install with the ntdll!RtlAddVectoredExceptionHandler
    // annotation
    EXPECT_TRUE(rig.host.has(sheller::EventTypeId::kExceptionHandlerInstall));
    for (const auto& judgment : rig.host.judgments) {
        if (judgment.type == sheller::EventTypeId::kExceptionHandlerInstall) {
            EXPECT_NE(judgment.api.find("RtlAddVectoredExceptionHandler"), std::string::npos)
                << "exception-handler-install api='" << judgment.api << "'";
        }
    }
    // the staged handler callbacks report handler-dispatch with attribution
    bool handler_dispatch = false;
    for (const auto& judgment : rig.host.judgments) {
        if (judgment.type == sheller::EventTypeId::kExceptionDisposition &&
            judgment.subtype ==
                static_cast<std::uint32_t>(sheller::ExceptionDisposition::kHandlerDispatch)) {
            handler_dispatch = true;
            EXPECT_NE(judgment.preamble.pc, 0U);
        }
    }
    EXPECT_TRUE(handler_dispatch);
}
