// Syscall skeleton end-to-end tests: the three ml64 direct-syscall samples
// run the full "capture -> rebuild -> syscall run" pipeline on Windows; the
// policy table unit checks are portable and cover the pure decision layer.

// First, before gtest: the fixture has to set the nonstandard-name defines before
// any include pulls <io.h> in on Windows (see tests/host_stream_capture.h).
#include "host_stream_capture.h"

#include "capture_detail.h"
#include "event_ledger.h"
#include "syscall_policy.h"

#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#ifdef _WIN32
#include <sheller/capture.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>
#endif

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace {

namespace syscalls = sheller::syscalls;

// Portable policy-table checks: default deny, built-in handlers, overrides.
TEST(SyscallPolicy, UnregisteredNumberDefaultsToAccessDenied)
{
    const syscalls::PolicyTable table;
    const auto& entry = table.entry_for(0xDEAD);
    EXPECT_EQ(entry.kind, syscalls::EntryKind::kReject);
    EXPECT_EQ(entry.reject_status, syscalls::kStatusAccessDenied);
}

TEST(SyscallPolicy, BuiltInNumbersAreHandlers)
{
    const syscalls::PolicyTable table;
    EXPECT_EQ(table.entry_for(syscalls::kNumberWriteFile).kind, syscalls::EntryKind::kHandler);
    EXPECT_EQ(table.entry_for(syscalls::kNumberDelayExecution).kind, syscalls::EntryKind::kHandler);
    EXPECT_EQ(table.entry_for(syscalls::kNumberTerminateProcess).kind,
              syscalls::EntryKind::kHandler);
}

TEST(SyscallPolicy, OverrideReplacesEntry)
{
    syscalls::PolicyTable table;
    table.set_entry(
        syscalls::kNumberWriteFile,
        syscalls::PolicyEntry{.kind = syscalls::EntryKind::kReject, .reject_status = 0xC0000123});
    const auto& entry = table.entry_for(syscalls::kNumberWriteFile);
    EXPECT_EQ(entry.kind, syscalls::EntryKind::kReject);
    EXPECT_EQ(entry.reject_status, 0xC0000123U);
}

#ifdef _WIN32

namespace fs = std::filesystem;

fs::path capture_to(const char* sample_path, const std::string& name)
{
    const auto dir = fs::temp_directory_path() / "sheller_syscall_test";
    fs::create_directories(dir);
    const auto snapshot = dir / name;

    const auto captured = sheller::capture::detail::run_impl(
        sheller::capture::Options{.sample_path = sample_path, .output_path = snapshot});
    EXPECT_EQ(captured.status, sheller::capture::Status::kOk) << captured.detail;
    return snapshot;
}

std::string read_file(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

TEST(SyscallRun, HelloSampleCompletesLifecycle)
{
    std::vector<std::uint8_t> sink;
    sheller::engine::SyscallRunOptions options;
    options.write_sink = [&sink](const std::uint8_t* data, std::size_t size) {
        sink.insert(sink.end(), data, data + size);
    };

    const auto snapshot = capture_to(SHELLER_SAMPLE_HELLO_PATH, "hello.snap");
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error)
        << " (syscalls=" << stats.error().stats.syscalls
        << " rejects=" << stats.error().stats.rejects
        << " terminated=" << stats.error().stats.terminated
        << " exit=" << stats.error().stats.exit_code << " uc=" << stats.error().unicorn_code << ")";

    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x1234U);
    EXPECT_EQ(stats->syscalls, 3U);
    EXPECT_EQ(stats->rejects, 0U);
    EXPECT_EQ(sink.size(), 5U);
    EXPECT_EQ(std::string(sink.begin(), sink.end()), "hello");
}

TEST(SyscallRun, DenySampleObservesRejection)
{
    std::vector<std::uint8_t> sink;
    sheller::engine::SyscallRunOptions options;
    options.write_sink = [&sink](const std::uint8_t* data, std::size_t size) {
        sink.insert(sink.end(), data, data + size);
    };

    const auto snapshot = capture_to(SHELLER_SAMPLE_DENY_PATH, "deny.snap");
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error)
        << " (syscalls=" << stats.error().stats.syscalls
        << " rejects=" << stats.error().stats.rejects
        << " terminated=" << stats.error().stats.terminated
        << " exit=" << stats.error().stats.exit_code << " uc=" << stats.error().unicorn_code << ")";

    // The sample stores rax after the denied syscall and passes it to
    // NtTerminateProcess as the exit code - the ABI write-back, made
    // observable by the guest itself.
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0xC0000022U); // STATUS_ACCESS_DENIED
    EXPECT_EQ(stats->rejects, 1U);
    EXPECT_EQ(stats->syscalls, 2U);
    EXPECT_TRUE(sink.empty());
}

TEST(SyscallRun, SpinSampleExhaustsBudget)
{
    sheller::engine::SyscallRunOptions options;
    options.max_instructions = 100000;

    const auto snapshot = capture_to(SHELLER_SAMPLE_SPIN_PATH, "spin.snap");
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_FALSE(stats.has_value());
    EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kBudgetExhausted);
    EXPECT_EQ(stats.error().stats.syscalls, 0U);
    EXPECT_FALSE(stats.error().stats.terminated);
    // The block counter works with no event sink attached (default-empty
    // options path: zero behavior change, one new observable).
    EXPECT_GT(stats.error().stats.blocks, 0U);
}

// One hello run with a ledger attached through the event sink, dumped to
// both output formats; the ledger, counters, and captured bytes come back
// for assertions.
struct LedgerRun {
    sheller::behavior::EventLedger ledger;
    sheller::engine::SyscallRunStats stats{};
    std::string hello;
};

LedgerRun run_with_ledger(const fs::path& snapshot, const fs::path& tlv_path,
                          const fs::path& json_path)
{
    LedgerRun run;
    std::vector<std::uint8_t> sink;
    sheller::engine::SyscallRunOptions options;
    options.write_sink = [&sink](const std::uint8_t* data, std::size_t size) {
        sink.insert(sink.end(), data, data + size);
    };
    options.event_sink = [&run](const sheller::EventTypeId type,
                                const sheller::EventPreamble& preamble,
                                const std::span<const std::uint8_t> fields) {
        run.ledger.record(type, preamble, fields);
    };

    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    EXPECT_TRUE(stats.has_value());
    if (stats.has_value()) {
        run.stats = *stats;
        EXPECT_TRUE(run.stats.terminated);
        EXPECT_EQ(run.stats.syscalls, 3U);
    }

    run.hello.assign(sink.begin(), sink.end());
    EXPECT_TRUE(run.ledger.write_tlv(tlv_path).has_value());
    EXPECT_TRUE(run.ledger.write_json(json_path).has_value());
    return run;
}

TEST(SyscallRunEventLedger, RepeatedRunsProduceIdenticalStreams)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_HELLO_PATH, "ledger_determinism.snap");
    const auto dir = fs::temp_directory_path() / "sheller_syscall_test";
    fs::create_directories(dir);

    const auto a = run_with_ledger(snapshot, dir / "run_a.tlv", dir / "run_a.json");
    const auto b = run_with_ledger(snapshot, dir / "run_b.tlv", dir / "run_b.json");

    // Event-stream hash stability: same snapshot replayed twice must give
    // byte-identical TLV and JSON dumps (no wall clock anywhere).
    EXPECT_EQ(read_file(dir / "run_a.tlv"), read_file(dir / "run_b.tlv"));
    EXPECT_EQ(read_file(dir / "run_a.json"), read_file(dir / "run_b.json"));
    EXPECT_EQ(a.hello, "hello");
    EXPECT_EQ(b.hello, "hello");
    EXPECT_EQ(a.stats.blocks, b.stats.blocks);
    EXPECT_EQ(a.ledger.size(), b.ledger.size());
}

TEST(SyscallRunEventLedger, HelloLedgerCarriesBlocksAndThreeSyscalls)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_HELLO_PATH, "ledger_hello.snap");
    const auto dir = fs::temp_directory_path() / "sheller_syscall_test";
    const auto run = run_with_ledger(snapshot, dir / "assert.tlv", dir / "assert.json");
    const auto& ledger = run.ledger;

    std::vector<std::uint32_t> numbers;
    std::vector<std::uint64_t> syscall_pcs;
    std::vector<std::uint64_t> block_addrs;
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        const auto entry = ledger.entry(i);
        if (entry.type == sheller::EventTypeId::kSyscall) {
            ASSERT_GE(entry.type_fields.size(), sizeof(std::uint32_t));
            numbers.push_back(sheller::le::load_le32(entry.type_fields.data()));
            syscall_pcs.push_back(entry.preamble.pc);
        } else if (entry.type == sheller::EventTypeId::kBlockExec) {
            ASSERT_GE(entry.type_fields.size(), sizeof(std::uint64_t));
            // The engine stamps the block start into both pc and payload.
            EXPECT_EQ(sheller::le::load_le64(entry.type_fields.data()), entry.preamble.pc);
            block_addrs.push_back(entry.preamble.pc);
        }
    }

    // Guest order: WriteFile, DelayExecution, TerminateProcess - rejects and
    // handlers alike produce the event.
    const std::vector<std::uint32_t> expected_numbers{syscalls::kNumberWriteFile,
                                                      syscalls::kNumberDelayExecution,
                                                      syscalls::kNumberTerminateProcess};
    EXPECT_EQ(numbers, expected_numbers);

    // Every block the hook counted produced an event, and every syscall ran
    // inside a block the ledger saw (block start at or before the syscall pc).
    EXPECT_EQ(ledger.count_of(sheller::EventTypeId::kBlockExec), run.stats.blocks);
    EXPECT_GT(run.stats.blocks, 0U);
    EXPECT_EQ(ledger.dropped(), 0U);
    EXPECT_EQ(ledger.size(), run.stats.blocks + 3U);
    for (const auto pc : syscall_pcs) {
        EXPECT_TRUE(std::any_of(block_addrs.begin(), block_addrs.end(),
                                [pc](const std::uint64_t addr) { return addr <= pc; }));
    }
}

TEST(SyscallRun, RejectOverrideChangesDenyCode)
{
    std::vector<std::uint8_t> sink;
    sheller::engine::SyscallRunOptions options;
    options.write_sink = [&sink](const std::uint8_t* data, std::size_t size) {
        sink.insert(sink.end(), data, data + size);
    };
    options.reject_overrides[0x1000] = 0xC0000123;

    const auto snapshot = capture_to(SHELLER_SAMPLE_HELLO_PATH, "override.snap");
    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    ASSERT_TRUE(stats.has_value())
        << sheller::engine::syscall_run_error_message(stats.error().error)
        << " (syscalls=" << stats.error().stats.syscalls
        << " rejects=" << stats.error().stats.rejects
        << " terminated=" << stats.error().stats.terminated
        << " exit=" << stats.error().stats.exit_code << " uc=" << stats.error().unicorn_code << ")";

    // WriteFile was rejected with the override code instead of writing, and
    // the guest still ran to termination.
    EXPECT_TRUE(sink.empty());
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x1234U);
    EXPECT_EQ(stats->rejects, 1U);
    EXPECT_EQ(stats->syscalls, 3U);
}

// ---------------------------------------------------------------------------
// The guest-output sink's contract, end to end. entry_multi writes three
// separate buffers and then terminates, which is the shape needed to show that a
// host callback throwing on one delivery loses exactly that delivery: with a
// single write in the run there is nothing to compare the loss against.
//
// The four things the specification claims are each a separate assertion below,
// and each has a control that fails if the mechanism never ran:
//   * the run still converges - asserted by the returned verdict, not by the
//     absence of a crash (the process surviving to print the result is the fifth
//     assertion's subject, and what shows the guard is what ends it is taking the
//     handler back out: the same run on the same snapshot then dies in std::terminate);
//   * only the throwing write's bytes are lost - the sink's own record shows the
//     order, so a reordered or partial delivery would not read as "onetwothree";
//   * the event stream and the run statistics are unchanged - compared against a
//     second run of the same snapshot with the same sink that does not throw,
//     byte for byte through both ledger dumps;
//   * the host's standard streams stay empty - asserted next to a control case
//     that proves this fixture catches bytes written from inside the callback.

struct MultiwriteRun {
    std::string kept;
    int entered = 0;
    int thrown = 0;
    bool ok = false;
    sheller::engine::SyscallRunStats stats{};
};

MultiwriteRun run_multiwrite(const fs::path& snapshot, const fs::path& tlv_path,
                             const fs::path& json_path, const int throw_on,
                             const bool print_from_sink = false)
{
    MultiwriteRun run;
    sheller::behavior::EventLedger ledger;
    sheller::engine::SyscallRunOptions options;
    options.write_sink = [&](const std::uint8_t* data, const std::size_t size) {
        ++run.entered;
        if (run.entered == throw_on) {
            ++run.thrown;
            throw std::runtime_error("the host's write sink is broken");
        }
        if (print_from_sink) {
            // The control: host bytes written from inside the callback, in the
            // middle of a run, with the capture window already open.
            std::fwrite(data, 1, size, stdout);
            std::fflush(stdout);
        }
        run.kept.append(reinterpret_cast<const char*>(data), size);
    };
    options.event_sink =
        [&](const sheller::EventTypeId type, const sheller::EventPreamble& preamble,
            const std::span<const std::uint8_t> fields) { ledger.record(type, preamble, fields); };

    const auto stats = sheller::engine::run_snapshot_syscalls(snapshot, options);
    run.ok = stats.has_value();
    run.stats = run.ok ? *stats : stats.error().stats;
    EXPECT_TRUE(ledger.write_tlv(tlv_path).has_value());
    EXPECT_TRUE(ledger.write_json(json_path).has_value());
    return run;
}

TEST(SyscallRunGuestSink, ThrowingSinkLosesThatWriteAndLeavesTheRunAlone)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_MULTIWRITE_PATH, "multiwrite.snap");
    const auto dir = fs::temp_directory_path() / "sheller_syscall_test";
    fs::create_directories(dir);

    const auto clean = run_multiwrite(snapshot, dir / "mw_clean.tlv", dir / "mw_clean.json", 0);
    const auto throwing = run_multiwrite(snapshot, dir / "mw_throw.tlv", dir / "mw_throw.json", 2);

    ASSERT_TRUE(clean.ok) << "the reference run has to work before it can be a reference";
    // (1) The run that had a callback throw still ran to its normal verdict.
    ASSERT_TRUE(throwing.ok) << "a throwing host sink did not stop the run";
    EXPECT_TRUE(throwing.stats.terminated);
    EXPECT_EQ(throwing.stats.exit_code, 0x1234U);
    EXPECT_EQ(throwing.stats.syscalls, 4U);
    EXPECT_EQ(throwing.stats.rejects, 0U);

    // (2) The callback was reached for every write, threw once for real, and the
    // bytes it never kept are exactly the ones of that one call.
    EXPECT_EQ(clean.kept, "onetwothree");
    EXPECT_EQ(throwing.entered, 3);
    EXPECT_EQ(throwing.thrown, 1);
    EXPECT_EQ(throwing.kept, "onethree");

    // (3) Nothing else moved: same counters, and the event stream byte for byte.
    EXPECT_EQ(throwing.stats.blocks, clean.stats.blocks);
    EXPECT_EQ(throwing.stats.exceptions, clean.stats.exceptions);
    EXPECT_EQ(read_file(dir / "mw_throw.tlv"), read_file(dir / "mw_clean.tlv"));
    EXPECT_EQ(read_file(dir / "mw_throw.json"), read_file(dir / "mw_clean.json"));
}

TEST(SyscallRunGuestSink, HostStreamsStayEmptyAcrossAThrowingSink)
{
    const auto snapshot = capture_to(SHELLER_SAMPLE_MULTIWRITE_PATH, "multiwrite_quiet.snap");
    sheller_test::StandardStreamCapture capture{"guest_sink_streams"};

    const auto run = run_multiwrite(snapshot, fs::temp_directory_path() / "q.tlv",
                                    fs::temp_directory_path() / "q.json", 2);

    ASSERT_TRUE(run.ok);
    ASSERT_EQ(run.thrown, 1) << "the run has to contain the throw for the silence to mean anything";
    // The library writes no host standard stream at any level, and a dropped write
    // is not an excuse to print about it: no fallback echo, no diagnostic.
    EXPECT_EQ(capture.stdout_text().size(), 0u);
    EXPECT_EQ(capture.stderr_text().size(), 0u);
}

TEST(SyscallRunGuestSink, TheStreamCaptureDoesSeeBytesFromInsideTheCallback)
{
    // The ruler for the case above. Without it, "zero bytes" would be equally
    // satisfied by a fixture that never redirected anything, and the assertion
    // would be about gtest's plumbing instead of about the library.
    const auto snapshot = capture_to(SHELLER_SAMPLE_MULTIWRITE_PATH, "multiwrite_probe.snap");
    sheller_test::StandardStreamCapture capture{"guest_sink_control"};

    const auto run = run_multiwrite(snapshot, fs::temp_directory_path() / "p.tlv",
                                    fs::temp_directory_path() / "p.json", 0, true);

    ASSERT_TRUE(run.ok);
    EXPECT_EQ(run.kept, "onetwothree");
    const auto out = capture.stdout_text();
    EXPECT_EQ(out, "onetwothree") << "bytes the host writes from inside the callback have to be "
                                     "caught by this fixture, or the empty-stream assertion above "
                                     "is not testing what it says";
    EXPECT_EQ(capture.stderr_text().size(), 0u);
}

#endif

} // namespace
