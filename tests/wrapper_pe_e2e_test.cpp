// Wrapper e2e: a bare shellcode blob rides the standard route -
// capture wraps it into the minimal PE, the run restores the entry and the
// blob executes, the behavior layer sees its direct syscall, and the
// terminate call ends the run with the blob's exit code.

#include "capture_detail.h"
#include "wrapper.h"

#include <sheller/capture.h>
#include <sheller/syscallrun.h>

#include "../behavior/behavior_rules.h"
#include "../engine/behavior_fact.h"
#include "../engine/rebuild_probe.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <set>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace fs = std::filesystem;

namespace {

// direct syscall (unregistered 0BEEFh) then NtTerminateProcess(-1, 1234h)
const std::vector<std::uint8_t> kBlob = {0xB8, 0xEF, 0xBE, 0x00, 0x00, 0x0F, 0x05, 0x49, 0xC7,
                                         0xC2, 0xFF, 0xFF, 0xFF, 0xFF, 0xBA, 0x34, 0x12, 0x00,
                                         0x00, 0xB8, 0x02, 0x10, 0x00, 0x00, 0x0F, 0x05};

fs::path write_blob(const std::string& name, const std::vector<std::uint8_t>& bytes)
{
    const auto dir = fs::temp_directory_path() / "sheller_wrapper_e2e";
    fs::create_directories(dir);
    const auto path = dir / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()),
              static_cast<std::streamsize>(bytes.size()));
    return path;
}

} // namespace

TEST(WrapperE2E, BlobRidesTheStandardRoute)
{
    const auto blob_path = write_blob("shellcode.bin", kBlob);
    const auto snapshot_path = fs::temp_directory_path() / "sheller_wrapper_e2e" / "w.snap";

    // clean leftovers of previous failed runs so the assertion below only
    // sees this run's temp file
    for (const auto& entry : fs::directory_iterator(fs::temp_directory_path())) {
        if (entry.path().filename().string().starts_with("sheller_wrap_")) {
            fs::remove(entry.path());
        }
    }

    sheller::capture::Options capture_options;
    capture_options.sample_path = blob_path;
    capture_options.output_path = snapshot_path;
    capture_options.shellcode = true;
    const auto captured = sheller::capture::detail::run_impl(capture_options);
    ASSERT_EQ(captured.status, sheller::capture::Status::kOk) << captured.detail;
    // the temp wrapper PE is cleaned up after the capture (no leftovers)
    bool leftover = false;
    for (const auto& entry : fs::directory_iterator(fs::temp_directory_path())) {
        const auto name = entry.path().filename().string();
        if (name.starts_with("sheller_wrap_")) {
            leftover = true;
        }
    }
    EXPECT_FALSE(leftover);

    // behavior wiring from the probe, same as the CLI assembles it
    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot_path);
    ASSERT_TRUE(probe.has_value());
    sheller::behavior::BehaviorRulesParams params;
    params.sample_image_base = probe->image_base;
    params.sample_image_size = probe->image_size;
    for (const auto& image : probe->images) {
        params.modules.push_back(image.module);
        if (std::string_view(image.module.name.data()) == "ntdll.dll") {
            params.ntdll_base = image.module.base;
        }
    }
    for (const auto& entry : probe->syscall_numbers) {
        if (std::string_view(entry.name.data()) == "NtQueryInformationProcess") {
            params.query_process_number = entry.number;
        }
    }
    for (const auto& slot : probe->export_slots) {
        if (slot.module_base == params.ntdll_base &&
            std::string_view(slot.name.data()).starts_with("Nt")) {
            params.syscall_entries.push_back(slot.function_va);
        }
    }
    std::ranges::sort(params.syscall_entries);
    sheller::behavior::BehaviorRules rules(params);
    std::vector<sheller::EventTypeId> emitted;
    rules.set_event_emitter(
        [&emitted](const sheller::EventTypeId type, const sheller::EventPreamble&,
                   const std::span<const std::uint8_t>) { emitted.push_back(type); });

    sheller::engine::SyscallRunOptions run_options;
    // The fact seam has no public options slot: the channel rides beside.
    sheller::engine::FactChannel fact_channel;
    fact_channel.behavior_sink = [&rules](const sheller::engine::BehaviorFact& fact) {
        rules.on_fact(fact);
    };
    run_options.event_sink = [&rules](const sheller::EventTypeId type,
                                      const sheller::EventPreamble& preamble,
                                      const std::span<const std::uint8_t>& fields) {
        rules.on_event(type, preamble, fields);
    };

    const auto stats = sheller::engine::detail::run_snapshot_syscalls_with_facts(
        snapshot_path, run_options, fact_channel);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x1234U); // the blob's own terminate call

    // the blob's unregistered direct syscall is seen and attributed
    EXPECT_NE(std::ranges::find(emitted, sheller::EventTypeId::kDirectSyscall), emitted.end());
}

TEST(WrapperE2E, WrapperSnapshotEntryIsBlobHead)
{
    const auto blob_path = write_blob("shellcode_head.bin", kBlob);
    const auto snapshot_path = fs::temp_directory_path() / "sheller_wrapper_e2e" / "head.snap";
    sheller::capture::Options capture_options;
    capture_options.sample_path = blob_path;
    capture_options.output_path = snapshot_path;
    capture_options.shellcode = true;
    static_cast<void>(sheller::capture::detail::run_impl(capture_options));

    const auto probe = sheller::engine::detail::attribute_snapshot_modules(snapshot_path);
    ASSERT_TRUE(probe.has_value());
    EXPECT_GE(probe->image_size, kBlob.size());
    // the wrapper's entry RVA is the section head (image_base + 0x1000) and
    // the snapshot holds the blob bytes verbatim at that guest address
    const auto entry_bytes = sheller::engine::detail::read_snapshot_range(
        snapshot_path, probe->image_base + 0x1000, static_cast<std::uint32_t>(kBlob.size()));
    ASSERT_TRUE(entry_bytes.has_value());
    // the snapshot holds the capture-time entry spin (jmp $) over the first
    // two bytes; the run restores the original bytes before executing
    ASSERT_GE(entry_bytes->size(), kBlob.size());
    EXPECT_EQ((*entry_bytes)[0], 0xEB);
    EXPECT_EQ((*entry_bytes)[1], 0xFE);
    for (std::size_t i = 2; i < kBlob.size(); ++i) {
        EXPECT_EQ((*entry_bytes)[i], kBlob[i]) << "byte " << i;
    }
}

// Concurrent wrapper naming. Each thread takes the same bare blob through the
// capture route, so each one wraps it into its own temp PE and spawns it. Two
// things have to hold: every capture succeeds, and the temp names are not shared.
//
// The collision shows up as a failure rather than as a visible duplicate, because
// the guard that owns a name removes the file when its own capture ends - a second
// thread still holding that path then spawns from a file that is gone. The poller
// below is what turns "not shared" into a measured statement: wrapper files live for
// the whole spawn, so catching two distinct names in flight is the observation that
// the names are actually being drawn per call, not once per process.
TEST(WrapperConcurrency, DistinctWrapperNamesUnderContention)
{
    constexpr int kThreads = 8;
    const auto blob_path = write_blob("shellcode_conc.bin", kBlob);
    const auto dir = fs::temp_directory_path() / "sheller_wrapper_conc";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);

    std::mutex seen_mutex;
    std::set<std::string> seen;
    std::atomic<bool> stop{false};
    std::thread poller([&] {
        while (!stop.load()) {
            std::error_code poll_ec;
            for (const auto& entry : fs::directory_iterator(fs::temp_directory_path(), poll_ec)) {
                const auto name = entry.path().filename().string();
                if (name.starts_with("sheller_wrap_")) {
                    std::lock_guard<std::mutex> lock(seen_mutex);
                    seen.insert(name);
                }
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(2));
        }
    });

    std::vector<sheller::capture::Status> statuses(kThreads, sheller::capture::Status::kOk);
    std::vector<std::string> details(kThreads);
    std::vector<std::thread> workers;
    workers.reserve(kThreads);
    for (int i = 0; i < kThreads; ++i) {
        workers.emplace_back([&, i] {
            sheller::capture::Options options;
            options.sample_path = blob_path;
            options.output_path = dir / ("conc_" + std::to_string(i) + ".snap");
            options.shellcode = true;
            const auto captured = sheller::capture::detail::run_impl(options);
            statuses[i] = captured.status;
            details[i] = captured.detail;
        });
    }
    for (auto& worker : workers) {
        worker.join();
    }
    stop.store(true);
    poller.join();

    for (int i = 0; i < kThreads; ++i) {
        EXPECT_EQ(statuses[i], sheller::capture::Status::kOk)
            << "thread " << i << ": " << details[i];
    }
    std::lock_guard<std::mutex> lock(seen_mutex);
    // Every thread produced a snapshot and the guard removes each wrapper file when
    // its own capture ends, so the distinct names caught in flight are the evidence
    // about naming. An empty set would mean the poller never saw a wrapper at all,
    // which would make the check vacuous - so it is asserted, not assumed.
    EXPECT_GE(seen.size(), 2U) << "the poller caught " << seen.size()
                               << " distinct wrapper name(s) in flight";
    for (int i = 0; i < kThreads; ++i) {
        EXPECT_TRUE(fs::exists(dir / ("conc_" + std::to_string(i) + ".snap")))
            << "no snapshot from thread " << i;
    }
}
