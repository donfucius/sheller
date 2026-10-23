// multi-thread scheduler e2e: the NASM blob creates a
// thread via NtCreateThreadEx, the worker writes the handoff value into a
// shared slot and terminates, the main thread waits (blocking yield) and
// exits with the slot value as the process code.

#include "wrapper.h"

#include <sheller/peloader.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;

namespace {

std::vector<std::uint8_t> read_blob(const char* path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

sheller::engine::SyscallRunStats run_once(const fs::path& pe_path)
{
    sheller::engine::SyscallRunOptions options;
    options.max_instructions = 0; // unlimited: the scheduler needs many legs
    options.max_blocks = 200000;
    options.timeout_ms = 30000;
    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    return stats.has_value() ? *stats : sheller::engine::SyscallRunStats{};
}

} // namespace

TEST(ThreadE2E, CreateWaitHandoffAndExit)
{
    const auto blob = read_blob(SHELLER_THREAD_BIN);
    ASSERT_FALSE(blob.empty()) << "missing " << SHELLER_THREAD_BIN;

    const auto dir = fs::temp_directory_path() / "sheller_thread_e2e";
    fs::create_directories(dir);
    const auto pe_path = dir / "thread_pe.exe";

    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    ASSERT_TRUE(wrapped.has_value());
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(wrapped->data()),
                  static_cast<std::streamsize>(wrapped->size()));
    }

    sheller::engine::SyscallRunOptions options;
    options.max_instructions = 0; // unlimited: the scheduler needs many legs
    options.max_blocks = 200000;
    options.timeout_ms = 30000;
    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    if (!stats.has_value()) {
        std::printf("thread e2e error=%d ucode=%u blocks=%llu\n",
                    static_cast<int>(stats.error().error), stats.error().unicorn_code,
                    static_cast<unsigned long long>(stats.error().stats.blocks));
    }
    ASSERT_TRUE(stats.has_value());
    EXPECT_TRUE(stats->terminated);
    // the worker's write landed in the shared slot and became the exit code
    EXPECT_EQ(stats->exit_code, 0x1234U);
    EXPECT_GE(stats->syscalls, 4U); // create + wait + thread-exit + process-exit
}

TEST(ThreadE2E, DeterministicAcrossRuns)
{
    const auto blob = read_blob(SHELLER_THREAD_BIN);
    ASSERT_FALSE(blob.empty());

    const auto dir = fs::temp_directory_path() / "sheller_thread_e2e_det";
    fs::create_directories(dir);
    const auto pe_path = dir / "thread_pe.exe";
    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    ASSERT_TRUE(wrapped.has_value());
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(wrapped->data()),
                  static_cast<std::streamsize>(wrapped->size()));
    }

    const auto first = run_once(pe_path);
    const auto second = run_once(pe_path);
    EXPECT_TRUE(first.terminated);
    EXPECT_EQ(first.exit_code, second.exit_code);
    EXPECT_EQ(first.exit_code, 0x1234U);
    EXPECT_EQ(first.syscalls, second.syscalls);
}
