// x86 multi-thread smoke: the 32-bit thread blob creates a
// worker via int 2e (synthetic 1003h), the worker writes 5678h into the
// shared slot and self-terminates (1004h), the main thread waits (1005h)
// and exits with the handoff value as the process code.

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

} // namespace

TEST(ThreadX86Smoke, CreateWaitHandoffAndExit)
{
    const auto blob = read_blob(SHELLER_THREAD_X86_BIN);
    ASSERT_FALSE(blob.empty()) << "missing " << SHELLER_THREAD_X86_BIN;

    const auto dir = fs::temp_directory_path() / "sheller_thread_x86_smoke";
    fs::create_directories(dir);
    const auto pe_path = dir / "thread_x86_pe.exe";

    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX86, blob);
    ASSERT_TRUE(wrapped.has_value());
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(wrapped->data()),
                  static_cast<std::streamsize>(wrapped->size()));
    }

    sheller::engine::SyscallRunOptions options;
    options.max_instructions = 0;
    options.max_blocks = 200000;
    options.timeout_ms = 30000;
    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    if (!stats.has_value()) {
        std::printf("thread x86 smoke error=%d ucode=%u blocks=%llu\n",
                    static_cast<int>(stats.error().error), stats.error().unicorn_code,
                    static_cast<unsigned long long>(stats.error().stats.blocks));
    }
    ASSERT_TRUE(stats.has_value());
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x5678U);

    const auto again = sheller::engine::run_pe_file(pe_path, options);
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(again->exit_code, 0x5678U);
}
