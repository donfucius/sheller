// x86 SEH smoke e2e: the NASM-assembled 32-bit blob installs a
// raw FS:[0] registration record, faults on a null write and the handler
// patches Eip past the fault and returns ExceptionContinueExecution, so the
// guest resumes into the success path: the write builtin emits "caught" and
// the terminate builtin exits 0x5678. Loaded through run_pe_file to exercise
// the whole x86 dispatch chain (engine synthesis, SysWOW64
// KiUserExceptionDispatcher, RtlDispatchException's FS:[0] walk, handler
// dispatch, context restore).

#include "wrapper.h"

#include <sheller/peloader.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "event_ledger.h"

namespace fs = std::filesystem;

namespace {

constexpr std::uint32_t kExpectedExitCode = 0x5678;

std::vector<std::uint8_t> read_blob(const char* path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

TEST(SehX86Smoke, HandlerDispatchesAndContinuesExecution)
{
    const auto blob = read_blob(SHELLER_SEH_X86_BIN);
    ASSERT_FALSE(blob.empty()) << "missing " << SHELLER_SEH_X86_BIN;

    const auto dir = fs::temp_directory_path() / "sheller_seh_x86_smoke";
    fs::create_directories(dir);
    const auto pe_path = dir / "seh_x86_smoke.exe";

    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX86, blob);
    ASSERT_TRUE(wrapped.has_value());
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(wrapped->data()),
                  static_cast<std::streamsize>(wrapped->size()));
    }

    std::vector<std::uint8_t> written;
    sheller::behavior::EventLedger ledger;
    sheller::engine::SyscallRunOptions options;
    options.max_blocks = 1000000;
    options.max_instructions = 0; // the dispatch's ntdll legs are instruction-heavy
    options.timeout_ms = 30000;
    options.write_sink = [&written](const std::uint8_t* data, std::size_t size) {
        written.insert(written.end(), data, data + size);
    };
    options.event_sink = [&ledger](const sheller::EventTypeId type,
                                   const sheller::EventPreamble& preamble,
                                   const std::span<const std::uint8_t> fields) {
        ledger.record(type, preamble, fields);
    };

    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    if (!stats.has_value()) {
        std::printf("seh x86 smoke error=%d ucode=%u blocks=%llu syscalls=%llu\n",
                    static_cast<int>(stats.error().error), stats.error().unicorn_code,
                    static_cast<unsigned long long>(stats.error().stats.blocks),
                    static_cast<unsigned long long>(stats.error().stats.syscalls));
    }
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, kExpectedExitCode);
    EXPECT_EQ(stats->exceptions, 1U);
    EXPECT_EQ(std::string(written.begin(), written.end()), "caught");

    // determinism: a second run agrees
    const auto again = sheller::engine::run_pe_file(pe_path, options);
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(again->exit_code, kExpectedExitCode);
}
