// x86 by-hash shellcode e2e: the NASM-assembled 32-bit blob walks
// PEB32->Ldr->InMemoryOrderModuleList, verifies MZ at each DllBase and
// exits with the count via raw int 2e. Loaded through run_pe_file to
// validate the x86 loader route end to end (mode selection, 32-bit layout,
// SysWOW64 modules, x86 environment, int 2e dispatch).

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

// The guest exits with its Ldr module count (MZ-valid bases only). That
// count tracks the HOST SysWOW64 import graph, not a fixed corpus fact:
// the authored core is sample + ntdll + kernel32 + kernelbase, and newer
// host builds grow the chain (advapi32 joining via the import closure
// reads exit=5). The loader route's guarantee is the core floor, so pin
// from below and assert the two runs agree instead of freezing the graph.
constexpr std::uint32_t kCoreModuleCount = 4;

std::vector<std::uint8_t> read_blob(const char* path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

TEST(LoaderByHashX86E2E, LdrWalkMzVerifyAndCount)
{
    const auto blob = read_blob(SHELLER_BYHASH_X86_BIN);
    ASSERT_FALSE(blob.empty()) << "missing " << SHELLER_BYHASH_X86_BIN;

    const auto dir = fs::temp_directory_path() / "sheller_byhash_x86_e2e";
    fs::create_directories(dir);
    const auto pe_path = dir / "byhash_x86_pe.exe";

    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX86, blob);
    ASSERT_TRUE(wrapped.has_value());
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(wrapped->data()),
                  static_cast<std::streamsize>(wrapped->size()));
    }

    sheller::engine::SyscallRunOptions options;
    options.max_blocks = 100000;
    options.timeout_ms = 30000;

    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    if (!stats.has_value()) {
        std::printf("byhash x86 e2e error=%d ucode=%u blocks=%llu\n",
                    static_cast<int>(stats.error().error), stats.error().unicorn_code,
                    static_cast<unsigned long long>(stats.error().stats.blocks));
    }
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_GE(stats->exit_code, kCoreModuleCount);

    // determinism: a second run agrees with the first on this host's graph
    const auto again = sheller::engine::run_pe_file(pe_path, options);
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(again->exit_code, stats->exit_code);
}
