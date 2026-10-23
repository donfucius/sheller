// x86 loader import e2e: a 32-bit blob with a hand-built PE32 import
// table (kernel32!VirtualAlloc + kernel32!ExitProcess) rides the loader
// route - the IAT resolves against the SysWOW64 modules, both stdcall calls
// land in the interception layer, and the run terminates with the marker
// exit code.

#include "wrapper.h"

#include <sheller/peloader.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
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

// Wraps the NASM blob and points the wrapper's (empty) DataDirectory[1] at
// the in-blob import descriptors (blob offset 0x40 = rva 0x1040, laid out by
// the asm's padding contract). PE32 optional header: dir[1].VA at 0x58+0x68.
std::expected<std::vector<std::uint8_t>, std::string>
build_pe(const std::vector<std::uint8_t>& blob)
{
    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX86, blob);
    if (!wrapped.has_value()) {
        return std::unexpected(std::string("wrap_blob failed"));
    }
    auto pe = *wrapped;
    const std::uint32_t dir_va = 0x1040;
    const std::uint32_t dir_sz = 0x28;
    std::memcpy(&pe[0x58 + 0x68], &dir_va, 4);
    std::memcpy(&pe[0x58 + 0x68 + 4], &dir_sz, 4);
    return pe;
}

} // namespace

TEST(LoaderImportsX86E2E, ImportBlobEndToEnd)
{
    const auto blob = read_blob(SHELLER_IMPORT_X86_BIN);
    ASSERT_FALSE(blob.empty()) << "missing " << SHELLER_IMPORT_X86_BIN;
    const auto pe = build_pe(blob);
    ASSERT_TRUE(pe.has_value()) << pe.error();

    const auto pe_path = fs::temp_directory_path() / "sheller_loader_imports_x86.exe";
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(pe->data()),
                  static_cast<std::streamsize>(pe->size()));
    }

    const auto stats = sheller::engine::run_pe_file(pe_path, {});
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x1122U); // the allocated page was writable
}

TEST(LoaderImportsX86E2E, DeterministicAcrossRuns)
{
    const auto blob = read_blob(SHELLER_IMPORT_X86_BIN);
    ASSERT_FALSE(blob.empty());
    const auto pe = build_pe(blob);
    ASSERT_TRUE(pe.has_value()) << pe.error();

    const auto pe_path = fs::temp_directory_path() / "sheller_loader_imports_x86_det.exe";
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(pe->data()),
                  static_cast<std::streamsize>(pe->size()));
    }

    sheller::engine::SyscallRunOptions options;
    options.timeout_ms = 60000;
    const auto first = sheller::engine::run_pe_file(pe_path, options);
    const auto second = sheller::engine::run_pe_file(pe_path, options);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(first->exit_code, 0x1122U);
    EXPECT_EQ(first->exit_code, second->exit_code);
    EXPECT_EQ(first->terminated, second->terminated);
    EXPECT_EQ(first->syscalls, second->syscalls);
}
