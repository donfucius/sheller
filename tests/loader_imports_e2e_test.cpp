// Loader import e2e: a bare blob with a hand-built import table
// (kernel32!VirtualAlloc + kernel32!ExitProcess) rides the loader route -
// the IAT resolves against the mapped system modules, both calls land in
// the interception layer, and the run terminates with the marker exit code.

#include "wrapper.h"

#include <sheller/peloader.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;
namespace {

constexpr std::uint32_t kBlobSectionRva = 0x1000;

std::vector<std::uint8_t> build_import_blob()
{
    std::vector<std::uint8_t> blob(0x200, 0);
    auto put = [&blob](std::size_t offset, const std::vector<std::uint8_t>& bytes) {
        std::copy(bytes.begin(), bytes.end(), blob.begin() + static_cast<std::size_t>(offset));
    };
    auto put32 = [&blob](std::size_t offset, std::uint32_t value) {
        std::memcpy(&blob[offset], &value, sizeof value);
    };
    auto put64 = [&blob](std::size_t offset, std::uint64_t value) {
        std::memcpy(&blob[offset], &value, sizeof value);
    };

    // entry: VirtualAlloc(NULL, 0x1000, COMMIT|RESERVE, RW) via IAT, prove
    // the page is writable, then ExitProcess(1122h) via IAT.
    // call disps: IAT VA (blob 0xC0/C8 -> va 4010C0/C8) minus the next
    // instruction VA (40101D / 40103C) = A3h / 8Ch.
    put(0x00, {0x48, 0x83, 0xEC, 0x28});             // sub rsp, 28h
    put(0x04, {0x33, 0xC9});                         // xor ecx, ecx
    put(0x06, {0xBA, 0x00, 0x10, 0x00, 0x00});       // mov edx, 1000h
    put(0x0B, {0x41, 0xB8, 0x00, 0x30, 0x00, 0x00}); // mov r8d, 3000h
    put(0x11, {0x41, 0xB9, 0x04, 0x00, 0x00, 0x00}); // mov r9d, 4
    put(0x17, {0xFF, 0x15, 0xA3, 0x00, 0x00, 0x00}); // call q [rip+A3h] -> IAT[0]
    put(0x1D, {0x48, 0x85, 0xC0});                   // test rax, rax
    put(0x20, {0x74, 0x0E});                         // jz dead (0x30)
    put(0x22, {0xC6, 0x00, 0x42});                   // mov byte [rax], 42h
    put(0x25, {0x8A, 0x00});                         // mov al, [rax]
    put(0x27, {0x3C, 0x42});                         // cmp al, 42h
    put(0x29, {0xB9, 0x22, 0x11, 0x00, 0x00});       // mov ecx, 1122h
    put(0x2E, {0xEB, 0x06});                         // jmp term (0x36)
    put(0x30, {0xB9, 0xAD, 0xDE, 0x00, 0x00});       // dead: mov ecx, 0DEADh
    put(0x35, {0x90});                               // nop
    put(0x36, {0xFF, 0x15, 0x8C, 0x00, 0x00, 0x00}); // term: call q [rip+8Ch] -> IAT[1]
    put(0x3C, {0xEB, 0xFE});                         // jmp $

    // import descriptors at blob+0x40 (rva 0x1040): one DLL + terminator
    put32(0x40, 0x1070); // OriginalFirstThunk rva
    put32(0x44, 0);      // TimeDateStamp
    put32(0x48, 0);      // ForwarderChain
    put32(0x4C, 0x10B0); // Name rva ("KERNEL32.dll")
    put32(0x50, 0x10C0); // FirstThunk rva (IAT)
    // terminator descriptor at 0x54..0x67 stays zero

    // OriginalFirstThunk array at blob+0x70 (rva 0x1070): hint/name rvas.
    // Per PECOFF the RVA points at the 2-byte hint; the name follows.
    // Name bytes live at 0x92/0xA2, so hint entries are 0x90/0xA0
    // (hint word = the zero bytes at 0x90/0xA0).
    put64(0x70, 0x1090); // "VirtualAlloc" hint/name
    put64(0x78, 0x10A0); // "ExitProcess" hint/name
    put64(0x80, 0);      // terminator

    // hint/name entries: 2-byte hint + NUL-terminated name
    put(0x92, {'V', 'i', 'r', 't', 'u', 'a', 'l', 'A', 'l', 'l', 'o', 'c', 0});
    put(0xA2, {'E', 'x', 'i', 't', 'P', 'r', 'o', 'c', 'e', 's', 's', 0});

    // DLL name at blob+0xB0 (rva 0x10B0)
    put(0xB0, {'K', 'E', 'R', 'N', 'E', 'L', '3', '2', '.', 'd', 'l', 'l', 0});

    // IAT at blob+0xC0 (rva 0x10C0): pre-resolution values = hint/name rvas
    put64(0xC0, 0x1090);
    put64(0xC8, 0x10A0);
    put64(0xD0, 0);
    return blob;
}

} // namespace

TEST(LoaderImportsE2E, ImportBlobEndToEnd)
{
    const auto blob = build_import_blob();
    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    ASSERT_TRUE(wrapped.has_value());
    auto pe = *wrapped;
    // the wrapper has no import directory: point DataDirectory[1] at the
    // in-blob import descriptors (opt 0x58 + 112 + 8 = dir[1] VA field)
    const std::uint32_t dir_va = 0x1040;
    const std::uint32_t dir_sz = 0x28;
    std::memcpy(&pe[0x58 + 112 + 8], &dir_va, 4);
    std::memcpy(&pe[0x58 + 112 + 12], &dir_sz, 4);

    const auto pe_path = fs::temp_directory_path() / "sheller_loader_imports.exe";
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(pe.data()),
                  static_cast<std::streamsize>(pe.size()));
    }

    sheller::engine::SyscallRunOptions options;
    options.timeout_ms = 60000;
    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x1122U); // the allocated page was writable
}

TEST(LoaderImportsE2E, DeterministicAcrossRuns)
{
    const auto blob = build_import_blob();
    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    ASSERT_TRUE(wrapped.has_value());
    auto pe = *wrapped;
    const std::uint32_t dir_va = 0x1040;
    const std::uint32_t dir_sz = 0x28;
    std::memcpy(&pe[0x58 + 112 + 8], &dir_va, 4);
    std::memcpy(&pe[0x58 + 112 + 12], &dir_sz, 4);

    const auto pe_path = fs::temp_directory_path() / "sheller_loader_imports_det.exe";
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(pe.data()),
                  static_cast<std::streamsize>(pe.size()));
    }

    const auto run = [&] {
        sheller::engine::SyscallRunOptions options;
        options.timeout_ms = 60000;
        const auto stats = sheller::engine::run_pe_file(pe_path, options);
        return stats.has_value() ? stats->exit_code : 0xDEADU;
    };
    EXPECT_EQ(run(), run());
    EXPECT_EQ(run(), 0x1122U);
}
