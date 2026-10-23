// x86 snapshot-route e2e: capture a real WOW64 process
// (the NASM by-hash blob wrapped as PE32), then rebuild and run the
// snapshot in the engine's 32-bit mode. The blob walks the real captured
// PEB32/Ldr chain, counts MZ-valid modules and terminates via a raw
// int 2e whose number is resolved from the captured SysWOW64 ntdll.

#include "capture_detail.h"
#include "wrapper.h"

#include "imports.h"
#include "loader.h"

#include <sheller/capture.h>
#include <sheller/peloader.h>
#include <sheller/syscallrun.h>

#include <windows.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <optional>
#include <vector>

namespace fs = std::filesystem;
namespace loader = sheller::loader;

namespace {

std::vector<std::uint8_t> read_bytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// NtTerminateProcess's number comes from the captured world's own ntdll:
// resolve the export host-side and read the wow64 stub (mov eax, imm32; ...).
std::optional<std::uint32_t> wow64_terminate_number()
{
    char system_root[MAX_PATH] = {};
    if (GetSystemDirectoryA(system_root, sizeof system_root) == 0) {
        return std::nullopt;
    }
    const auto bytes = read_bytes(fs::path(system_root) / "../SysWOW64/ntdll.dll");
    if (bytes.empty()) {
        return std::nullopt;
    }
    const auto info = loader::parse_pe(bytes);
    if (!info.has_value()) {
        return std::nullopt;
    }
    auto image = loader::build_image(bytes, *info);
    if (!image.has_value()) {
        return std::nullopt;
    }
    loader::LoadedModule module;
    module.base = 0;
    module.image = std::move(*image);
    std::memcpy(module.name.data(), "ntdll.dll", 9);
    if (!loader::index_exports(module).has_value()) {
        return std::nullopt;
    }
    const auto resolved = loader::resolve_export(std::vector<loader::LoadedModule>{module},
                                                 "ntdll.dll", "NtTerminateProcess");
    if (!resolved.ok || resolved.va >= module.image.size()) {
        return std::nullopt;
    }
    const auto* stub = module.image.data() + resolved.va;
    // wow64 stub: mov eax, imm32; mov edx, transition; call edx
    if (stub[0] != 0xB8 || stub[5] != 0xBA || stub[10] != 0xFF || stub[11] != 0xD2) {
        return std::nullopt;
    }
    std::uint32_t number = 0;
    std::memcpy(&number, stub + 1, sizeof number);
    return number;
}

// The blob ships with the loader-route placeholder number (1002h); the
// snapshot route must use the real captured ntdll's number.
bool patch_terminate_number(std::vector<std::uint8_t>& blob, std::uint32_t number)
{
    const std::array<std::uint8_t, 7> pattern = {0xB8, 0x02, 0x10, 0x00, 0x00, 0xCD, 0x2E};
    for (std::size_t i = 0; i + pattern.size() <= blob.size(); ++i) {
        if (std::memcmp(blob.data() + i, pattern.data(), pattern.size()) == 0) {
            std::memcpy(blob.data() + i + 1, &number, sizeof number);
            return true;
        }
    }
    return false;
}

} // namespace

TEST(CaptureX86E2E, Wow64CaptureAndRebuildRun)
{
    const auto number = wow64_terminate_number();
    ASSERT_TRUE(number.has_value()) << "cannot resolve the wow64 NtTerminateProcess number";

    auto blob = read_bytes(SHELLER_BYHASH_X86_BIN);
    ASSERT_FALSE(blob.empty());
    ASSERT_TRUE(patch_terminate_number(blob, *number));

    const auto dir = fs::temp_directory_path() / "sheller_capture_x86_e2e";
    fs::create_directories(dir);
    const auto pe_path = dir / "byhash_x86_capture.exe";
    const auto snap_path = dir / "byhash_x86.snap";

    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX86, blob);
    ASSERT_TRUE(wrapped.has_value());
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(wrapped->data()),
                  static_cast<std::streamsize>(wrapped->size()));
    }

    sheller::capture::Options options{.sample_path = pe_path, .output_path = snap_path};
    const auto result = sheller::capture::detail::run_impl(options);
    ASSERT_EQ(result.status, sheller::capture::Status::kOk) << result.detail;

    const auto snapshot = read_bytes(snap_path);
    ASSERT_FALSE(snapshot.empty());

    sheller::engine::SyscallRunOptions run_options;
    run_options.timeout_ms = 30000;
    const auto stats = sheller::engine::run_snapshot_syscalls(snap_path, run_options);
    if (!stats.has_value()) {
        std::printf("x86 snapshot run error=%d ucode=%u blocks=%llu\n",
                    static_cast<int>(stats.error().error), stats.error().unicorn_code,
                    static_cast<unsigned long long>(stats.error().stats.blocks));
    }
    ASSERT_TRUE(stats.has_value());
    EXPECT_TRUE(stats->terminated);
    // the walk counts the captured wow64 Ldr modules (sample + ntdll32 +
    // kernel32 + kernelbase at minimum); the exact total is loader-built
    EXPECT_GE(stats->exit_code, 3U);
}

TEST(CaptureX86E2E, DeterministicAcrossRuns)
{
    const auto number = wow64_terminate_number();
    ASSERT_TRUE(number.has_value());

    auto blob = read_bytes(SHELLER_BYHASH_X86_BIN);
    ASSERT_FALSE(blob.empty());
    ASSERT_TRUE(patch_terminate_number(blob, *number));

    const auto dir = fs::temp_directory_path() / "sheller_capture_x86_e2e_det";
    fs::create_directories(dir);

    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX86, blob);
    ASSERT_TRUE(wrapped.has_value());
    const auto pe_path = dir / "byhash_x86_capture.exe";
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(wrapped->data()),
                  static_cast<std::streamsize>(wrapped->size()));
    }

    const auto run = [&]() -> sheller::engine::SyscallRunStats {
        const auto snap_path = dir / "det.snap";
        sheller::capture::Options options{.sample_path = pe_path, .output_path = snap_path};
        const auto result = sheller::capture::detail::run_impl(options);
        EXPECT_EQ(result.status, sheller::capture::Status::kOk) << result.detail;
        if (result.status != sheller::capture::Status::kOk) {
            return {};
        }
        sheller::engine::SyscallRunOptions run_options;
        run_options.timeout_ms = 30000;
        const auto stats = sheller::engine::run_snapshot_syscalls(snap_path, run_options);
        return stats.has_value() ? *stats : sheller::engine::SyscallRunStats{};
    };
    const auto first = run();
    const auto second = run();
    EXPECT_TRUE(first.terminated);
    EXPECT_EQ(first.exit_code, second.exit_code);
    EXPECT_GT(first.exit_code, 0U);
}
