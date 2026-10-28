// Synthetic system modules: the generated modules must be
// deterministic (same manifest in, byte-identical out), their Nt* stubs must
// resolve through the engine's own syscall-number parser, and the loader
// route must run the by-hash corpus against them (synthetic mode on).

#include <unicorn/unicorn.h>

#include "loader_route.h"
#include "syscall_number_map.h"
#include <sheller/peloader.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <utility>
#include <vector>

namespace fs = std::filesystem;

namespace {

constexpr const char* kGenScript = SYNTH_GEN_SCRIPT;
constexpr const char* kManifestDir = SYNTH_MANIFEST_DIR;
constexpr const char* kModuleDir = SYNTH_MODULE_DIR;
constexpr const char* kPython = SYNTH_PYTHON;

std::vector<std::uint8_t> read_file(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

int run_generator(const fs::path& out_dir)
{
    const std::string cmd = std::string(kPython) + " \"" + kGenScript + "\" \"" + kManifestDir +
                            "\" \"" + out_dir.string() + "\"";
    return std::system(cmd.c_str());
}

// Scans the manifest text for an export's syscall number (ad-hoc: the
// manifest is a frozen committed artifact with a known shape).
std::optional<std::uint32_t> manifest_syscall_number(const std::string& manifest_text,
                                                     const std::string& export_name)
{
    const auto marker = "\"syscall_number\": ";
    auto pos = manifest_text.find("\"name\": \"" + export_name + "\"");
    if (pos == std::string::npos) {
        return std::nullopt;
    }
    pos = manifest_text.find(marker, pos);
    if (pos == std::string::npos || pos - manifest_text.find(export_name) > 200) {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(
        std::strtoul(manifest_text.c_str() + pos + strlen(marker), nullptr, 10));
}

} // namespace

TEST(SynthModules, GenerationIsDeterministic)
{
    const auto dir = fs::temp_directory_path() / "sheller_synth_det";
    fs::remove_all(dir / "a");
    fs::remove_all(dir / "b");
    ASSERT_EQ(run_generator(dir / "a"), 0);
    ASSERT_EQ(run_generator(dir / "b"), 0);
    for (const auto* module : {"ntdll.x64.dll", "ntdll.x86.dll", "kernel32.x64.dll",
                               "ucrtbase.x86.dll", "user32.x64.dll"}) {
        const auto a = read_file(dir / "a" / module);
        const auto b = read_file(dir / "b" / module);
        ASSERT_FALSE(a.empty()) << module;
        EXPECT_EQ(a, b) << module;
    }
}

TEST(SynthModules, NtStubNumbersResolveThroughTheEngine)
{
    std::string manifest_text;
    {
        std::ifstream in(std::string(kManifestDir) + "/ntdll.x64.json");
        ASSERT_TRUE(in);
        manifest_text.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
    }
    const auto image = read_file(fs::path(kModuleDir) / "ntdll.x64.dll");
    ASSERT_FALSE(image.empty());

    uc_engine* uc = nullptr;
    ASSERT_EQ(uc_open(UC_ARCH_X86, UC_MODE_64, &uc), UC_ERR_OK);
    const std::uint64_t base = 0x7FF800000000ULL;
    ASSERT_EQ(uc_mem_map(uc, base, 0x42000, UC_PROT_ALL), UC_ERR_OK);
    ASSERT_EQ(uc_mem_write(uc, base, image.data(), image.size()), UC_ERR_OK);

    const auto all_exports = sheller::syscalls::enumerate_exports(uc, base);
    std::printf("enumerate_exports count=%zu first=", all_exports.size());
    if (!all_exports.empty()) {
        std::printf("%s@%llx", all_exports.front().name.data(),
                    static_cast<unsigned long long>(all_exports.front().address));
    }
    std::printf("\n");
    const auto entries = sheller::syscalls::enumerate_ntdll_syscalls(uc, base);
    EXPECT_GT(entries.size(), 400U); // the manifest carries 488 numbered Nt*

    const auto expected = manifest_syscall_number(manifest_text, "NtCreateFile");
    ASSERT_TRUE(expected.has_value());
    bool found = false;
    for (const auto& entry : entries) {
        if (std::string_view(entry.name.data()) == "NtCreateFile") {
            found = true;
            EXPECT_EQ(entry.number, *expected);
        }
    }
    EXPECT_TRUE(found) << "NtCreateFile must resolve through the synthetic stub";
    uc_close(uc);
}

// A FIFTH extra must coexist with the reserved slots.
// The extras ladder (x64 ascending from the third core base, x86 descending)
// used to run straight through the tier-2 reserved bases - the ladder's
// first member was advapi32's slot, its fifth user32's - so an extended
// directory double-mapped and died as a unicorn setup failure. The reserved
// pair now sits beyond the ladder's direction of travel; this test regenerates
// the frozen directory plus a synthetic winhttp (the reviewer's fifth extra)
// and requires a live construction with distinct, non-overlapping spans.
TEST(SynthModules, FifthExtraCoexistsWithTheReservedSlots)
{
    namespace fs = std::filesystem;
    const auto dir = fs::temp_directory_path() / "sheller_synth_fifth_extra";
    fs::remove_all(dir);
    const auto manifest_dir = dir / "manifest";
    const auto module_dir = dir / "modules";
    fs::create_directories(manifest_dir);
    for (const auto& entry : fs::directory_iterator(kManifestDir)) {
        fs::copy_file(entry.path(), manifest_dir / entry.path().filename());
    }
    {
        std::ofstream out(manifest_dir / "winhttp.x64.json", std::ios::binary | std::ios::trunc);
        out << R"({"name": "winhttp.dll", "arch": "x64", "exports": [)"
            << R"({"name": "WinHttpOpen", "ordinal": 1},)"
            << R"({"name": "WinHttpConnect", "ordinal": 2}]})";
    }
    {
        // run_generator reads the frozen kManifestDir; this test needs its
        // own manifest set (frozen + winhttp)
        const std::string cmd = std::string(kPython) + " \"" + kGenScript + "\" \"" +
                                manifest_dir.string() + "\" \"" + module_dir.string() + "\"";
        ASSERT_EQ(std::system(cmd.c_str()), 0) << cmd;
    }

    // live construction (the fixed-slot planner) over the nine-module world
    auto guest = sheller::engine::prepare_pe_file(SHELLER_SAMPLE_PACKED_PATH, false, module_dir);
    ASSERT_TRUE(guest.has_value()) << "extended synthetic directory failed to construct";

    std::vector<std::uint64_t> bases;
    for (std::size_t i = 0; i < guest->map.module_count(); ++i) {
        bases.push_back(guest->map.module(i).base);
    }
    ASSERT_GE(bases.size(), 9U);
    // distinct bases and non-overlapping image spans
    std::sort(bases.begin(), bases.end());
    ASSERT_TRUE(std::adjacent_find(bases.begin(), bases.end()) == bases.end())
        << "two resident modules plan at one base";
    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
    for (std::size_t i = 0; i < guest->map.module_count(); ++i) {
        const auto& module = guest->map.module(i);
        spans.push_back({module.base, module.base + module.size});
    }
    std::sort(spans.begin(), spans.end());
    for (std::size_t i = 1; i < spans.size(); ++i) {
        EXPECT_LE(spans[i - 1].second, spans[i].first)
            << "module image spans overlap at " << std::hex << spans[i - 1].second;
    }
    // the reserved pair and the fifth ladder member each landed where planned
    const auto find_base = [&](const std::uint64_t base) {
        return std::find(bases.begin(), bases.end(), base) != bases.end();
    };
    EXPECT_TRUE(find_base(0x7FF700000000ULL)); // reserved user32 slot (far side)
    EXPECT_TRUE(find_base(0x7FFF00000000ULL)); // the ladder's fifth member: winhttp
}

TEST(SynthModules, PackedSampleRunsCleanWithSyntheticModules)
{
    // the packed corpus (heap-heavy, loads its import DLLs post-OEP) used to
    // die in real-ntdll code paths; with synthetic modules the whole load
    // chain is engine-answered, so the run must not end in an unhandled
    // exception
    const auto packed = read_file(SHELLER_SAMPLE_PACKED_PATH);
    ASSERT_FALSE(packed.empty());

    const auto dir = fs::temp_directory_path() / "sheller_synth_packed";
    fs::create_directories(dir);
    const auto pe_path = dir / "packed_synth.exe";
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(packed.data()),
                  static_cast<std::streamsize>(packed.size()));
    }

    sheller::engine::SyscallRunOptions options;
    options.max_blocks = 2000000;
    options.timeout_ms = 120000;
    options.synthetic_system_modules = true;
    options.synthetic_module_dir = kModuleDir;

    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    if (!stats.has_value()) {
        std::printf(
            "synth packed error=%d (%s) blocks=%llu exceptions=%llu\n",
            static_cast<int>(stats.error().error),
            std::string(sheller::engine::syscall_run_error_message(stats.error().error)).c_str(),
            static_cast<unsigned long long>(stats.error().stats.blocks),
            static_cast<unsigned long long>(stats.error().stats.exceptions));
    }
    // the acceptance: the run must actually enter execution and reach a
    // legitimate endpoint - any construction/setup failure (unicorn setup,
    // I/O, bad image) is a hard failure, not a tolerated shape. The packed
    // payload's documented ends: normal termination, budget exhaustion, or
    // an absorbed-crash normal exit.
    ASSERT_TRUE(stats.has_value() ||
                stats.error().error != sheller::engine::SyscallRunError::kUnhandledException)
        << "synth run must not die on an unhandled exception";
    if (!stats.has_value()) {
        EXPECT_NE(stats.error().error, sheller::engine::SyscallRunError::kUnicornFailure)
            << "construction/setup failures are not acceptable run endpoints";
        EXPECT_GT(stats.error().stats.blocks, 0ULL) << "the run must execute at least one block";
    } else {
        EXPECT_GT(stats.value().blocks, 0ULL);
    }
}
