// Synthetic system modules: the generated modules must be
// deterministic (same manifest in, byte-identical out), their Nt* stubs must
// resolve through the engine's own syscall-number parser, and the loader
// route must run the by-hash corpus against them (synthetic mode on).

#include <unicorn/unicorn.h>

#include "syscall_number_map.h"
#include <sheller/peloader.h>
#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
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
    for (const auto* module :
         {"ntdll.x64.dll", "ntdll.x86.dll", "kernel32.x64.dll", "ucrtbase.x86.dll"}) {
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
    // the acceptance: no unhandled-crash fallback while the payload runs
    ASSERT_TRUE(stats.has_value() ||
                stats.error().error != sheller::engine::SyscallRunError::kUnhandledException);
}
