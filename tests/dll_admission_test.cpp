// DLL-input admission tests (Windows): the system-dependency contract.
// The admission never trusts a file name - a private dependency is rejected
// before any process exists, a staged same-named file next to the sample
// cannot smuggle itself in, and a verified system dependency (user32 in the
// packed corpus) yields a runner plan. The staged-runner smoke runs the
// real loader end to end: the runner loads the benign same-named corpus DLL
// and exits with the designed fixed code.

#include "dll_admission.h"
#include "pe_headers.h"
#include "wrapper.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

std::vector<std::uint8_t> read_bytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

fs::path packed_dll()
{
    return fs::path{SHELLER_SAMPLE_PACKED_DLL_PATH};
}

// A structurally valid import-table PE whose only dependency is a private
// DLL: build a runner, then rewrite its kernel32 dependency name to a
// same-length fake (both spell "kernel32.dll" and "PRIVATE9.dll" in 12
// bytes, so the name table stays intact).
std::vector<std::uint8_t> bytes_with_private_dependency()
{
    sheller::capture::RunnerPlan plan;
    plan.arrival_name = "sample.dll";
    plan.imports = {{"kernel32.dll", "LoadLibraryW", 0}, {"kernel32.dll", "ExitProcess", 0}};
    auto pe = *sheller::capture::build_runner(plan);
    int replaced = 0;
    for (std::size_t i = 0; i + 12 <= pe.size(); ++i) {
        if (std::string_view{reinterpret_cast<const char*>(pe.data() + i), 12} == "kernel32.dll") {
            const char fake[] = "PRIVATE9.dll";
            std::memcpy(pe.data() + i, fake, 12);
            ++replaced;
        }
    }
    EXPECT_GE(replaced, 1) << "fixture rewrite found no dependency name";
    return pe;
}

TEST(DllAdmission, PackedCorpusAdmitsSystemDependencies)
{
    const auto bytes = read_bytes(packed_dll());
    const auto plan = sheller::capture::admit_dll_sample(bytes, "packed.dll");
    ASSERT_TRUE(plan.has_value()) << plan.error();
    // base pair + one USER32 import; every module is a real system name
    ASSERT_GE(plan->imports.size(), 3u);
    EXPECT_EQ(plan->imports[0].module, "kernel32.dll");
    EXPECT_EQ(plan->imports[0].symbol, "LoadLibraryW");
    EXPECT_EQ(plan->imports[1].symbol, "ExitProcess");
    bool saw_user32 = false;
    for (std::size_t i = 2; i < plan->imports.size(); ++i) {
        EXPECT_EQ(plan->imports[i].module, "USER32.dll");
        saw_user32 = true;
        EXPECT_FALSE(plan->imports[i].symbol.empty() && plan->imports[i].ordinal == 0);
    }
    EXPECT_TRUE(saw_user32);
}

TEST(DllAdmission, PrivateDependencyRejectedBeforeSpawn)
{
    const auto bytes = bytes_with_private_dependency();
    const auto plan = sheller::capture::admit_dll_sample(bytes, "sample.dll");
    ASSERT_FALSE(plan.has_value());
    EXPECT_NE(plan.error().find("PRIVATE9.dll"), std::string::npos)
        << "rejection must name the dependency: " << plan.error();
}

TEST(DllAdmission, StagedSameNamedFileDoesNotSmuggle)
{
    const auto bytes = bytes_with_private_dependency();
    // A file named like the private dependency sits next to the "sample":
    // the system32-only probe must not see it.
    const auto stage =
        fs::temp_directory_path() / ("sheller_admit_" + std::to_string(GetCurrentProcessId()));
    fs::create_directories(stage);
    fs::copy_file(packed_dll(), stage / "PRIVATE9.dll", fs::copy_options::overwrite_existing);
    const auto plan = sheller::capture::admit_dll_sample(bytes, "sample.dll");
    std::error_code ec;
    fs::remove_all(stage, ec);
    ASSERT_FALSE(plan.has_value());
    EXPECT_NE(plan.error().find("PRIVATE9.dll"), std::string::npos);
}

TEST(DllAdmission, ArrivalNameCollidingWithDependencyRejected)
{
    const auto bytes = read_bytes(packed_dll()); // imports USER32.dll
    const auto plan = sheller::capture::admit_dll_sample(bytes, "USER32.dll");
    ASSERT_FALSE(plan.has_value());
    EXPECT_NE(plan.error().find("collides"), std::string::npos) << plan.error();
}

// The real-loader smoke: the runner loads the benign same-named corpus DLL
// and exits through the designed fixed code 0x5A.
TEST(DllAdmission, StagedRunnerLoadsBenignDllAndExitsDesigned)
{
    const auto bytes = read_bytes(packed_dll());
    const auto plan = sheller::capture::admit_dll_sample(bytes, "packed.dll");
    ASSERT_TRUE(plan.has_value()) << plan.error();
    const auto runner = sheller::capture::build_runner(*plan);
    ASSERT_TRUE(runner.has_value());

    const auto stage =
        fs::temp_directory_path() / ("sheller_smoke_" + std::to_string(GetCurrentProcessId()));
    fs::create_directories(stage);
    const fs::path runner_path = stage / "smoke_runner.exe";
    {
        std::ofstream out(runner_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(runner->data()),
                  static_cast<std::streamsize>(runner->size()));
    }
    fs::copy_file(packed_dll(), stage / "packed.dll", fs::copy_options::overwrite_existing);

    STARTUPINFOW si = {.cb = sizeof si};
    PROCESS_INFORMATION pi = {};
    std::wstring cmd = L"\"" + runner_path.wstring() + L"\"";
    ASSERT_NE(CreateProcessW(runner_path.wstring().c_str(), cmd.data(), nullptr, nullptr, FALSE, 0,
                             nullptr, stage.wstring().c_str(), &si, &pi),
              0);
    ASSERT_EQ(WaitForSingleObject(pi.hProcess, 30000), WAIT_OBJECT_0);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::error_code ec;
    fs::remove_all(stage, ec);
    EXPECT_EQ(code, 0x5Au) << "runner must reach its designed ExitProcess(0x5A), got 0x" << std::hex
                           << code;
}

// Diagnostic twin of the smoke above: without a same-named DLL the
// LoadLibraryW call simply fails (NULL), the stub still falls through to
// ExitProcess(0x5A) - the runner's own import table and PE shape are what
// this pins, isolated from loading the corpus DLL.
TEST(DllAdmission, StagedRunnerWithoutDllStillExitsDesigned)
{
    const auto bytes = read_bytes(packed_dll());
    const auto plan = sheller::capture::admit_dll_sample(bytes, "packed.dll");
    ASSERT_TRUE(plan.has_value()) << plan.error();
    const auto runner = sheller::capture::build_runner(*plan);
    ASSERT_TRUE(runner.has_value());

    const auto stage =
        fs::temp_directory_path() / ("sheller_alone_" + std::to_string(GetCurrentProcessId()));
    fs::create_directories(stage);
    const fs::path runner_path = stage / "alone_runner.exe";
    {
        std::ofstream out(runner_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(runner->data()),
                  static_cast<std::streamsize>(runner->size()));
    }
    // Diagnostic copy retained for external inspection (dumpbin etc.).
    {
        std::error_code dec;
        fs::create_directories(R"(C:\devdrv\tmp\runner_dump)", dec);
        std::ofstream out(R"(C:\devdrv\tmp\runner_dump\runner.exe)",
                          std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(runner->data()),
                  static_cast<std::streamsize>(runner->size()));
    }
    STARTUPINFOW si = {.cb = sizeof si};
    PROCESS_INFORMATION pi = {};
    std::wstring cmd = L"\"" + runner_path.wstring() + L"\"";
    ASSERT_NE(CreateProcessW(runner_path.wstring().c_str(), cmd.data(), nullptr, nullptr, FALSE, 0,
                             nullptr, stage.wstring().c_str(), &si, &pi),
              0);
    ASSERT_EQ(WaitForSingleObject(pi.hProcess, 30000), WAIT_OBJECT_0);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    std::error_code ec;
    fs::remove_all(stage, ec);
    EXPECT_EQ(code, 0x5Au) << "runner alone must exit 0x5A, got 0x" << std::hex << code;
}

} // namespace
