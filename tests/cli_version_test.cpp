// Smoke tests: the CLI prints its version and exits 0 (no args / --version);
// unknown arguments exit non-zero.

#include <gtest/gtest.h>

#include "test_temp.hpp"
#include <cstdlib>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <system_error>

namespace {

namespace fs = std::filesystem;

// POSIX shells do not search the current directory; cmd.exe does. The test's
// working directory is the CLI directory, so prefix ./ only where it is needed.
// Explicit string_view on purpose: auto would deduce const char* from literals.
#ifdef _WIN32
constexpr std::string_view kCliCommand = SHELLER_CLI_FILE_NAME;
#else
constexpr std::string_view kCliCommand = "./" SHELLER_CLI_FILE_NAME;
#endif

// Runs the CLI with the given args (output captured), returns "rc|output".
// cwd is the CLI directory; a leading quote on the command would trigger
// cmd /c quote-stripping and break redirection. The capture file is a
// per-process temp path: the CLI suites share that working directory, so a
// fixed name lets concurrent ctest jobs clobber each other's output.
std::string run_and_capture(std::string_view args)
{
    const auto out_path = sheller_test::temp_path("sheller_cli_version_out.txt").string();
    const auto cmd = std::format("{} {} > \"{}\" 2>&1", kCliCommand, args, out_path);
    const auto exit_code = std::system(cmd.c_str());
    std::ifstream file(out_path);
    const std::string output((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
    std::error_code ec;
    fs::remove(out_path, ec);
    return std::format("{}|{}", exit_code, output);
}

TEST(CliVersion, VersionFlagExitsZeroAndPrintsName)
{
    const auto result = run_and_capture("--version");
    EXPECT_EQ(result.substr(0, result.find('|')), "0");
    EXPECT_NE(result.find("sheller v"), std::string::npos);
}

TEST(CliVersion, NoArgsAlsoPrintsVersion)
{
    const auto result = run_and_capture("");
    EXPECT_EQ(result.substr(0, result.find('|')), "0");
    EXPECT_NE(result.find("sheller v"), std::string::npos);
}

TEST(CliUsage, UnknownArgExitsNonZero)
{
    const auto cmd = std::format("{} --definitely-not-a-flag", kCliCommand);
    EXPECT_NE(std::system(cmd.c_str()), 0);
}

} // namespace
