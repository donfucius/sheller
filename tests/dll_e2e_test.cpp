// DLL-input route end-to-end (Windows): the acceptance line, pinned against
// the CLI. capture → unpack on the packed corpus must produce a loadable
// .unp whose entry point matches the upx -d reference (0x13E4) with the DLL
// flag intact, and --stop xfer=1 must stop at the stub's post-restore jump
// to that entry (the OEP dump stop). The live-capture replay chain lives in
// dll_capture_e2e_test.cpp: the captured world's payload is
// machine-sensitive past the OEP (the per-process entropy family), so those
// tests run outside the shared CI runners.

#include <gtest/gtest.h>

#ifdef _WIN32
#include <sheller/snapshot.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#endif

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

#ifdef _WIN32
constexpr std::string_view kCliCommand = SHELLER_CLI_FILE_NAME;
#else
constexpr std::string_view kCliCommand = "./" SHELLER_CLI_FILE_NAME;
#endif

std::string run_and_capture(std::string_view args)
{
    const auto out_path = sheller_test::temp_path("sheller_dll_e2e_out.txt").string();
    const auto cmd = std::format("{} {} > \"{}\" 2>&1", kCliCommand, args, out_path);
    const auto exit_code = std::system(cmd.c_str());
    std::ifstream file(out_path);
    const std::string output((std::istreambuf_iterator<char>(file)),
                             std::istreambuf_iterator<char>());
    std::error_code ec;
    fs::remove(out_path, ec);
    return std::format("{}|{}", exit_code, output);
}

#ifdef _WIN32

fs::path packed_dll()
{
    return fs::path{SHELLER_SAMPLE_PACKED_DLL_PATH};
}

std::vector<std::uint8_t> read_bytes(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::uint32_t entry_rva_of(const std::vector<std::uint8_t>& pe)
{
    const auto e_lfanew =
        static_cast<std::uint32_t>(pe[0x3C]) | (static_cast<std::uint32_t>(pe[0x3D]) << 8);
    return static_cast<std::uint32_t>(pe[e_lfanew + 40]) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 41]) << 8) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 42]) << 16) |
           (static_cast<std::uint32_t>(pe[e_lfanew + 43]) << 24);
}

std::uint16_t characteristics_of(const std::vector<std::uint8_t>& pe)
{
    const auto e_lfanew =
        static_cast<std::uint32_t>(pe[0x3C]) | (static_cast<std::uint32_t>(pe[0x3D]) << 8);
    return static_cast<std::uint16_t>(pe[e_lfanew + 22]) |
           static_cast<std::uint16_t>(pe[e_lfanew + 23] << 8);
}

// The acceptance: capture → unpack on the packed corpus reproduces the
// reference entry point (0x13E4 = the real DllMain) with the DLL flag kept.
TEST(DllE2E, UnpackReproducesReferenceEntryPoint)
{
    const auto dir = sheller_test::temp_path("sheller_dll_e2e");
    fs::create_directories(dir);
    const auto output = dir / "packed.dll.unp";
    const auto result =
        run_and_capture(std::format("unpack \"{}\" -o \"{}\" -b 60M --timeout-ms 300000",
                                    packed_dll().string(), output.string()));
    ASSERT_EQ(result.substr(0, result.find('|')), "0") << result;
    ASSERT_TRUE(fs::exists(output));
    const auto bytes = read_bytes(output);
    ASSERT_GE(bytes.size(), 0x200u);
    EXPECT_EQ(entry_rva_of(bytes), 0x13E4u);
    EXPECT_NE(characteristics_of(bytes) & 0x2000, 0); // IMAGE_FILE_DLL kept
}

// The usable stop face on the packed DLL: --stop xfer=1 stops before the
// landing block of the stub's post-restore jump to the unpacked entry (the
// first counted transfer - the OEP dump stop). The esp faces on this stub
// are a documented silent miss (see dll_capture_e2e_test.cpp).
TEST(DllE2E, Xfer1StopsAtTheOepTransfer)
{
    const auto dir = sheller_test::temp_path("sheller_dll_e2e_xfer");
    fs::create_directories(dir);
    const auto output = dir / "xfer.dll.unp";
    const auto result =
        run_and_capture(std::format("unpack \"{}\" -o \"{}\" --stop xfer=1 -b 60M --timeout-ms"
                                    " 300000",
                                    packed_dll().string(), output.string()));
    ASSERT_EQ(result.substr(0, result.find('|')), "0") << result;
    EXPECT_NE(result.find("xfer target reached (xfers=1)"), std::string::npos) << result;
    EXPECT_NE(result.find("terminated=0"), std::string::npos) << result;
    EXPECT_TRUE(fs::exists(output)); // the OEP-face dump
}

#endif // _WIN32

} // namespace
