// Loader e2e: a bare blob wrapped as a PE enters through the loader
// route - TLS callbacks scheduled before the entry in array order, the
// entry's direct syscall lands as a behavior signal, and the terminate call
// ends the run with the marker-derived exit code.

#include "wrapper.h"

#include <sheller/peloader.h>
#include <sheller/syscallrun.h>

#include "../behavior/behavior_rules.h"

#include <gtest/gtest.h>

#include "render_test_util.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

namespace fs = std::filesystem;
namespace {

constexpr std::uint64_t kImageBase = 0x400000ULL;
constexpr std::uint64_t kBlobVa = kImageBase + 0x1000; // section head = entry

void put64(std::vector<std::uint8_t>& bytes, const std::size_t offset, const std::uint64_t value)
{
    std::memcpy(&bytes[offset], &value, sizeof value);
}

std::vector<std::uint8_t> u32bytes(std::uint32_t value)
{
    return {static_cast<std::uint8_t>(value & 0xFF), static_cast<std::uint8_t>((value >> 8) & 0xFF),
            static_cast<std::uint8_t>((value >> 16) & 0xFF),
            static_cast<std::uint8_t>((value >> 24) & 0xFF)};
}

// The loader-route sample: entry code + TLS structures in one blob.
// cb1 writes 11h at blob+0x80; cb2 writes 22h at blob+0x81 only when cb1
// already ran - the entry combines both markers into the exit code 1122h,
// so order violations surface as a different exit code. The entry also
// issues one unregistered syscall (direct-syscall signal) before exiting.
std::vector<std::uint8_t> build_sample()
{
    const std::uint64_t marker1 = kBlobVa + 0x80;
    const std::uint64_t marker2 = kBlobVa + 0x81;
    const std::uint64_t index_va = kBlobVa + 0x90;
    const std::uint64_t array_va = kBlobVa + 0xA0;
    const std::uint64_t cb1 = kBlobVa + 0xB0;
    const std::uint64_t cb2 = kBlobVa + 0xC0;

    std::vector<std::uint8_t> blob(0x200, 0);
    auto put = [&blob](std::size_t offset, const std::vector<std::uint8_t>& bytes) {
        std::copy(bytes.begin(), bytes.end(), blob.begin() + static_cast<std::size_t>(offset));
    };
    // entry: read both markers, combine, direct syscall, terminate 1122h
    put(0x00, {0x0F, 0xB6, 0x14, 0x25, 0x81, 0x10, 0x40, 0x00}); // movzx edx, byte [B+0x81]
    put(0x08, {0x0F, 0xB6, 0x0C, 0x25, 0x80, 0x10, 0x40, 0x00}); // movzx ecx, byte [B+0x80]
    put(0x10, {0xC1, 0xE2, 0x08});                               // shl edx, 8
    put(0x13, {0x0B, 0xD1});                                     // or edx, ecx
    put(0x15, {0xB8, 0xEF, 0xBE, 0x00, 0x00});                   // mov eax, 0BEEFh
    put(0x1A, {0x0F, 0x05});                                     // syscall (direct signal)
    put(0x1C, {0x49, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF});       // mov r10, -1
    put(0x23, {0xBA, 0x22, 0x11, 0x00, 0x00});                   // mov edx, 1122h
    put(0x28, {0xB8, 0x02, 0x10, 0x00, 0x00});                   // mov eax, 1002h
    put(0x2D, {0x0F, 0x05});                                     // syscall (terminate)
    // TLS directory at blob+0x40
    put64(blob, 0x40, 0);        // StartAddressOfRawData
    put64(blob, 0x48, 0);        // EndAddressOfRawData
    put64(blob, 0x50, index_va); // AddressOfIndex
    put64(blob, 0x58, array_va); // AddressOfCallBacks
    // cb1: mov byte [marker1], 11h ; ret
    put(0xB0, {0xC6, 0x04, 0x25});
    put64(blob, 0xB3, marker1);
    put(0xB7, {0x11, 0xC3});
    // cb2: only when cb1 ran - mov byte [marker2], 22h ; ret
    put(0xC0, {0x80, 0x3D});
    put64(blob, 0xC3, marker1);
    put(0xC7, {0x11, 0x75, 0x08});
    put(0xCA, {0xC6, 0x04, 0x25});
    put64(blob, 0xCD, marker2);
    put(0xD1, {0x22, 0xC3});
    // markers and the callback array
    blob[0x80] = 0;
    blob[0x81] = 0;
    put64(blob, 0x90, 0);   // index
    put64(blob, 0xA0, cb1); // callbacks[0]
    put64(blob, 0xA8, cb2); // callbacks[1]
    put64(blob, 0xB0, 0);   // terminator
    return blob;
}

std::filesystem::path write_temp_pe(const std::string& name, const std::vector<std::uint8_t>& pe)
{
    const auto dir = fs::temp_directory_path() / "sheller_loader_e2e";
    fs::create_directories(dir);
    const auto path = dir / name;
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(pe.data()), static_cast<std::streamsize>(pe.size()));
    return path;
}

std::vector<std::uint8_t> spin_pe()
{
    return sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64,
                                       std::vector<std::uint8_t>{0xEB, 0xFE})
        .value();
}

// Non-Windows hosts run the constructed container, which requires the
// synthetic module pages; Windows hosts keep the live loader entry.
sheller::engine::SyscallRunOptions loader_run_options()
{
    sheller::engine::SyscallRunOptions options;
#ifndef _WIN32
    options.synthetic_system_modules = true;
    options.synthetic_module_dir = SYNTH_MODULE_DIR;
#endif
    return options;
}

} // namespace

TEST(LoaderE2E, TlsOrderDirectSyscallAndTerminate)
{
    const auto blob = build_sample();
    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    ASSERT_TRUE(wrapped.has_value());
    // flip the wrapper's TLS data directory onto the in-blob TLS structures
    auto pe = *wrapped;
    const auto dir_entry = u32bytes(0x1000); // TLS directory RVA
    const auto dir_size = u32bytes(0x40);    // its size
    std::copy(dir_entry.begin(), dir_entry.end(), pe.begin() + 0x58 + 0xB8);
    std::copy(dir_size.begin(), dir_size.end(), pe.begin() + 0x58 + 0xBC);
    const auto pe_path = write_temp_pe("loader_tls.exe", pe);

    auto options = loader_run_options();
    options.timeout_ms = 60000;
    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    if (!stats.has_value()) {
        std::printf("tls e2e error=%d uc=%x", static_cast<int>(stats.error().error),
                    stats.error().unicorn_code);
        std::puts("");
    }
    ASSERT_TRUE(stats.has_value()) << static_cast<int>(stats.error().error);
    EXPECT_TRUE(stats->terminated);
    EXPECT_EQ(stats->exit_code, 0x1122U); // both TLS callbacks ran (11h/22h)
}

TEST(LoaderE2E, BudgetExhaustsOnSpinBlob)
{
    const auto pe_path = write_temp_pe("loader_spin.exe", spin_pe());
    auto options = loader_run_options();
    options.max_blocks = 10000;
    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    ASSERT_FALSE(stats.has_value()); // budget runs report failure, by design
    EXPECT_EQ(stats.error().error, sheller::engine::SyscallRunError::kBudgetExhausted);
    EXPECT_EQ(stats.error().stats.blocks, 10000U);
}

TEST(LoaderE2E, DeterministicAcrossRuns)
{
    std::vector<std::uint8_t> blob(0x40, 0);
    const auto direct = {0xB8, 0xEF, 0xBE, 0x00, 0x00, 0x0F, 0x05}; // mov eax,0BEEFh; syscall
    std::copy(direct.begin(), direct.end(), blob.begin());
    const auto terminate = {0x49, 0xC7, 0xC2, 0xFF, 0xFF, 0xFF, 0xFF, // mov r10, -1
                            0xBA, 0x34, 0x12, 0x00, 0x00,             // mov edx, 1234h
                            0xB8, 0x02, 0x10, 0x00, 0x00,             // mov eax, 1002h
                            0x0F, 0x05};                              // syscall
    std::copy(terminate.begin(), terminate.end(), blob.begin() + 7);
    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    ASSERT_TRUE(wrapped.has_value());
    const auto pe_path = write_temp_pe("loader_det.exe", *wrapped);

    const auto run = [&] {
        sheller::behavior::BehaviorRulesParams params;
        params.sample_image_base = kImageBase;
        params.sample_image_size = 0x2000;
        sheller::behavior::BehaviorRules rules(params);
        std::string emitted;
        rules.set_event_emitter([&emitted](const sheller::EventTypeId type,
                                           const sheller::EventPreamble& preamble,
                                           const std::span<const std::uint8_t>) {
            emitted += sheller::event_type_name(type);
            emitted += ':' + std::to_string(preamble.pc);
            emitted += '\n';
        });
        auto options = loader_run_options();
        // The fact seam has no public options slot: the channel rides beside.
        sheller::engine::FactChannel fact_channel;
        fact_channel.behavior_sink = [&rules](const sheller::engine::BehaviorFact& fact) {
            rules.on_fact(fact);
        };
        options.event_sink = [&rules](const sheller::EventTypeId type,
                                      const sheller::EventPreamble& preamble,
                                      const std::span<const std::uint8_t>& fields) {
            rules.on_event(type, preamble, fields);
        };
        const auto stats =
            sheller::engine::detail::run_pe_file_with_facts(pe_path, options, fact_channel);
        const bool ok = stats.has_value() && stats->terminated && stats->exit_code == 0x1234U;
        return std::pair(ok, emitted);
    };
    const auto [ok1, report1] = run();
    const auto [ok2, report2] = run();
    EXPECT_TRUE(ok1);
    EXPECT_TRUE(ok2);
    EXPECT_EQ(report1, report2);
    EXPECT_NE(report1, "[]"); // the direct syscall lands as a signal
}
