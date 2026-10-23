// Shim memory-access failure semantics: the VEX.256
// data-movement shim must synthesize STATUS_ACCESS_VIOLATION (read/write +
// fault address) when its loads/stores hit unmapped memory - the previous
// #UD fallback turned every such fault into STATUS_ILLEGAL_INSTRUCTION.
// The blobs hand-assemble vmovdqu ymm load/store against an unmapped
// address inside a minimal wrapped PE; the bare wrapper has no SEH, so the
// synthesized AV surfaces as an unhandled crash with the AV code in the
// exception ledger. Windows only (capture + real ntdll dispatch).

#include "event_ledger.h"
#include "wrapper.h"

#include <sheller/peloader.h>

#include <sheller/syscallrun.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <vector>

#ifdef _WIN32

namespace {

constexpr std::uint64_t kUnmapped = 0x40000000;

// movabs rax, <kUnmapped>; vmovdqu ymm0, [rax]; ret
std::vector<std::uint8_t> load_blob()
{
    return {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00, 0xC5, 0xFD, 0x6F, 0x00, 0xC3};
}

// movabs rax, <kUnmapped>; vmovdqu [rax], ymm0; ret
std::vector<std::uint8_t> store_blob()
{
    return {0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
            0x00, 0x00, 0xC5, 0xFD, 0x7F, 0x00, 0xC3};
}

std::size_t count_exceptions(const sheller::behavior::EventLedger& ledger, const std::uint32_t code)
{
    std::size_t seen = 0;
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        const auto entry = ledger.entry(i);
        if (entry.type != sheller::EventTypeId::kException) {
            continue;
        }
        if (entry.type_fields.size() < sizeof(std::uint32_t)) {
            continue;
        }
        if (sheller::le::load_le32(entry.type_fields.data()) == code) {
            ++seen;
        }
    }
    return seen;
}

struct RunResult {
    bool ok{};
    sheller::engine::SyscallRunError error{};
    sheller::behavior::EventLedger ledger;
};

RunResult run_wrapped(const std::vector<std::uint8_t>& blob)
{
    namespace fs = std::filesystem;
    const auto dir = fs::temp_directory_path() / "sheller_shim_pf";
    fs::create_directories(dir);
    static unsigned counter = 0;
    const auto pe_path = dir / ("shim_pf_" + std::to_string(++counter) + ".exe");

    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    EXPECT_TRUE(wrapped.has_value());
    {
        std::ofstream out(pe_path, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(wrapped->data()),
                  static_cast<std::streamsize>(wrapped->size()));
    }

    RunResult result;
    sheller::engine::SyscallRunOptions options;
    options.max_instructions = 0;
    options.max_blocks = 200000;
    options.timeout_ms = 30000;
    options.event_sink = [&result](const sheller::EventTypeId type,
                                   const sheller::EventPreamble& preamble,
                                   const std::span<const std::uint8_t> fields) {
        result.ledger.record(type, preamble, fields);
    };
    const auto stats = sheller::engine::run_pe_file(pe_path, options);
    result.ok = stats.has_value();
    if (!stats.has_value()) {
        result.error = stats.error().error;
    }
    return result;
}

} // namespace

TEST(ShimPf, LoadFromUnmappedSynthesizesAccessViolation)
{
    const auto result = run_wrapped(load_blob());
    EXPECT_FALSE(result.ok); // the bare wrapper has no AV handler
    EXPECT_EQ(result.error, sheller::engine::SyscallRunError::kUnhandledException);
    // the fault surfaced as an access violation, never as #UD
    EXPECT_GE(count_exceptions(result.ledger, 0xC0000005U), 1U);
    EXPECT_EQ(count_exceptions(result.ledger, 0xC000001DU), 0U);
}

TEST(ShimPf, StoreToUnmappedSynthesizesAccessViolation)
{
    const auto result = run_wrapped(store_blob());
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error, sheller::engine::SyscallRunError::kUnhandledException);
    EXPECT_GE(count_exceptions(result.ledger, 0xC0000005U), 1U);
    EXPECT_EQ(count_exceptions(result.ledger, 0xC000001DU), 0U);
}

#endif
