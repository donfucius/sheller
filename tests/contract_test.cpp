// Contract type-layer tests: TLV encode/decode round-trips, forward
// compatibility (unknown types skipped), golden bytes, negative paths, and
// layout pins. Everything here runs on both platforms - the contract is
// pure types and pure functions.

#include <sheller/events.h>
#include <sheller/guest_context.h>
#include <sheller/guest_probe.h>
#include <sheller/syscall_ctx.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <span>
#include <string>
#include <vector>

namespace {

namespace ev = sheller;

constexpr std::uint32_t kFixtureTid = 42;
constexpr std::uint64_t kFixtureSeqBase = 100;
constexpr std::uint64_t kFixturePc = 0x7FF600001000ULL;

sheller::EventPreamble fixture_preamble(std::uint64_t seq)
{
    return sheller::EventPreamble{.seq = seq, .tid = kFixtureTid, .pc = kFixturePc};
}

// Fixture with all four fields distinct so round-trips prove field order.
sheller::EventPreamble fixture_preamble_at(std::size_t index)
{
    return sheller::EventPreamble{
        .seq = kFixtureSeqBase + index, .tid = kFixtureTid, .pc = kFixturePc + index};
}

std::vector<sheller::EventPreamble> fixture_preambles(std::size_t count)
{
    std::vector<sheller::EventPreamble> preambles;
    for (std::size_t i = 0; i < count; ++i) {
        preambles.push_back(fixture_preamble_at(i));
    }
    return preambles;
}

TEST(GuestContractTypes, GuestContextLayoutIsPinned)
{
    static_assert(sizeof(sheller::GuestContext) == 16 * sizeof(std::uint64_t) + 16);
    const sheller::GuestContext ctx{.regs = {1, 2, 3}, .rip = 0x401000, .rflags = 0x246};
    EXPECT_EQ(ctx.regs[0], 1U);
    EXPECT_EQ(ctx.regs[1], 2U);
    EXPECT_EQ(ctx.regs[2], 3U);
    EXPECT_EQ(ctx.regs[15], 0U);
    EXPECT_EQ(ctx.rip, 0x401000U);
    EXPECT_EQ(ctx.rflags, 0x246U);
}

TEST(GuestContractTypes, SyscallCtxCarriesNumberArgsTidAndResult)
{
    sheller::SyscallCtx ctx{.number = 0x1000,
                            .r10 = 0xA,
                            .rdx = 0xB,
                            .r8 = 0xC,
                            .r9 = 0xD,
                            .rip = 0x401000U,
                            .rsp = 0x7F000000U,
                            .tid = kFixtureTid,
                            .result = 0};
    ctx.result = -0x2A; // any handler result survives
    EXPECT_EQ(ctx.number, 0x1000U);
    EXPECT_EQ(ctx.r10, 0xAU);
    EXPECT_EQ(ctx.tid, kFixtureTid);
    EXPECT_EQ(ctx.result, -0x2A);
}

TEST(GuestContractTypes, GuestProbeIsAbstract)
{
    static_assert(std::is_abstract_v<sheller::GuestProbe>);
}

TEST(EventTypes, CoversEventList)
{
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kMemRead) == 1);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kMemWrite) == 2);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kBlockExec) == 3);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kXfer) == 4);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kSyscall) == 5);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kCpuid) == 6);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kRdtsc) == 7);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kException) == 8);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kThreadCreate) == 9);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kApiCall) == 10);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kSampleCode) == 11);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kPebWalk) == 12);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kExportWalk) == 13);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kDirectSyscall) == 14);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kIndirectSyscall) == 15);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kGetPc) == 16);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kRwxAlloc) == 17);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kSmcExecute) == 18);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kAntiDebug) == 19);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kOepCandidate) == 20);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kExceptionDisposition) == 21);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kExceptionHandlerInstall) == 22);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kLoopSkip) == 23);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kKusdAccess) == 24);
    static_assert(static_cast<std::uint16_t>(ev::EventTypeId::kStackRestore) == 25);
    // The fixed name table moves with the enum: one spelling per id.
    static_assert(ev::kEventTypeCount == 26);
    static_assert(ev::kEventTypeNames.size() == ev::kEventTypeCount);
    static_assert(ev::kEventTypeNames[11] == "sample-code");
    static_assert(ev::kEventTypeNames[12] == "peb-walk");
    static_assert(ev::kEventTypeNames[18] == "smc-execute");
    static_assert(ev::kEventTypeNames[21] == "exception-disposition");
    static_assert(ev::kEventTypeNames[22] == "exception-handler-install");
    static_assert(ev::kEventTypeNames[24] == "kusd-access");
    static_assert(ev::kEventTypeNames[25] == "stack-restore");
    static_assert(ev::is_judgment_event(ev::EventTypeId::kPebWalk));
    static_assert(ev::is_judgment_event(ev::EventTypeId::kKusdAccess));
    static_assert(!ev::is_judgment_event(ev::EventTypeId::kSampleCode));
    static_assert(!ev::is_judgment_event(ev::EventTypeId::kApiCall));
    // The stack-restore confirmation is engine-produced, not a rule-layer
    // judgment: it sits outside the judgment range on purpose.
    static_assert(!ev::is_judgment_event(ev::EventTypeId::kStackRestore));
    SUCCEED();
}

TEST(EventTypes, JudgmentPayloadRoundTrip)
{
    const ev::JudgmentFields fields{
        .address = 0x7FF600001080ULL,
        .aux = 0x1234,
        .subtype = static_cast<std::uint32_t>(ev::AntiDebugSubtype::kRdtscBurst),
        .api = "kernel32!IsDebuggerPresent"};
    std::array<std::uint8_t, 256> out{};
    const auto written = ev::encode_judgment(out, fields);
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(*written, ev::kJudgmentFixedBytes + fields.api.size());

    const auto decoded = ev::read_judgment(std::span(out.data(), *written));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->fields.address, fields.address);
    EXPECT_EQ(decoded->fields.aux, fields.aux);
    EXPECT_EQ(decoded->fields.subtype, fields.subtype);
    EXPECT_EQ(decoded->fields.api, fields.api);
}

TEST(EventTypes, ForwardedFactPayloadsRoundTrip)
{
    const ev::MemAccessFields access{.address = 0x7FFE0320,
                                     .value = 0xDEADBEEF,
                                     .size = 8,
                                     .flags = ev::kMemAccessFlagSampleWriter};
    std::array<std::uint8_t, 64> out{};
    const auto written = ev::encode_mem_access(out, access);
    ASSERT_TRUE(written.has_value());
    const auto decoded = ev::read_mem_access(std::span(out.data(), *written));
    ASSERT_TRUE(decoded.has_value());
    EXPECT_EQ(decoded->address, access.address);
    EXPECT_EQ(decoded->value, access.value);
    EXPECT_EQ(decoded->size, access.size);
    EXPECT_EQ(decoded->flags, access.flags);

    const std::array<std::uint8_t, 5> bytes{0xE8, 0, 0, 0, 0};
    const ev::SampleCodeFields code{.length = 5, .bytes = bytes};
    const auto code_written = ev::encode_sample_code(out, code);
    ASSERT_TRUE(code_written.has_value());
    const auto code_decoded = ev::read_sample_code(std::span(out.data(), *code_written));
    ASSERT_TRUE(code_decoded.has_value());
    EXPECT_EQ(code_decoded->length, 5);
    ASSERT_EQ(code_decoded->bytes.size(), 5U);
    EXPECT_EQ(0, std::memcmp(code_decoded->bytes.data(), bytes.data(), bytes.size()));
}

TEST(EventTypes, JudgmentSubtypeSpellings)
{
    EXPECT_EQ(ev::anti_debug_subtype_name(
                  static_cast<std::uint32_t>(ev::AntiDebugSubtype::kBeingDebugged)),
              "being-debugged");
    EXPECT_EQ(ev::anti_debug_subtype_name(
                  static_cast<std::uint32_t>(ev::AntiDebugSubtype::kProbeApiCall)),
              "probe-api-call");
    EXPECT_EQ(ev::exception_disposition_name(
                  static_cast<std::uint32_t>(ev::ExceptionDisposition::kFirstChance)),
              "first-chance");
    EXPECT_EQ(ev::exception_disposition_name(
                  static_cast<std::uint32_t>(ev::ExceptionDisposition::kUnhandled)),
              "unhandled");
}

TEST(TlvRoundTrip, EveryEventTypeSurvives)
{
    const auto preambles = fixture_preambles(8);
    const std::vector<ev::EventTypeId> types = {
        ev::EventTypeId::kMemRead, ev::EventTypeId::kMemWrite,  ev::EventTypeId::kBlockExec,
        ev::EventTypeId::kXfer,    ev::EventTypeId::kSyscall,   ev::EventTypeId::kCpuid,
        ev::EventTypeId::kRdtsc,   ev::EventTypeId::kException,
    };
    for (std::size_t i = 0; i < types.size(); ++i) {
        SCOPED_TRACE(static_cast<int>(types[i]));
        const std::vector<std::uint8_t> fields(i % 3, 0xAB);

        std::array<std::uint8_t, 512> out{};
        const auto written = ev::encode_event(out, types[i], preambles[i], fields);
        ASSERT_TRUE(written.has_value()) << ev::event_codec_error_message(written.error());
        ASSERT_EQ(*written, ev::kEventHeaderSize + ev::kEventPreambleSize + fields.size());

        std::span<const std::uint8_t> in(out.data(), *written);
        const auto view = ev::read_event(in);
        ASSERT_TRUE(view.has_value()) << ev::event_codec_error_message(view.error());
        EXPECT_EQ(view->type, types[i]);
        EXPECT_EQ(view->total_size, *written);
        ASSERT_EQ(view->payload.size(), ev::kEventPreambleSize + fields.size());

        const auto decoded = ev::read_preamble(view->payload);
        ASSERT_TRUE(decoded.has_value());
        EXPECT_EQ(decoded->seq, preambles[i].seq);
        EXPECT_EQ(decoded->tid, preambles[i].tid);
        EXPECT_EQ(decoded->pc, preambles[i].pc);
        if (!fields.empty()) {
            EXPECT_EQ(0, std::memcmp(view->payload.data() + ev::kEventPreambleSize, fields.data(),
                                     fields.size()));
        }
    }
}

TEST(TlvRoundTrip, EmptyPayloadIsPreambleOnly)
{
    std::array<std::uint8_t, 128> out{};
    const auto written =
        ev::encode_event(out, ev::EventTypeId::kCpuid, fixture_preamble(kFixtureSeqBase), {});
    ASSERT_TRUE(written.has_value());
    EXPECT_EQ(*written, ev::kEventHeaderSize + ev::kEventPreambleSize);

    std::span<const std::uint8_t> in(out.data(), *written);
    const auto view = ev::read_event(in);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->payload.size(), ev::kEventPreambleSize);
}

TEST(TlvForwardCompat, UnknownTypeIsSkipped)
{
    std::array<std::uint8_t, 512> out{};
    std::size_t cursor = 0;

    // unknown type 0x7FFF with an 8-byte payload, then a known event
    const auto unknown =
        ev::encode_event(std::span(out).subspan(cursor), static_cast<ev::EventTypeId>(0x7FFF),
                         fixture_preamble(1), std::vector<std::uint8_t>(8, 0xEE));
    ASSERT_TRUE(unknown.has_value());
    cursor += *unknown;

    const auto known = ev::encode_event(std::span(out).subspan(cursor), ev::EventTypeId::kBlockExec,
                                        fixture_preamble(2), std::vector<std::uint8_t>{});
    ASSERT_TRUE(known.has_value());
    cursor += *known;

    std::span<const std::uint8_t> in(out.data(), cursor);
    const auto first = ev::read_event(in);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->type, static_cast<ev::EventTypeId>(0x7FFF));

    const auto second = ev::read_event(in.subspan(first->total_size));
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->type, ev::EventTypeId::kBlockExec);
}

// Two back-to-back syscall events: the canonical fixed byte sequence for the
// golden file and the truncation/bad-length negatives.
std::vector<std::uint8_t> canonical_bytes()
{
    const auto preambles = fixture_preambles(2);
    std::array<std::uint8_t, 512> out{};
    std::size_t cursor = 0;
    for (const auto& preamble : preambles) {
        const auto written =
            ev::encode_event(std::span(out).subspan(cursor), ev::EventTypeId::kSyscall, preamble,
                             std::vector<std::uint8_t>{0x34, 0x12});
        if (!written.has_value()) {
            ADD_FAILURE() << ev::event_codec_error_message(written.error());
            return {};
        }
        cursor += *written;
    }
    return std::vector<std::uint8_t>(out.begin(), out.begin() + static_cast<long>(cursor));
}

TEST(TlvGolden, GoldenBytesMatchLayout)
{
    const auto bytes = canonical_bytes();
    const auto expected_size =
        2 * (ev::kEventHeaderSize + ev::kEventPreambleSize + sizeof(std::uint16_t));
    ASSERT_EQ(bytes.size(), expected_size);

#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996) // getenv is fine in a test
#endif
    const char* const regenerate = std::getenv("SHELLER_REGEN_CONTRACT_GOLDEN");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (regenerate != nullptr && *regenerate != '\0') {
        std::ofstream out(regenerate, std::ios::binary | std::ios::trunc);
        out.write(reinterpret_cast<const char*>(bytes.data()),
                  static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(out) << "cannot write golden file: " << regenerate;
        GTEST_SKIP() << "golden regenerated at " << regenerate;
    }

    std::ifstream golden(SHELLER_CONTRACT_GOLDEN, std::ios::binary);
    ASSERT_TRUE(golden) << "golden file missing: " << SHELLER_CONTRACT_GOLDEN
                        << " (regenerate via SHELLER_REGEN_CONTRACT_GOLDEN)";
    const std::string golden_bytes((std::istreambuf_iterator<char>(golden)),
                                   std::istreambuf_iterator<char>());
    const std::string byte_str(bytes.begin(), bytes.end());
    EXPECT_EQ(golden_bytes, byte_str)
        << "TLV wire layout drifted - bump the schema and regenerate the golden";
}

TEST(TlvNegative, TruncatedStreamIsRejected)
{
    auto bytes = canonical_bytes();
    bytes.resize(ev::kEventHeaderSize + ev::kEventPreambleSize - 1); // cut inside payload
    std::span<const std::uint8_t> in(bytes.data(), bytes.size());
    const auto view = ev::read_event(in);
    ASSERT_FALSE(view.has_value());
    EXPECT_EQ(view.error(), ev::EventCodecError::kTruncated);
}

TEST(TlvNegative, BadLengthFieldIsRejected)
{
    auto bytes = canonical_bytes();
    bytes[ev::kEventLengthOffset] = 0xFF;
    bytes[ev::kEventLengthOffset + 1] = 0xFF;
    std::span<const std::uint8_t> in(bytes.data(), bytes.size());
    const auto view = ev::read_event(in);
    ASSERT_FALSE(view.has_value());
    EXPECT_EQ(view.error(), ev::EventCodecError::kTruncated);
}

} // namespace
