// API-call codec tests: the kApiCall /
// function-form kSyscall payload wire contract as pure functions - head
// encode/read round-trips, the parameter record stream (kind caps,
// truncation bits, unreadable), the pinned UTF-16LE->UTF-8 conversion, and
// the raw-degradation shape for unknown syscall numbers. Pure standard
// library - runs on both platforms.

#include <sheller/events.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace {

namespace ev = sheller;

constexpr sheller::EventPreamble kPreamble{.seq = 0, .tid = 7, .pc = 0x140001000};

std::vector<std::uint8_t> le_bytes(const std::uint64_t value, const std::size_t width)
{
    std::vector<std::uint8_t> bytes(width, 0);
    if (width == 4) {
        ev::le::store_le32(bytes.data(), static_cast<std::uint32_t>(value));
    } else {
        ev::le::store_le64(bytes.data(), value);
    }
    return bytes;
}

// Encodes a complete kApiCall event (TLV) from head fields + record stream.
std::vector<std::uint8_t> encode_api_call(const ev::ApiCallFields& fields,
                                          const std::size_t record_bytes)
{
    std::vector<std::uint8_t> payload(ev::kApiCallFixedBytes + fields.name.size() + record_bytes);
    const auto head = ev::encode_api_call_head(payload, fields);
    if (!head) {
        return {};
    }
    std::vector<std::uint8_t> tlv(ev::kEventHeaderSize + ev::kEventPreambleSize + payload.size());
    const auto written =
        ev::encode_event(tlv, ev::EventTypeId::kApiCall, kPreamble,
                         std::span<const std::uint8_t>{payload.data(), payload.size()});
    if (!written) {
        return {};
    }
    tlv.resize(*written);
    return tlv;
}

} // namespace

TEST(ApiCallCodec, HeadRoundTripWithStrARecord)
{
    std::vector<std::uint8_t> payload(ev::kApiCallFixedBytes + 16 + 16);
    const ev::ApiCallFields fields{.name = "LoadLibraryA",
                                   .module = 1,
                                   .flags = ev::kEventFlagSuccess,
                                   .retval = 0x7FF800000000,
                                   .caller_retaddr = 0x1400012F4};
    const auto head = ev::encode_api_call_head(payload, fields);
    ASSERT_TRUE(head.has_value());

    const std::string arg = "ntdll.dll";
    std::size_t cursor = *head;
    const auto rec =
        ev::append_param_record(payload, cursor, ev::ParamKind::kStrA,
                                std::span<const std::uint8_t>{
                                    reinterpret_cast<const std::uint8_t*>(arg.data()), arg.size()});
    ASSERT_TRUE(rec.appended);
    EXPECT_FALSE(rec.truncated);
    payload.resize(cursor);

    const auto view = ev::read_api_call(payload);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->fields.name, "LoadLibraryA");
    EXPECT_EQ(view->fields.module, 1);
    EXPECT_EQ(view->fields.flags, ev::kEventFlagSuccess);
    EXPECT_EQ(view->fields.retval, 0x7FF800000000ULL);
    EXPECT_EQ(view->fields.caller_retaddr, 0x1400012F4ULL);

    std::size_t rcursor = 0;
    const auto parsed = ev::read_param_record(view->records, rcursor);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->kind, ev::ParamKind::kStrA);
    EXPECT_FALSE(parsed->truncated);
    const std::string decoded{reinterpret_cast<const char*>(parsed->bytes.data()),
                              parsed->bytes.size()};
    EXPECT_EQ(decoded, "ntdll.dll");
    EXPECT_EQ(rcursor, view->records.size()); // exactly one record
}

TEST(ApiCallCodec, TlvRoundTripPreservesEverything)
{
    const auto tlv = encode_api_call({.name = "VirtualAlloc",
                                      .module = 1,
                                      .flags = ev::kEventFlagSuccess,
                                      .retval = 0x1D000000,
                                      .caller_retaddr = 0x14000130C},
                                     0);
    ASSERT_FALSE(tlv.empty());

    const auto event = ev::read_event(tlv);
    ASSERT_TRUE(event.has_value());
    EXPECT_EQ(event->type, ev::EventTypeId::kApiCall);
    const auto preamble = ev::read_preamble(event->payload);
    ASSERT_TRUE(preamble.has_value());
    EXPECT_EQ(preamble->tid, 7);
    EXPECT_EQ(preamble->pc, 0x140001000ULL);

    // read_api_call consumes type fields: skip the common preamble.
    const auto view = ev::read_api_call(event->payload.subspan(ev::kEventPreambleSize));
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->fields.name, "VirtualAlloc");
    EXPECT_TRUE(view->records.empty());
}

TEST(ApiCallCodec, LongMangledNameFitsWithoutTruncation)
{
    // The 183B MSVC template-instance identity case: name-only apicall must
    // fit the head + name with zero truncation anywhere.
    std::string name(183, '?');
    const auto tlv = encode_api_call({.name = name,
                                      .module = 4,
                                      .flags = ev::kEventFlagSuccess,
                                      .retval = 0,
                                      .caller_retaddr = 0x140001000},
                                     0);
    ASSERT_FALSE(tlv.empty());
    const auto event = ev::read_event(tlv);
    ASSERT_TRUE(event.has_value());
    const auto view = ev::read_api_call(event->payload.subspan(ev::kEventPreambleSize));
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->fields.name.size(), 183U);
    EXPECT_EQ(view->fields.flags & ev::kEventFlagTruncated, 0);
}

TEST(ApiCallCodec, ParamCapSetsTruncationBits)
{
    // A 300-byte buffer-style record cuts to the 64B buffer cap, sets the
    // per-record bit7 and (producer-side) the event-level bit2.
    std::vector<std::uint8_t> payload(ev::kApiCallFixedBytes + 32 + 256);
    const ev::ApiCallFields fields{.name = "WriteFile",
                                   .module = 1,
                                   .flags = ev::kEventFlagSuccess | ev::kEventFlagTruncated,
                                   .retval = 1,
                                   .caller_retaddr = 0x140001000};
    const auto head = ev::encode_api_call_head(payload, fields);
    ASSERT_TRUE(head.has_value());
    const std::vector<std::uint8_t> blob(300, 0xAB);
    std::size_t cursor = *head;
    const auto rec = ev::append_param_record(payload, cursor, ev::ParamKind::kBuf, blob);
    ASSERT_TRUE(rec.appended);
    EXPECT_TRUE(rec.truncated);
    payload.resize(cursor);

    const auto view = ev::read_api_call(payload);
    ASSERT_TRUE(view.has_value());
    std::size_t rcursor = 0;
    const auto parsed = ev::read_param_record(view->records, rcursor);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->kind, ev::ParamKind::kBuf);
    EXPECT_TRUE(parsed->truncated);
    EXPECT_EQ(parsed->bytes.size(), ev::kParamBufMaxBytes);
}

TEST(ApiCallCodec, UnreadableRecordHasNoBytesAndNoTruncationBit)
{
    std::vector<std::uint8_t> payload(ev::kApiCallFixedBytes + 16 + 8);
    const ev::ApiCallFields fields{.name = "NtQueryObject",
                                   .module = 0,
                                   .flags = ev::kEventFlagSuccess,
                                   .retval = 0,
                                   .caller_retaddr = 0x140001000};
    const auto head = ev::encode_api_call_head(payload, fields);
    ASSERT_TRUE(head.has_value());
    std::size_t cursor = *head;
    const auto rec = ev::append_param_record(payload, cursor, ev::ParamKind::kUnreadable, {});
    ASSERT_TRUE(rec.appended);
    EXPECT_FALSE(rec.truncated);
    payload.resize(cursor);

    const auto view = ev::read_api_call(payload);
    ASSERT_TRUE(view.has_value());
    std::size_t rcursor = 0;
    const auto parsed = ev::read_param_record(view->records, rcursor);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->kind, ev::ParamKind::kUnreadable);
    EXPECT_FALSE(parsed->truncated);
    EXPECT_TRUE(parsed->bytes.empty());
}

TEST(ApiCallCodec, Utf16ConversionPinsReplacementsAndBoundaries)
{
    // "a" + lone surrogate (-> U+FFFD) + U+00E9 + surrogate pair (U+1F600) + "z"
    const std::vector<std::uint8_t> src = {
        'a',  0,    // U+0061
        0x00, 0xD8, // lone high surrogate -> U+FFFD (3 UTF-8 bytes)
        0xE9, 0x00, // U+00E9 (2 UTF-8 bytes)
        0x3D, 0xD8, // high surrogate of U+1F600
        0x00, 0xDE, // low surrogate (4 UTF-8 bytes for the pair)
        'z',  0};   // U+007A
    std::string out;
    const auto conv = ev::convert_utf16le_to_utf8(src, out, 128);
    EXPECT_TRUE(conv.units_consumed == 6); // all six units consumed
    EXPECT_FALSE(conv.truncated);
    ASSERT_EQ(out.size(), 1 + 3 + 2 + 4 + 1); // a FFFD(3) é(2) emoji(4) z
    EXPECT_EQ(out, "a\xEF\xBF\xBD\xC3\xA9\xF0\x9F\x98\x80z");
}

TEST(ApiCallCodec, Utf16ConversionTruncatesAtCodePointBoundary)
{
    // Five 3-byte code points = 15 bytes; cap at 10 keeps exactly 3 points.
    std::vector<std::uint8_t> src;
    for (int i = 0; i < 5; ++i) {
        const std::uint16_t cp = 0x4E00 + static_cast<std::uint16_t>(i); // CJK, 3 UTF-8 bytes
        src.push_back(static_cast<std::uint8_t>(cp & 0xFF));
        src.push_back(static_cast<std::uint8_t>(cp >> 8));
    }
    std::string out;
    const auto conv = ev::convert_utf16le_to_utf8(src, out, 10);
    EXPECT_TRUE(conv.truncated);
    EXPECT_EQ(conv.units_consumed, 3U);
    EXPECT_EQ(out.size(), 9U); // whole code points only, never a split sequence
}

TEST(SyscallCodec, DecodedFormRoundTrip)
{
    std::vector<std::uint8_t> payload(ev::kSyscallFixedBytes + 3 * 11);
    const ev::SyscallFields fields{
        .number = 0x55, .flags = ev::kEventFlagSuccess, .status = 0, .caller_retaddr = 0x1400018B2};
    ASSERT_TRUE(ev::encode_syscall_head(payload, fields).has_value());
    std::size_t cursor = ev::kSyscallFixedBytes;
    ASSERT_TRUE(
        ev::append_param_record(payload, cursor, ev::ParamKind::kPtr, le_bytes(0x1A4B0008, 8))
            .appended);
    ASSERT_TRUE(
        ev::append_param_record(payload, cursor, ev::ParamKind::kU32, le_bytes(0x80000000, 4))
            .appended);
    ASSERT_TRUE(
        ev::append_param_record(payload, cursor, ev::ParamKind::kStrW,
                                {reinterpret_cast<const std::uint8_t*>("\\??\\C:\\x.dll"), 14})
            .appended);
    payload.resize(cursor);

    const auto view = ev::read_syscall(payload);
    ASSERT_TRUE(view.has_value());
    EXPECT_EQ(view->fields.number, 0x55U);
    EXPECT_EQ(view->fields.status, 0U);
    EXPECT_EQ(view->fields.caller_retaddr, 0x1400018B2ULL);
    std::size_t rcursor = 0;
    const auto first = ev::read_param_record(view->records, rcursor);
    ASSERT_TRUE(first.has_value());
    EXPECT_EQ(first->kind, ev::ParamKind::kPtr);
    const auto second = ev::read_param_record(view->records, rcursor);
    ASSERT_TRUE(second.has_value());
    EXPECT_EQ(second->kind, ev::ParamKind::kU32);
    const auto third = ev::read_param_record(view->records, rcursor);
    ASSERT_TRUE(third.has_value());
    EXPECT_EQ(third->kind, ev::ParamKind::kStrW);
    EXPECT_EQ(rcursor, view->records.size());
}

TEST(SyscallCodec, RawDegradationShapeIsFourU64Records)
{
    // Unknown call number: flags bit1 + exactly four u64 register records.
    std::vector<std::uint8_t> payload(ev::kSyscallFixedBytes + 4 * 11);
    const ev::SyscallFields fields{.number = 0x1A3,
                                   .flags = ev::kEventFlagRaw,
                                   .status = 0xC0000002,
                                   .caller_retaddr = 0x14000195C};
    ASSERT_TRUE(ev::encode_syscall_head(payload, fields).has_value());
    std::size_t cursor = ev::kSyscallFixedBytes;
    for (const std::uint64_t reg : {0x2F910ULL, 0x8ULL, 0x30ULL, 0x0ULL}) {
        ASSERT_TRUE(ev::append_param_record(payload, cursor, ev::ParamKind::kU64, le_bytes(reg, 8))
                        .appended);
    }
    payload.resize(cursor);

    const auto view = ev::read_syscall(payload);
    ASSERT_TRUE(view.has_value());
    EXPECT_NE(view->fields.flags & ev::kEventFlagRaw, 0);
    EXPECT_EQ(view->fields.status, 0xC0000002U);
    std::size_t count = 0;
    std::size_t rcursor = 0;
    while (rcursor < view->records.size()) {
        const auto rec = ev::read_param_record(view->records, rcursor);
        ASSERT_TRUE(rec.has_value());
        EXPECT_EQ(rec->kind, ev::ParamKind::kU64);
        EXPECT_EQ(rec->bytes.size(), 8U);
        ++count;
    }
    EXPECT_EQ(count, 4U);
}

TEST(SyscallCodec, SyntheticTierZeroRecordsAndFlag)
{
    // The re-emission shape: synthetic bit set, no records at all, status
    // from the interception retval's low half, caller shared with apicall.
    std::vector<std::uint8_t> payload(ev::kSyscallFixedBytes);
    const ev::SyscallFields head{.number = 0x1F,
                                 .flags = ev::kEventFlagSynthetic,
                                 .status = 0x1D000000,
                                 .caller_retaddr = 0x14000130C};
    ASSERT_TRUE(ev::encode_syscall_head(payload, head).has_value());

    const auto view = ev::read_syscall(payload);
    ASSERT_TRUE(view.has_value());
    EXPECT_NE(view->fields.flags & ev::kEventFlagSynthetic, 0);
    EXPECT_EQ(view->fields.status, 0x1D000000U);
    EXPECT_EQ(view->fields.caller_retaddr, 0x14000130CULL);
    EXPECT_TRUE(view->records.empty());
}

TEST(ParamRecordCodec, StackSlotRecordsAppendWithoutJoining)
{
    // Two form params, then two shallow-stack slots: positional reads stay
    // on the params; the slots ride the same record stream untouched.
    std::vector<std::uint8_t> payload(ev::kSyscallFixedBytes + 2 * 11 + 2 * 11);
    const ev::SyscallFields head{
        .number = 0x55, .flags = ev::kEventFlagRaw, .status = 0, .caller_retaddr = 0x1400018B2};
    ASSERT_TRUE(ev::encode_syscall_head(payload, head).has_value());
    std::size_t cursor = ev::kSyscallFixedBytes;
    for (const std::uint64_t reg : {0x10ULL, 0x20ULL}) {
        std::vector<std::uint8_t> v(8);
        ev::le::store_le64(v.data(), reg);
        ASSERT_TRUE(ev::append_param_record(payload, cursor, ev::ParamKind::kU64, v).appended);
    }
    for (const std::uint64_t slot : {0x140001000ULL, 0x7FFA11223344ULL}) {
        std::vector<std::uint8_t> v(8);
        ev::le::store_le64(v.data(), slot);
        ASSERT_TRUE(
            ev::append_param_record(payload, cursor, ev::ParamKind::kStackSlot, v).appended);
    }
    payload.resize(cursor);

    const auto view = ev::read_syscall(payload);
    ASSERT_TRUE(view.has_value());
    std::size_t walked = 0;
    std::size_t params = 0;
    std::size_t slots = 0;
    std::size_t rcursor = 0;
    while (rcursor < view->records.size()) {
        const auto rec = ev::read_param_record(view->records, rcursor);
        ASSERT_TRUE(rec.has_value());
        if (rec->kind == ev::ParamKind::kStackSlot) {
            ++slots;
            ASSERT_EQ(rec->bytes.size(), 8U);
        } else {
            ASSERT_LT(params, 2U); // params keep positions 0..1
            ++params;
        }
        ++walked;
    }
    EXPECT_EQ(walked, 4U);
    EXPECT_EQ(params, 2U);
    EXPECT_EQ(slots, 2U);
}

TEST(ParamRecordCodec, RejectsMalformedStream)
{
    const std::vector<std::uint8_t> bad_header = {0x04}; // kind, no len
    std::size_t cursor = 0;
    EXPECT_FALSE(ev::read_param_record(bad_header, cursor).has_value());

    const std::vector<std::uint8_t> bad_len = {0x04, 0xFF, 0x01}; // len=511 > span
    cursor = 0;
    EXPECT_FALSE(ev::read_param_record(bad_len, cursor).has_value());
}

TEST(ParamRecordCodec, CutToSlotFitMarksTruncation)
{
    // Defensive branch: a record that does not fit the remaining span is cut
    // to fit (never silently dropped) and reported truncated.
    std::vector<std::uint8_t> tight(ev::kApiCallFixedBytes + 2 + 3 +
                                    10); // head + 1B name + 10B record
    const ev::ApiCallFields fields{
        .name = "X", .module = 0, .flags = 0, .retval = 0, .caller_retaddr = 0};
    const auto head = ev::encode_api_call_head(tight, fields);
    ASSERT_TRUE(head.has_value());
    const std::vector<std::uint8_t> blob(600, 0xCD);
    std::size_t cursor = *head;
    const auto rec = ev::append_param_record(tight, cursor, ev::ParamKind::kBuf, blob);
    ASSERT_TRUE(rec.appended);
    EXPECT_TRUE(rec.truncated);
    EXPECT_EQ(cursor, tight.size());

    const auto view = ev::read_api_call(tight);
    ASSERT_TRUE(view.has_value());
    std::size_t rcursor = 0;
    const auto parsed = ev::read_param_record(view->records, rcursor);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_TRUE(parsed->truncated);
    EXPECT_EQ(parsed->bytes.size(), 11U); // everything the slot had left
    EXPECT_EQ(rcursor, view->records.size());
}
