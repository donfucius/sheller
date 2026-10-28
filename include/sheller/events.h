// Behavior event stream: TLV wire format for the raw
// event ledger. Little-endian, self-delimiting -- readers
// skip event types they do not know by the length field -- and encoded by
// pure functions over byte spans: no buffering, no IO, no state (the ring
// buffer and the sinks are the event ledger's slice).

#ifndef SHELLER_EVENTS_H
#define SHELLER_EVENTS_H

#include <sheller/byte_order.h>
#include <sheller/guest_context.h>
#include <sheller/syscall_ctx.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <string>
#include <string_view>

namespace sheller {

// Event types from the raw-ledger list, in a dedicated id
// space (0 is reserved so an all-zero buffer never parses as a valid event;
// 0xFF00+ stays open for future additions).
enum class EventTypeId : std::uint16_t {
    kInvalid = 0,
    kMemRead = 1,
    kMemWrite = 2,
    kBlockExec = 3,
    kXfer = 4,
    kSyscall = 5,
    kCpuid = 6,
    kRdtsc = 7,
    kException = 8,
    kThreadCreate = 9, // payload = new tid, start routine (only fires
                       // when a guest creates a thread; single-thread
                       // streams stay unchanged)
    kApiCall = 10,     // loader-route interception fact: name-in-band +
                       // module index + kind-encoded parameter records
                       // Parameter names ride the
                       // semantic layer's description table, never the wire.
    // Forwarded fact: the instruction bytes a monitored code window
    // observed at pc (window side - high volume).
    kSampleCode = 11,
    // Judgment events (the rule layer's 13 patterns), ids 12..24. Spelled
    // with the historical signal-kind names except two that read better in
    // the report: exception-disposition (which no longer collides with the
    // raw exception event) and exception-handler-install. Every hit emits
    // one event - no dedupe, no capacity cap.
    kPebWalk = 12,
    kExportWalk = 13,
    kDirectSyscall = 14,
    kIndirectSyscall = 15,
    kGetPc = 16,
    kRwxAlloc = 17,
    kSmcExecute = 18,
    kAntiDebug = 19,
    kOepCandidate = 20,
    kExceptionDisposition = 21,
    kExceptionHandlerInstall = 22,
    kLoopSkip = 23,
    kKusdAccess = 24,
    // The entry stack-restore confirmation: the
    // engine's esp window saw the completed restore of the entry save area -
    // a pop put the stack pointer back at the entry face with a decoded
    // register pop. Preamble-only (pc is the confirming read's rip); never a
    // stop by itself - the esp stop target is the stop, this is the passive
    // observation every instrumented run carries.
    kStackRestore = 25,
};

inline constexpr std::size_t kEventTypeCount =
    static_cast<std::size_t>(EventTypeId::kStackRestore) + 1;

// True for the judgment ids (kPebWalk..kKusdAccess): the rule layer produces
// them, the semantic collector and the ledger carry them like any event.
inline constexpr bool is_judgment_event(const EventTypeId type)
{
    return static_cast<std::size_t>(type) >= static_cast<std::size_t>(EventTypeId::kPebWalk) &&
           static_cast<std::size_t>(type) <= static_cast<std::size_t>(EventTypeId::kKusdAccess);
}

// Judgment subtypes, carried in the judgment payload's subtype field. The
// fixed lowercase spellings are part of the report contract (the enum and the
// spelling move together), exactly as the retired signal header declared them.
enum class AntiDebugSubtype : std::uint32_t {
    kBeingDebugged = 1,
    kQueryInformationProcess = 2,
    kRdtscBurst = 3,
    kCpuidHypervisor = 4,
    kProbeApiCall = 5,
};

inline constexpr std::string_view anti_debug_subtype_name(const std::uint32_t subtype)
{
    switch (static_cast<AntiDebugSubtype>(subtype)) {
    case AntiDebugSubtype::kBeingDebugged:
        return "being-debugged";
    case AntiDebugSubtype::kQueryInformationProcess:
        return "query-information-process";
    case AntiDebugSubtype::kRdtscBurst:
        return "rdtsc-burst";
    case AntiDebugSubtype::kCpuidHypervisor:
        return "cpuid-hypervisor";
    case AntiDebugSubtype::kProbeApiCall:
        return "probe-api-call";
    }
    return "";
}

enum class ExceptionDisposition : std::uint32_t {
    kFirstChance = 1,
    kUnhandled = 2,
    kHandlerDispatch = 3,
};

inline constexpr std::string_view exception_disposition_name(const std::uint32_t subtype)
{
    switch (static_cast<ExceptionDisposition>(subtype)) {
    case ExceptionDisposition::kFirstChance:
        return "first-chance";
    case ExceptionDisposition::kUnhandled:
        return "unhandled";
    case ExceptionDisposition::kHandlerDispatch:
        return "handler-dispatch";
    }
    return "";
}

// Common payload prefix every event carries, before any type-specific
// fields: sequence number, thread id, and the guest pc.
struct EventPreamble {
    std::uint64_t seq{};
    std::uint32_t tid{};
    std::uint64_t pc{};
};

// Fixed lowercase event names, indexed by EventTypeId: part of the wire
// contract (the type u16 on the left and this spelling on the right move
// together). Values outside the known id space render as "unknown".
inline constexpr std::array<std::string_view, kEventTypeCount> kEventTypeNames{
    "invalid",
    "mem-read",
    "mem-write",
    "block-exec",
    "xfer",
    "syscall",
    "cpuid",
    "rdtsc",
    "exception",
    "thread-create",
    "apicall",
    "sample-code",
    "peb-walk",
    "export-walk",
    "direct-syscall",
    "indirect-syscall",
    "getpc",
    "rwx-alloc",
    "smc-execute",
    "anti-debug",
    "oep-candidate",
    "exception-disposition",
    "exception-handler-install",
    "loop-skip",
    "kusd-access",
    "stack-restore"};

inline std::string_view event_type_name(const EventTypeId type)
{
    const auto index = static_cast<std::size_t>(type);
    return index < kEventTypeNames.size() ? kEventTypeNames[index] : std::string_view{"unknown"};
}

// Wire layout: [type u16][length u16][payload], little-endian; length covers
// the payload bytes (preamble + type-specific fields). Derived offsets are
// pinned by static_asserts -- the layout is part of the contract.
inline constexpr std::size_t kEventTypeOffset = 0;
inline constexpr std::size_t kEventLengthOffset = kEventTypeOffset + sizeof(std::uint16_t);
inline constexpr std::size_t kEventHeaderSize = kEventLengthOffset + sizeof(std::uint16_t);
inline constexpr std::size_t kEventPreambleOffset = 0;
inline constexpr std::size_t kEventPreambleTidOffset = kEventPreambleOffset + sizeof(std::uint64_t);
inline constexpr std::size_t kEventPreamblePcOffset =
    kEventPreambleTidOffset + sizeof(std::uint32_t);
inline constexpr std::size_t kEventPreambleSize = kEventPreamblePcOffset + sizeof(std::uint64_t);

static_assert(kEventHeaderSize == 4, "event header must be 4 bytes");
static_assert(kEventPreambleSize == 20, "event preamble must be 20 bytes");

enum class EventCodecError {
    kNone = 0,
    kOverflow,  // output span too small for the encoded event
    kTruncated, // input ended inside the header, the payload, or past a bad length
};

std::string_view event_codec_error_message(EventCodecError error);

// Serializes one event: [type][length][preamble][type_fields]; returns the
// number of bytes written. type_fields may be empty (the preamble alone is a
// complete payload for pc-only events such as cpuid/rdtsc).
inline std::expected<std::size_t, EventCodecError>
encode_event(std::span<std::uint8_t> out, EventTypeId type, const EventPreamble& preamble,
             std::span<const std::uint8_t> type_fields);

struct EventView {
    EventTypeId type{};
    std::size_t total_size{};                // header + payload, the skip distance
    std::span<const std::uint8_t> payload{}; // preamble + type-specific fields
};

// Parses one event at the front of the input. Unknown event types come back
// with type preserved as their raw value and payload intact -- the caller
// decides whether a type is known; skipping is simply ignoring the payload
// and advancing by total_size.
inline std::expected<EventView, EventCodecError> read_event(std::span<const std::uint8_t> in);

// Decodes the common preamble from an event payload span.
inline std::expected<EventPreamble, EventCodecError>
read_preamble(std::span<const std::uint8_t> payload);

std::string_view event_codec_error_message(EventCodecError error);

// -- api-call parameter records -----------------
//
// Shared flags byte for kApiCall and kSyscall payloads; producers OR the
// bits that apply.
inline constexpr std::uint8_t kEventFlagSuccess = 0x01;   // bit0: call succeeded
inline constexpr std::uint8_t kEventFlagRaw = 0x02;       // bit1: parameters are raw register
                                                          // values (no signature decode)
inline constexpr std::uint8_t kEventFlagTruncated = 0x04; // bit2: payload has truncated params
inline constexpr std::uint8_t kEventFlagSynthetic = 0x08; // bit3: interception-layer derived
                                                          // fact, not directly observed; the
                                                          // synthetic tier carries NO parameter
                                                          // records or shallow-stack slots

// Parameter record wire: [kind u8][len u16][bytes len], positional, no
// names. kind low 7 bits; bit7 marks this record truncated at capture
// (caps below). len covers bytes only and is 0 for kUnreadable.
inline constexpr std::uint8_t kParamTruncatedBit = 0x80;
enum class ParamKind : std::uint8_t {
    kU32 = 0,
    kU64 = 1,
    kPtr = 2,
    kBool = 3,
    kStrA = 4, // ANSI bytes as captured
    kStrW = 5, // UTF-16LE converted to UTF-8 at capture (pinned algorithm:
               // lone surrogates -> U+FFFD; caps below count post-conversion)
    kBuf = 6,
    kUnreadable = 7, // guest memory unreadable at capture; no bytes follow
    kStackSlot = 8,  // shallow-stack snapshot slot (u64 raw value above the
                     // caller's return address; attribution-only - appended
                     // AFTER form-parameter records, never positionally
                     // joined, never counted as a form parameter)
};

// Capture-side caps: string parameters keep at most 128 UTF-8 bytes, buffer
// parameters 64 raw bytes. Original lengths are NOT stored - length
// semantics live in same-name size parameters of the call.
inline constexpr std::size_t kParamStrMaxBytes = 128;
inline constexpr std::size_t kParamBufMaxBytes = 64;

struct ParamRecordView {
    ParamKind kind{};
    bool truncated{};
    std::span<const std::uint8_t> bytes{}; // empty for kUnreadable
};

struct ParamAppendResult {
    bool appended{};  // record (possibly cut to fit) landed in out
    bool truncated{}; // bytes were cut by a cap or by slot fit
};

// Appends one record at out[cursor] and advances cursor past it. Oversized
// string/buffer bytes are cut to their cap; a record that would not fit the
// remaining span is cut further to fit (defensive - the 256B slot budget
// means this should not fire). Nothing is appended only when even the
// 3-byte header does not fit.
inline ParamAppendResult append_param_record(std::span<std::uint8_t> out, std::size_t& cursor,
                                             const ParamKind kind,
                                             const std::span<const std::uint8_t> bytes)
{
    const std::size_t cap = kind == ParamKind::kStrA || kind == ParamKind::kStrW
                                ? kParamStrMaxBytes
                                : (kind == ParamKind::kBuf ? kParamBufMaxBytes : bytes.size());
    std::size_t kept = bytes.size() < cap ? bytes.size() : cap;
    bool truncated = kept < bytes.size();
    if (cursor + 3 + kept > out.size()) {
        if (cursor + 3 > out.size()) {
            return {.appended = false, .truncated = false};
        }
        kept = out.size() - cursor - 3;
        truncated = true;
    }
    out[cursor] = static_cast<std::uint8_t>(kind) | (truncated ? kParamTruncatedBit : 0);
    le::store_le16(out.data() + cursor + 1, static_cast<std::uint16_t>(kept));
    if (kept != 0) {
        for (std::size_t i = 0; i < kept; ++i) {
            out[cursor + 3 + i] = bytes[i];
        }
    }
    cursor += 3 + kept;
    return {.appended = true, .truncated = truncated};
}

// Parses one record at in[cursor]; advances cursor past it. kTruncated
// means the record header or bytes ran past the span - the stream is
// malformed and the caller must stop.
inline std::expected<ParamRecordView, EventCodecError>
read_param_record(const std::span<const std::uint8_t> in, std::size_t& cursor)
{
    if (cursor + 3 > in.size()) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    const auto kind_byte = in[cursor];
    const auto len = le::load_le16(in.data() + cursor + 1);
    if (cursor + 3 + len > in.size()) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    const ParamRecordView view{.kind = static_cast<ParamKind>(kind_byte & ~kParamTruncatedBit),
                               .truncated = (kind_byte & kParamTruncatedBit) != 0,
                               .bytes = in.subspan(cursor + 3, len)};
    cursor += 3 + len;
    return view;
}

// UTF-16LE code units -> UTF-8, pinned conversion algorithm for the kStrW
// capture point (determinism contract): valid pairs encode as UTF-8, lone
// surrogates and a dangling odd byte become U+FFFD, and the output stops at
// whole-code-point boundaries when max_bytes would be exceeded (never a
// split sequence). Appends to out; reports units consumed and whether
// source was cut by max_bytes.
struct Utf16Conversion {
    std::size_t units_consumed{};
    bool truncated{};
};

inline Utf16Conversion convert_utf16le_to_utf8(const std::span<const std::uint8_t> src,
                                               std::string& out, const std::size_t max_bytes)
{
    static constexpr char32_t kReplacement = 0xFFFD;
    const auto encode = [&](const char32_t cp) {
        if (cp < 0x80) {
            out.push_back(static_cast<char>(cp));
        } else if (cp < 0x800) {
            out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else if (cp < 0x10000) {
            out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        } else {
            out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
            out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
        }
    };
    const auto units = src.size() / 2;
    const auto unit_at = [&](const std::size_t i) { return le::load_le16(src.data() + 2 * i); };
    const auto encoded_size = [](const char32_t cp) {
        return cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
    };
    Utf16Conversion result{};
    std::size_t i = 0;
    while (i < units) {
        char32_t cp = unit_at(i);
        std::size_t consumed = 1;
        if (cp >= 0xD800 && cp <= 0xDBFF && i + 1 < units && unit_at(i + 1) >= 0xDC00 &&
            unit_at(i + 1) <= 0xDFFF) {
            cp = 0x10000 + ((cp - 0xD800) << 10) + (unit_at(i + 1) - 0xDC00);
            consumed = 2;
        } else if (cp >= 0xD800 && cp <= 0xDFFF) {
            cp = kReplacement; // lone surrogate
        }
        if (out.size() + encoded_size(cp) > max_bytes) {
            result.truncated = true;
            break;
        }
        encode(cp);
        i += consumed;
        result.units_consumed += consumed;
    }
    if (i * 2 < src.size() && !result.truncated) {
        result.truncated = true; // dangling odd byte: reported, not encoded
    }
    return result;
}

// -- kApiCall payload ------------------------------------------------------
// [name_len u8][name][module u16][flags u8][retval u64][caller u64][records]
// The offsets below describe the empty-name form; every field after the
// name shifts by name_len (accessors compute dynamic offsets).
inline constexpr std::size_t kApiCallNameLenOffset = 0;
inline constexpr std::size_t kApiCallModuleOffset = kApiCallNameLenOffset + 1;
inline constexpr std::size_t kApiCallFixedBytes = kApiCallModuleOffset + 2 + 1 + 8 + 8; // 20
static_assert(kApiCallFixedBytes == 20, "apicall fixed head must be 20 bytes");

struct ApiCallFields {
    std::string_view name; // <=255 bytes, no NUL
    std::uint16_t module{};
    std::uint8_t flags{};
    std::uint64_t retval{};
    std::uint64_t caller_retaddr{};
};

// Writes the fixed head; parameter records follow via append_param_record.
// Returns the cursor after the head.
inline std::expected<std::size_t, EventCodecError> encode_api_call_head(std::span<std::uint8_t> out,
                                                                        const ApiCallFields& fields)
{
    if (fields.name.size() > 255 || out.size() < kApiCallFixedBytes + fields.name.size()) {
        return std::unexpected(EventCodecError::kOverflow);
    }
    out[kApiCallNameLenOffset] = static_cast<std::uint8_t>(fields.name.size());
    for (std::size_t i = 0; i < fields.name.size(); ++i) {
        out[kApiCallModuleOffset + i] = static_cast<std::uint8_t>(fields.name[i]);
    }
    const std::size_t module_at = kApiCallModuleOffset + fields.name.size();
    le::store_le16(out.data() + module_at, fields.module);
    out[module_at + 2] = fields.flags;
    le::store_le64(out.data() + module_at + 3, fields.retval);
    le::store_le64(out.data() + module_at + 11, fields.caller_retaddr);
    return kApiCallFixedBytes + fields.name.size();
}

struct ApiCallView {
    ApiCallFields fields{};                  // name views into the input span
    std::span<const std::uint8_t> records{}; // parameter record stream
};

inline std::expected<ApiCallView, EventCodecError>
read_api_call(const std::span<const std::uint8_t> payload)
{
    if (payload.size() < kApiCallFixedBytes) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    ApiCallView view;
    const auto name_len = payload[kApiCallNameLenOffset];
    if (payload.size() < kApiCallFixedBytes + name_len) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    const auto name_bytes = payload.subspan(kApiCallModuleOffset, name_len);
    view.fields.name =
        std::string_view{reinterpret_cast<const char*>(name_bytes.data()), name_bytes.size()};
    const std::size_t module_at = kApiCallModuleOffset + name_len;
    view.fields.module = le::load_le16(payload.data() + module_at);
    view.fields.flags = payload[module_at + 2];
    view.fields.retval = le::load_le64(payload.data() + module_at + 3);
    view.fields.caller_retaddr = le::load_le64(payload.data() + module_at + 11);
    view.records = payload.subspan(kApiCallFixedBytes + name_len);
    return view;
}

// -- kSyscall payload (function-form reshape) -----
// [number u32][flags u8][status u32][caller u64][records]
inline constexpr std::size_t kSyscallNumberOffset = 0;
inline constexpr std::size_t kSyscallFlagsOffset = kSyscallNumberOffset + 4;
inline constexpr std::size_t kSyscallStatusOffset = kSyscallFlagsOffset + 1;
inline constexpr std::size_t kSyscallCallerOffset = kSyscallStatusOffset + 4;
inline constexpr std::size_t kSyscallFixedBytes = kSyscallCallerOffset + 8; // 17
static_assert(kSyscallFixedBytes == 17, "syscall fixed head must be 17 bytes");

struct SyscallFields {
    std::uint32_t number{}; // observed call number (name resolution is a
                            // semantic-layer join, never on the wire)
    std::uint8_t flags{};   // kEventFlag* bits
    std::uint32_t status{}; // NTSTATUS; raw档 = rejection code or 0
    std::uint64_t caller_retaddr{};
};

inline std::expected<std::size_t, EventCodecError> encode_syscall_head(std::span<std::uint8_t> out,
                                                                       const SyscallFields& fields)
{
    if (out.size() < kSyscallFixedBytes) {
        return std::unexpected(EventCodecError::kOverflow);
    }
    le::store_le32(out.data() + kSyscallNumberOffset, fields.number);
    out[kSyscallFlagsOffset] = fields.flags;
    le::store_le32(out.data() + kSyscallStatusOffset, fields.status);
    le::store_le64(out.data() + kSyscallCallerOffset, fields.caller_retaddr);
    return kSyscallFixedBytes;
}

struct SyscallView {
    SyscallFields fields{};
    std::span<const std::uint8_t> records{}; // decoded records, or 4 raw u64
};

inline std::expected<SyscallView, EventCodecError>
read_syscall(const std::span<const std::uint8_t> payload)
{
    if (payload.size() < kSyscallFixedBytes) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    SyscallView view;
    view.fields.number = le::load_le32(payload.data() + kSyscallNumberOffset);
    view.fields.flags = payload[kSyscallFlagsOffset];
    view.fields.status = le::load_le32(payload.data() + kSyscallStatusOffset);
    view.fields.caller_retaddr = le::load_le64(payload.data() + kSyscallCallerOffset);
    view.records = payload.subspan(kSyscallFixedBytes);
    return view;
}

// -- judgment payload ------------------------------------------------------
// [address u64][aux u64][subtype u32][api_len u8][api bytes]
// pc/tid/seq ride the common preamble. api is the "module!function"
// annotation when the fact resolves to a named export, empty otherwise.
inline constexpr std::size_t kJudgmentAddressOffset = 0;
inline constexpr std::size_t kJudgmentAuxOffset = kJudgmentAddressOffset + 8;
inline constexpr std::size_t kJudgmentSubtypeOffset = kJudgmentAuxOffset + 8;
inline constexpr std::size_t kJudgmentApiLenOffset = kJudgmentSubtypeOffset + 4;
inline constexpr std::size_t kJudgmentFixedBytes = kJudgmentApiLenOffset + 1; // 21
static_assert(kJudgmentFixedBytes == 21, "judgment fixed head must be 21 bytes");

struct JudgmentFields {
    std::uint64_t address{};
    std::uint64_t aux{};
    std::uint32_t subtype{};
    std::string_view api{}; // <=255 bytes, no NUL
};

inline std::expected<std::size_t, EventCodecError> encode_judgment(std::span<std::uint8_t> out,
                                                                   const JudgmentFields& fields)
{
    if (fields.api.size() > 255 || out.size() < kJudgmentFixedBytes + fields.api.size()) {
        return std::unexpected(EventCodecError::kOverflow);
    }
    le::store_le64(out.data() + kJudgmentAddressOffset, fields.address);
    le::store_le64(out.data() + kJudgmentAuxOffset, fields.aux);
    le::store_le32(out.data() + kJudgmentSubtypeOffset, fields.subtype);
    out[kJudgmentApiLenOffset] = static_cast<std::uint8_t>(fields.api.size());
    for (std::size_t i = 0; i < fields.api.size(); ++i) {
        out[kJudgmentFixedBytes + i] = static_cast<std::uint8_t>(fields.api[i]);
    }
    return kJudgmentFixedBytes + fields.api.size();
}

struct JudgmentView {
    JudgmentFields fields{}; // api views into the input span
};

inline std::expected<JudgmentView, EventCodecError>
read_judgment(const std::span<const std::uint8_t> payload)
{
    if (payload.size() < kJudgmentFixedBytes) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    JudgmentView view;
    const auto api_len = payload[kJudgmentApiLenOffset];
    if (payload.size() < kJudgmentFixedBytes + api_len) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    view.fields.address = le::load_le64(payload.data() + kJudgmentAddressOffset);
    view.fields.aux = le::load_le64(payload.data() + kJudgmentAuxOffset);
    view.fields.subtype = le::load_le32(payload.data() + kJudgmentSubtypeOffset);
    view.fields.api = std::string_view{
        reinterpret_cast<const char*>(payload.data() + kJudgmentFixedBytes), api_len};
    return view;
}

// -- forwarded fact payloads ----------------------------------------------
// mem-read / mem-write: [address u64][value u64][size u32][flags u8].
// mem-read carries the read value in value; mem-write has no captured value
// (0). The flags byte carries the writer attribution for mem-write: bit0 is
// set when the faulting writer is sample code (the sample image or a
// private-executable region). Other bits are reserved (0).
inline constexpr std::uint8_t kMemAccessFlagSampleWriter = 0x01;
inline constexpr std::size_t kMemAccessAddressOffset = 0;
inline constexpr std::size_t kMemAccessValueOffset = kMemAccessAddressOffset + 8;
inline constexpr std::size_t kMemAccessSizeOffset = kMemAccessValueOffset + 8;
inline constexpr std::size_t kMemAccessFlagsOffset = kMemAccessSizeOffset + 4;
inline constexpr std::size_t kMemAccessFixedBytes = kMemAccessFlagsOffset + 1; // 21
static_assert(kMemAccessFixedBytes == 21, "mem access payload must be 21 bytes");

struct MemAccessFields {
    std::uint64_t address{};
    std::uint64_t value{};
    std::uint32_t size{};
    std::uint8_t flags{};
};

inline std::expected<std::size_t, EventCodecError> encode_mem_access(std::span<std::uint8_t> out,
                                                                     const MemAccessFields& fields)
{
    if (out.size() < kMemAccessFixedBytes) {
        return std::unexpected(EventCodecError::kOverflow);
    }
    le::store_le64(out.data() + kMemAccessAddressOffset, fields.address);
    le::store_le64(out.data() + kMemAccessValueOffset, fields.value);
    le::store_le32(out.data() + kMemAccessSizeOffset, fields.size);
    out[kMemAccessFlagsOffset] = fields.flags;
    return kMemAccessFixedBytes;
}

inline std::expected<MemAccessFields, EventCodecError>
read_mem_access(const std::span<const std::uint8_t> payload)
{
    if (payload.size() < kMemAccessFixedBytes) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    return MemAccessFields{.address = le::load_le64(payload.data() + kMemAccessAddressOffset),
                           .value = le::load_le64(payload.data() + kMemAccessValueOffset),
                           .size = le::load_le32(payload.data() + kMemAccessSizeOffset),
                           .flags = payload[kMemAccessFlagsOffset]};
}

// sample-code: [length u8][bytes length] - the instruction bytes at pc.
inline constexpr std::size_t kSampleCodeLengthOffset = 0;
inline constexpr std::size_t kSampleCodeBytesOffset = kSampleCodeLengthOffset + 1;
inline constexpr std::size_t kSampleCodeMaxBytes = 15;

struct SampleCodeFields {
    std::uint8_t length{};
    std::span<const std::uint8_t> bytes{};
};

inline std::expected<std::size_t, EventCodecError>
encode_sample_code(std::span<std::uint8_t> out, const SampleCodeFields& fields)
{
    const std::size_t kept = std::min<std::size_t>(fields.length, fields.bytes.size());
    if (kept > kSampleCodeMaxBytes || out.size() < kSampleCodeBytesOffset + kept) {
        return std::unexpected(EventCodecError::kOverflow);
    }
    out[kSampleCodeLengthOffset] = static_cast<std::uint8_t>(kept);
    for (std::size_t i = 0; i < kept; ++i) {
        out[kSampleCodeBytesOffset + i] = fields.bytes[i];
    }
    return kSampleCodeBytesOffset + kept;
}

struct SampleCodeView {
    std::uint8_t length{};
    std::span<const std::uint8_t> bytes{};
};

inline std::expected<SampleCodeView, EventCodecError>
read_sample_code(const std::span<const std::uint8_t> payload)
{
    if (payload.empty()) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    const auto length = payload[kSampleCodeLengthOffset];
    if (length > kSampleCodeMaxBytes ||
        payload.size() < kSampleCodeBytesOffset + std::size_t{length}) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    return SampleCodeView{.length = length,
                          .bytes = payload.subspan(kSampleCodeBytesOffset, length)};
}

inline std::string_view event_codec_error_message(const EventCodecError error)
{
    switch (error) {
    case EventCodecError::kNone:
        return "ok";
    case EventCodecError::kOverflow:
        return "output span too small";
    case EventCodecError::kTruncated:
        return "event stream truncated or bad length";
    }
    return "unknown event codec error";
}

std::expected<std::size_t, EventCodecError>
encode_event(std::span<std::uint8_t> out, const EventTypeId type, const EventPreamble& preamble,
             const std::span<const std::uint8_t> type_fields)
{
    const std::size_t payload_size = kEventPreambleSize + type_fields.size();
    const std::size_t total = kEventHeaderSize + payload_size;
    if (out.size() < total) {
        return std::unexpected(EventCodecError::kOverflow);
    }
    le::store_le16(out.data() + kEventTypeOffset, static_cast<std::uint16_t>(type));
    le::store_le16(out.data() + kEventLengthOffset, static_cast<std::uint16_t>(payload_size));

    std::size_t cursor = kEventHeaderSize; // payload starts right after the header
    le::store_le64(out.data() + cursor, preamble.seq);
    cursor += sizeof(std::uint64_t);
    le::store_le32(out.data() + cursor, preamble.tid);
    cursor += sizeof(std::uint32_t);
    le::store_le64(out.data() + cursor, preamble.pc);
    cursor += sizeof(std::uint64_t);

    if (!type_fields.empty()) {
        for (std::size_t i = 0; i < type_fields.size(); ++i) {
            out[cursor + i] = type_fields[i];
        }
    }
    return total;
}

inline std::expected<EventView, EventCodecError> read_event(const std::span<const std::uint8_t> in)
{
    if (in.size() < kEventHeaderSize) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    const auto type_value = le::load_le16(in.data() + kEventTypeOffset);
    const auto payload_size = le::load_le16(in.data() + kEventLengthOffset);
    const std::size_t total = kEventHeaderSize + payload_size;
    if (in.size() < total) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    const EventView view{.type = static_cast<EventTypeId>(type_value),
                         .total_size = total,
                         .payload = in.subspan(kEventHeaderSize, payload_size)};
    return view;
}

inline std::expected<EventPreamble, EventCodecError>
read_preamble(const std::span<const std::uint8_t> payload)
{
    if (payload.size() < kEventPreambleSize) {
        return std::unexpected(EventCodecError::kTruncated);
    }
    EventPreamble preamble;
    preamble.seq = le::load_le64(payload.data());
    preamble.tid = le::load_le32(payload.data() + kEventPreambleTidOffset);
    preamble.pc = le::load_le64(payload.data() + kEventPreamblePcOffset);
    return preamble;
}

} // namespace sheller

#endif // SHELLER_EVENTS_H
