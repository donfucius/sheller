#include "event_ledger.h"
#include <format>

#include <algorithm>
#include <fstream>
#include <string>

namespace sheller::behavior {
namespace {

// Lowercase 0x-prefixed hex without leading zeros (0 -> "0x0"): the one
// address spelling of the JSON render.
void append_hex(std::string& out, const std::uint64_t value)
{
    static constexpr char kDigits[] = "0123456789abcdef";
    out.push_back('0');
    out.push_back('x');
    auto started = false;
    for (auto shift = 60; shift >= 0; shift -= 4) {
        const auto nibble = (value >> shift) & 0xFu;
        if (nibble == 0 && !started && shift != 0) {
            continue;
        }
        out.push_back(kDigits[nibble]);
        started = true;
    }
}

// Appends the minimal payload field per type: block-exec's addr (u64 LE),
// syscall's num (u32 LE), exception's code (u32 LE). Events missing their
// payload bytes render preamble-only - a deterministic skip, never a
// malformed object.
void append_payload_fields(std::string& out, const EventLedger::Entry& entry)
{
    if (entry.type == EventTypeId::kBlockExec &&
        entry.type_fields.size() >= sizeof(std::uint64_t)) {
        out += ",\"addr\":\"";
        append_hex(out, le::load_le64(entry.type_fields.data()));
        out.push_back('"');
    } else if (entry.type == EventTypeId::kSyscall &&
               entry.type_fields.size() >= sizeof(std::uint32_t)) {
        out += ",\"num\":\"";
        append_hex(out, le::load_le32(entry.type_fields.data()));
        out.push_back('"');
    } else if (entry.type == EventTypeId::kException &&
               entry.type_fields.size() >= sizeof(std::uint32_t)) {
        out += ",\"code\":\"";
        append_hex(out, le::load_le32(entry.type_fields.data()));
        out.push_back('"');
    }
}

std::string render_json(const EventLedger& ledger)
{
    std::string out;
    out.push_back('[');
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        if (i != 0) {
            out.push_back(',');
        }
        const auto entry = ledger.entry(i);
        out += "{\"type\":\"";
        out += event_type_name(entry.type);
        out += "\",\"seq\":";
        out += std::to_string(entry.preamble.seq);
        out += ",\"tid\":";
        out += std::to_string(entry.preamble.tid);
        out += ",\"pc\":\"";
        append_hex(out, entry.preamble.pc);
        out.push_back('"');
        append_payload_fields(out, entry);
        out.push_back('}');
    }
    out.push_back(']');
    return out;
}

} // namespace

std::string_view ledger_error_message(const LedgerError error)
{
    switch (error) {
    case LedgerError::kNone:
        return "ok";
    case LedgerError::kIoFailure:
        return "ledger file could not be opened or written";
    case LedgerError::kEncodeFailure:
        return "event encoding failed";
    }
    return "unknown ledger error";
}

EventLedger::EventLedger(const std::size_t capacity)
    : ring_(std::max<std::size_t>(capacity, std::size_t{1})) // a zero-slot ring cannot modulo
{
}

void EventLedger::record(const EventTypeId type, const EventPreamble& preamble,
                         const std::span<const std::uint8_t> type_fields)
{
    const std::size_t capacity = ring_.size();
    Slot& slot = ring_[(head_ + size_) % capacity];

    slot.type = type;
    slot.preamble = preamble;

    if (type_fields.size() > kMaxEventFields) {
        ++truncated_;
    }
    const auto kept = static_cast<std::uint16_t>(std::min(type_fields.size(), kMaxEventFields));
    if (kept != 0) {
        std::copy_n(type_fields.data(), kept, slot.fields.begin());
    }
    slot.field_count = kept;

    // Third truncation layer: api-call payloads carry an event-level flag
    // (bit2) when any parameter record was cut at capture; count those here
    // so the ledger answers "how much was degraded" in one place. The flags
    // byte's position is fixed per type (syscall head is 4+1 fixed; apicall
    // rides 1 byte past the variable-length name + module).
    if (type == EventTypeId::kSyscall && type_fields.size() > 4 &&
        (type_fields[4] & kEventFlagTruncated) != 0) {
        ++truncated_;
    } else if (type == EventTypeId::kApiCall && type_fields.size() > 1) {
        const std::size_t name_len = type_fields[0];
        if (type_fields.size() > 1 + name_len + 2 &&
            (type_fields[1 + name_len + 2] & kEventFlagTruncated) != 0) {
            ++truncated_;
        }
    }

    if (size_ == capacity) {
        head_ = (head_ + 1) % capacity;
        ++dropped_;
    } else {
        ++size_;
    }

    const auto type_index = static_cast<std::size_t>(type);
    if (type_index < type_counts_.size()) {
        ++type_counts_[type_index];
    }
}

std::size_t EventLedger::size() const
{
    return size_;
}

EventLedger::Entry EventLedger::entry(const std::size_t index) const
{
    const Slot& slot = ring_[(head_ + index) % ring_.size()];
    return Entry{.type = slot.type,
                 .preamble = slot.preamble,
                 .type_fields = std::span(slot.fields.data(), slot.field_count)};
}

std::uint64_t EventLedger::dropped() const
{
    return dropped_;
}

std::uint64_t EventLedger::truncated() const
{
    return truncated_;
}

std::uint64_t EventLedger::count_of(const EventTypeId type) const
{
    const auto index = static_cast<std::size_t>(type);
    return index < type_counts_.size() ? type_counts_[index] : 0;
}

void EventLedger::record_stub_call(const std::uint16_t module, const std::string_view name,
                                   const std::uint64_t count)
{
    stub_counts_[{module, std::string{name}}] += count;
}

const std::map<std::pair<std::uint16_t, std::string>, std::uint64_t>&
EventLedger::stub_counts() const
{
    return stub_counts_;
}

std::expected<std::size_t, LedgerError>
EventLedger::write_tlv(const std::filesystem::path& path) const
{
    std::size_t total = 0;
    for (std::size_t i = 0; i < size_; ++i) {
        total += kEventHeaderSize + kEventPreambleSize + entry(i).type_fields.size();
    }

    std::vector<std::uint8_t> buffer(total);
    std::size_t cursor = 0;
    for (std::size_t i = 0; i < size_; ++i) {
        const auto item = entry(i);
        const auto written = encode_event(std::span(buffer).subspan(cursor), item.type,
                                          item.preamble, item.type_fields);
        if (!written.has_value()) {
            return std::unexpected(LedgerError::kEncodeFailure);
        }
        cursor += *written;
    }

    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return std::unexpected(LedgerError::kIoFailure);
    }
    out.write(reinterpret_cast<const char*>(buffer.data()),
              static_cast<std::streamsize>(buffer.size()));
    if (!out) {
        return std::unexpected(LedgerError::kIoFailure);
    }
    return buffer.size();
}

std::expected<std::size_t, LedgerError>
EventLedger::write_json(const std::filesystem::path& path) const
{
    const auto rendered = render_json(*this);
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        return std::unexpected(LedgerError::kIoFailure);
    }
    out.write(rendered.data(), static_cast<std::streamsize>(rendered.size()));
    if (!out) {
        return std::unexpected(LedgerError::kIoFailure);
    }
    return rendered.size();
}

} // namespace sheller::behavior
