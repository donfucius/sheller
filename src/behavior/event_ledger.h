// Behavior event ledger: a fixed-capacity ring
// of raw behavior events plus the two deterministic outputs - TLV bytes via
// the guest-contract codec and hand-rolled JSON. Engine-agnostic by
// construction: the engine emits events through a sink callback and never
// links back here, so this module only knows the contract types. No wall
// clock anywhere: repeated runs of the same snapshot must produce
// byte-identical outputs.

#ifndef SHELLER_BEHAVIOR_EVENT_LEDGER_H
#define SHELLER_BEHAVIOR_EVENT_LEDGER_H

#include <sheller/events.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace sheller::behavior {

inline constexpr std::size_t kDefaultLedgerCapacity = 65536;
// Per-event cap for the type-specific fields: full-slot budget (256B), no
// name-escape second encoding. Largest known
// producers fit the budget equation - CRT-identity apicall 183B name +
// 20B fixed head ≈ 203B; CreateFileW-shaped worst case ≈ 128B capped path +
// 20B head + param records ≈ 248B. Anything longer is cut per parameter
// (kParamTruncatedBit) and counted.
inline constexpr std::size_t kMaxEventFields = 256;

enum class LedgerError {
    kNone = 0,
    kIoFailure,
    kEncodeFailure, // unreachable with the exact-size dump buffer; pins the invariant
};

std::string_view ledger_error_message(LedgerError error);

class EventLedger {
  public:
    explicit EventLedger(std::size_t capacity = kDefaultLedgerCapacity);

    // Copies one event into the ring. The caller owns the whole-run seq
    // (preamble.seq, assigned by the facade's stream cursor) - the ledger
    // never renumbers, so its entries and the report share one ordinal
    // space. A full ring drops the oldest event and bumps dropped().
    void record(EventTypeId type, const EventPreamble& preamble,
                std::span<const std::uint8_t> type_fields);

    // One ring entry, oldest first. type_fields views the ledger's storage
    // and stays valid until the next record call.
    struct Entry {
        EventTypeId type{};
        EventPreamble preamble{};
        std::span<const std::uint8_t> type_fields{};
    };

    std::size_t size() const;
    Entry entry(std::size_t index) const; // index < size()

    std::uint64_t dropped() const;   // events evicted by a full ring
    std::uint64_t truncated() const; // events cut by the slot cap or carrying
                                     // per-parameter truncation (flags bit2)
    // Cumulative record counts per known event type; counts survive ring
    // eviction (they answer "how much happened", not "what is kept").
    std::uint64_t count_of(EventTypeId type) const;

    // Stub-call side table: synthesized-stub export
    // calls report as (module, name) -> call count instead of per-call
    // events. Counts survive ring eviction; the map's strict order makes the
    // snapshot deterministic. The engine drains its run-end tally here.
    void record_stub_call(std::uint16_t module, std::string_view name, std::uint64_t count = 1);
    const std::map<std::pair<std::uint16_t, std::string>, std::uint64_t>& stub_counts() const;

    // Whole-ledger dumps, oldest to newest, aggregated in memory and written
    // in one shot so a failed write never leaves a half-populated file.
    // Return the byte count written.
    std::expected<std::size_t, LedgerError> write_tlv(const std::filesystem::path& path) const;
    std::expected<std::size_t, LedgerError> write_json(const std::filesystem::path& path) const;

  private:
    struct Slot {
        EventTypeId type{EventTypeId::kInvalid};
        EventPreamble preamble{};
        std::array<std::uint8_t, kMaxEventFields> fields{};
        std::uint16_t field_count{}; // u16: the 256B budget does not fit u8
    };

    std::vector<Slot> ring_; // sized once at construction, never reallocated
    std::size_t head_{};     // index of the oldest entry
    std::size_t size_{};
    std::uint64_t dropped_{};
    std::uint64_t truncated_{};
    std::map<std::pair<std::uint16_t, std::string>, std::uint64_t> stub_counts_{};
    std::array<std::uint64_t, kEventTypeCount>
        type_counts_{}; // fixed table: record() sits on the hook hot path and must not allocate
};

} // namespace sheller::behavior

#endif // SHELLER_BEHAVIOR_EVENT_LEDGER_H
