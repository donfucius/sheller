// Behavior report event accounting: exact whole-run per-type counts plus
// the stub-call side table. The collector rides the facade-owned
// event_sink/stub_sink seams; counts accumulate for the whole run (no ring,
// no eviction). The per-class detail lists live in the analysis facade's
// semantic events - the CLI render layer formats them from the public
// artifacts.

#ifndef SHELLER_BEHAVIOR_REPORT_EVENTS_H
#define SHELLER_BEHAVIOR_REPORT_EVENTS_H

#include <sheller/events.h>

#include <array>
#include <cstdint>
#include <map>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace sheller::behavior {

// Exact event accounting for the report: counts accumulate for the whole
// run. Malformed payloads count (the deterministic skip - never a fabricated
// item).
class EventTally {
  public:
    void on_event(EventTypeId type, const EventPreamble& preamble,
                  std::span<const std::uint8_t> type_fields);
    // Direct count for a fact whose event was not delivered (no ledger and no
    // observer selection): the counts header stays exact without paying the
    // per-event delivery path.
    void add_count(EventTypeId type, std::uint64_t count);
    // Same shape as the ledger's stub side table; the engine drains its
    // run-end tally here. Map order keeps the snapshot deterministic.
    void on_stub_call(std::uint16_t module, std::string_view name, std::uint64_t count = 1);

    std::uint64_t count_of(EventTypeId type) const;
    const std::map<std::pair<std::uint16_t, std::string>, std::uint64_t>& stub_counts() const;

  private:
    std::array<std::uint64_t, kEventTypeCount> counts_{};
    std::map<std::pair<std::uint16_t, std::string>, std::uint64_t> stub_counts_{};
};

} // namespace sheller::behavior

#endif // SHELLER_BEHAVIOR_REPORT_EVENTS_H
