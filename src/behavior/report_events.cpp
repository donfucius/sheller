#include "report_events.h"

namespace sheller::behavior {

void EventTally::on_event(const EventTypeId type, const EventPreamble& preamble,
                          const std::span<const std::uint8_t> type_fields)
{
    static_cast<void>(preamble);
    static_cast<void>(type_fields);
    const auto type_index = static_cast<std::size_t>(type);
    if (type_index >= counts_.size()) {
        return; // outside the known id space: nothing to name, nothing to count
    }
    ++counts_[type_index];
}

void EventTally::add_count(const EventTypeId type, const std::uint64_t count)
{
    const auto type_index = static_cast<std::size_t>(type);
    if (type_index < counts_.size()) {
        counts_[type_index] += count;
    }
}

void EventTally::on_stub_call(const std::uint16_t module, const std::string_view name,
                              const std::uint64_t count)
{
    stub_counts_[{module, std::string{name}}] += count;
}

std::uint64_t EventTally::count_of(const EventTypeId type) const
{
    const auto index = static_cast<std::size_t>(type);
    return index < counts_.size() ? counts_[index] : 0;
}

const std::map<std::pair<std::uint16_t, std::string>, std::uint64_t>&
EventTally::stub_counts() const
{
    return stub_counts_;
}

} // namespace sheller::behavior
