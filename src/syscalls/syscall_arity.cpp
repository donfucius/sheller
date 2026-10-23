#include "syscall_arity.h"

#include <algorithm>
#include <array>
#include <cstring>

namespace sheller::syscalls {
namespace {

struct ArityRow {
    std::string_view name;
    std::uint32_t count;
};

constexpr ArityRow kArityTable[] = {
#include "syscall_arity_seed.inc"
};

constexpr auto kAritySorted = [] {
    std::array<ArityRow, std::size(kArityTable)> sorted{};
    for (std::size_t i = 0; i < sorted.size(); ++i) {
        sorted[i] = kArityTable[i];
    }
    std::sort(sorted.begin(), sorted.end(),
              [](const ArityRow& a, const ArityRow& b) { return a.name < b.name; });
    return sorted;
}();

} // namespace

std::optional<std::uint32_t> nt_arg_count(const std::string_view name)
{
    const auto it = std::lower_bound(
        kAritySorted.begin(), kAritySorted.end(), name,
        [](const ArityRow& row, const std::string_view key) { return row.name < key; });
    if (it == kAritySorted.end() || it->name != name) {
        return std::nullopt;
    }
    return it->count;
}

} // namespace sheller::syscalls
