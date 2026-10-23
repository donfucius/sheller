// Engine diagnostic helper tests (src/engine/diag_trace.h): the two conditions that
// gate a record, measured where the claim actually lives. "The default path allocates
// nothing" is a statement about std::format never running, so the ruler is a formatter
// that counts its own invocations - a sink that received no records would also be
// satisfied by a broken sink, and would not tell a skipped render from a skipped
// delivery. Every case therefore carries a positive control that does render.

#include "diag_trace.h"
#include "log_detail.h"
#include <sheller/log.h>

#include <gtest/gtest.h>

#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace diag = sheller::engine::diag;

struct counted {
    // A process-wide counter, reached through a static: the point is to count
    // invocations of the one formatter below, from anywhere in the file.
    static int& renders()
    {
        static int value = 0;
        return value;
    }
};

std::vector<std::string>& records()
{
    // Heap-anchored, as in log_test.cpp: the sink closures reference this container
    // and the log state outlives the test body, so a function-local static would be
    // a use-after-destruction waiting to happen.
    static auto* const held = new std::vector<std::string>();
    return *held;
}

void install(const sheller::log::level threshold)
{
    sheller::log::detail::set_sink_impl(
        [](const sheller::log::level, const std::string_view message) {
            records().emplace_back(message);
        },
        threshold);
    records().clear();
    counted::renders() = 0;
}

} // namespace

template <> struct std::formatter<counted> : std::formatter<std::string_view> {
    auto format(const counted& value, std::format_context& ctx) const
    {
        (void)value; // the argument is only a render trigger
        ++counted::renders();
        return std::formatter<std::string_view>::format("rendered", ctx);
    }
};

namespace {

TEST(EngineDiag, DisabledSiteRendersNothing)
{
    // The host's threshold would take the record; the site switch is what is off.
    install(sheller::log::level::kDebug);
    EXPECT_TRUE(sheller::log::would_log(sheller::log::level::kDebug));
    diag::emit(sheller::log::level::kDebug, false, "{} and {}", counted{}, counted{});
    EXPECT_TRUE(records().empty());
    EXPECT_EQ(counted::renders(), 0);
    // The assembled-line overload is gated the same way.
    diag::emit(sheller::log::level::kDebug, false, std::string_view{"assembled"});
    EXPECT_TRUE(records().empty());
    // Positive control: with only the switch flipped, both arguments render and the
    // record is delivered, so the two zeros above are a skipped render, not a dead
    // sink or a counter nobody touches.
    diag::emit(sheller::log::level::kDebug, true, "{} and {}", counted{}, counted{});
    EXPECT_EQ(records().size(), 1U);
    EXPECT_EQ(records().front(), "rendered and rendered");
    EXPECT_EQ(counted::renders(), 2);
}

TEST(EngineDiag, SiteOnAboveThresholdRendersNothing)
{
    // The opposite half: the site is switched on, the host's threshold is above it.
    install(sheller::log::level::kWarning);
    EXPECT_FALSE(sheller::log::would_log(sheller::log::level::kDebug));
    diag::emit(sheller::log::level::kDebug, true, "{}", counted{});
    EXPECT_TRUE(records().empty());
    EXPECT_EQ(counted::renders(), 0);
    diag::emit(sheller::log::level::kDebug, true, std::string_view{"assembled"});
    EXPECT_TRUE(records().empty());
    // Same site, a level the threshold takes: rendered and delivered.
    diag::emit(sheller::log::level::kWarning, true, "{}", counted{});
    ASSERT_EQ(records().size(), 1U);
    EXPECT_EQ(records().front(), "rendered");
    EXPECT_EQ(counted::renders(), 1);
}

TEST(EngineDiag, SwitchesReadTheEnvironmentAndAreOffInThisProcess)
{
    // No env is set in this binary by design - the cases that need a switch on run in
    // tests/engine_trace_test.cpp, which sets its variables before RUN_ALL_TESTS
    // because a function-local static cannot be re-read. What is pinned here is the
    // half that a normal run pays: switch off, so a site that passes its own cached
    // flag produces no record and no render.
    // Failing here means this process started with one of the three names already in its
    // environment - a host, or a CI job, that set it for its own reasons. Objecting is
    // correct (the switch names are surface an embedder can reach, and this case measures
    // the switch-off path), but it is not a library fault, so the message says which
    // world it saw instead of pointing at the code under test.
    const auto ambient = [] {
        std::string found{};
        if (diag::seh_on()) {
            found += "SHELLER_SEH_TRACE ";
        }
        if (diag::loop_gate_on()) {
            found += "SHELLER_LOOP_GATE_TRACE ";
        }
        if (diag::file_on()) {
            found += "SHELLER_FILE_TRACE ";
        }
        return found;
    };
    EXPECT_FALSE(diag::seh_on()) << "the switch-off path needs no site variable set; found: ["
                                 << ambient() << "]";
    EXPECT_FALSE(diag::loop_gate_on())
        << "the switch-off path needs no site variable set; found: [" << ambient() << "]";
    EXPECT_FALSE(diag::file_on()) << "the switch-off path needs no site variable set; found: ["
                                  << ambient() << "]";
    install(sheller::log::level::kDebug);
    diag::emit(sheller::log::level::kDebug, diag::seh_on(), "{}", counted{});
    diag::emit(sheller::log::level::kDebug, diag::file_on(), "{}", counted{});
    diag::emit(sheller::log::level::kDebug, diag::loop_gate_on(), "{}", counted{});
    EXPECT_TRUE(records().empty());
    EXPECT_EQ(counted::renders(), 0);
    EXPECT_FALSE(diag::wanted(sheller::log::level::kDebug, diag::seh_on()));
    EXPECT_TRUE(diag::wanted(sheller::log::level::kDebug, true));
}

TEST(EngineDiag, RecordsCarryTheSiteMarkerTheHostFiltersOn)
{
    // The trace prefix is what makes a record attributable once it reaches a sink that
    // mixes it with everything else the library says, so it survives the routing: the
    // call sites keep spelling it, and it arrives verbatim.
    install(sheller::log::level::kDebug);
    diag::emit(sheller::log::level::kDebug, true, "[seh-step] layers={}", 3);
    ASSERT_EQ(records().size(), 1U);
    EXPECT_EQ(records().front(), "[seh-step] layers=3");
}

} // namespace
