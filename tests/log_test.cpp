// Log facade unit test: the public setter (merged set_sink(sink, level)),
// the level threshold, and the silence contract - a library with no sink
// installed (or an empty sink installed) must not deliver anything. The log
// state is the one deliberate process-global, so every test installs its own
// sink first and gtest runs the cases sequentially in this binary.

#include "log_detail.h"
#include <sheller/log.h>

#include <gtest/gtest.h>

#include <array>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

struct CapturedRecord {
    sheller::log::level level{};
    std::string message{};
};

using Capture = std::vector<CapturedRecord>;

Capture& capture()
{
    // Heap-anchored on purpose: the sink closures reference this container,
    // and a function-local static would be destroyed before the log state
    // (a write during static destruction would then push into a dead vector).
    static auto* const records = new Capture();
    return *records;
}

sheller::log::sink recording_sink()
{
    return [](const sheller::log::level level, const std::string_view message) {
        capture().push_back({level, std::string{message}});
    };
}

} // namespace

TEST(Log, InstalledSinkReceivesWrite)
{
    sheller::log::detail::set_sink_impl(recording_sink(), sheller::log::level::kDebug);
    capture().clear();

    sheller::log::write(sheller::log::level::kWarning, "reaches the sink");
    sheller::log::warning("via the wrapper");

    ASSERT_EQ(capture().size(), 2u);
    EXPECT_EQ(capture()[0].level, sheller::log::level::kWarning);
    EXPECT_EQ(capture()[0].message, "reaches the sink");
    EXPECT_EQ(capture()[1].level, sheller::log::level::kWarning);
    EXPECT_EQ(capture()[1].message, "via the wrapper");
}

TEST(Log, LevelThresholdFilters)
{
    sheller::log::detail::set_sink_impl(recording_sink(), sheller::log::level::kWarning);
    capture().clear();

    sheller::log::debug("below");
    sheller::log::info("below");
    sheller::log::warning("at the threshold");
    sheller::log::error("above");

    ASSERT_EQ(capture().size(), 2u);
    EXPECT_EQ(capture()[0].message, "at the threshold");
    EXPECT_EQ(capture()[1].level, sheller::log::level::kError);
}

TEST(Log, EmptySinkIsSilent)
{
    sheller::log::detail::set_sink_impl({}, sheller::log::level::kDebug);
    capture().clear();

    sheller::log::error("nowhere to go");

    EXPECT_TRUE(capture().empty());
}

TEST(Log, ReplacementSinkStopsReceiving)
{
    Capture first_capture;
    sheller::log::detail::set_sink_impl(
        [&first_capture](const sheller::log::level level, const std::string_view message) {
            first_capture.push_back({level, std::string{message}});
        },
        sheller::log::level::kDebug);
    sheller::log::detail::set_sink_impl(recording_sink(), sheller::log::level::kDebug);
    capture().clear();

    sheller::log::info("second sink only");

    EXPECT_TRUE(first_capture.empty());
    ASSERT_EQ(capture().size(), 1u);
    EXPECT_EQ(capture()[0].message, "second sink only");
}

TEST(Log, WouldLogAgreesWithWhatWriteDelivers)
{
    // The pre-check exists so a caller can skip building an expensive message
    // (the engine's run-start record does exactly that); it is only useful if it
    // never disagrees with write() about the same level.
    constexpr std::array levels{sheller::log::level::kDebug, sheller::log::level::kInfo,
                                sheller::log::level::kWarning, sheller::log::level::kError};

    // No sink: nothing is delivered, so nothing is promised - at any level.
    sheller::log::detail::set_sink_impl({}, sheller::log::level::kDebug);
    for (const auto sev : levels) {
        EXPECT_FALSE(sheller::log::would_log(sev)) << static_cast<int>(sev);
    }

    // Threshold at kWarning: the two levels below it are refused, the rest pass.
    sheller::log::detail::set_sink_impl(recording_sink(), sheller::log::level::kWarning);
    capture().clear();
    for (const auto sev : levels) {
        const auto before = capture().size();
        const bool promised = sheller::log::would_log(sev);
        sheller::log::write(sev, "probe");
        EXPECT_EQ(capture().size() > before, promised) << static_cast<int>(sev);
        const bool expect_pass =
            static_cast<int>(sev) >= static_cast<int>(sheller::log::level::kWarning);
        EXPECT_EQ(promised, expect_pass) << static_cast<int>(sev);
    }
    ASSERT_EQ(capture().size(), 2u);
}

TEST(Log, ConvenienceWrappersCarryTheirLevel)
{
    sheller::log::detail::set_sink_impl(recording_sink(), sheller::log::level::kDebug);
    capture().clear();

    sheller::log::debug("d");
    sheller::log::info("i");
    sheller::log::warning("w");
    sheller::log::error("e");

    ASSERT_EQ(capture().size(), 4u);
    EXPECT_EQ(capture()[0].level, sheller::log::level::kDebug);
    EXPECT_EQ(capture()[1].level, sheller::log::level::kInfo);
    EXPECT_EQ(capture()[2].level, sheller::log::level::kWarning);
    EXPECT_EQ(capture()[3].level, sheller::log::level::kError);
}

TEST(Log, ThrowingSinkDropsThatRecordAndNothingElse)
{
    // The callback contract says a sink must not throw. A host that breaks it
    // must not be able to end its own process through a diagnostic channel: the
    // record is dropped - not counted, not echoed anywhere, because the library
    // writes no host standard stream (tests/engine_stdstream_gate.cmake is what
    // keeps that a rule and not an intention).
    int entered = 0;
    sheller::log::detail::set_sink_impl(
        [&entered](const sheller::log::level, const std::string_view) {
            ++entered;
            throw std::runtime_error("the host's sink is broken");
        },
        sheller::log::level::kDebug);

    sheller::log::write(sheller::log::level::kWarning, "first");
    // The counter is what makes this a test of containment rather than of
    // silence: had the sink never been reached, nothing would have thrown and
    // the case would pass while proving nothing.
    EXPECT_EQ(entered, 1);
    sheller::log::write(sheller::log::level::kError, "second");
    EXPECT_EQ(entered, 2);
    // Threshold and installation state survived the throw - write() holds the
    // same lock the throwing callback was invoked under.
    EXPECT_TRUE(sheller::log::would_log(sheller::log::level::kDebug));

    // A recording sink installed afterwards still receives: nothing latched
    // inside the facade.
    capture().clear();
    sheller::log::detail::set_sink_impl(recording_sink(), sheller::log::level::kDebug);
    sheller::log::warning("after");
    ASSERT_EQ(capture().size(), 1u);
    EXPECT_EQ(capture()[0].message, "after");
}
