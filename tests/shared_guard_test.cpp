// Unit tests for the export layer's containment helper (src/shared/guard.h).
// Header-only and free of engine and unicorn types, so this TU is also the
// "compiles standalone" check the header's own contract claims. Portable: the
// same file runs on both platforms.
//
// The behaviors pinned here are the ones the six exported entries rely on: a
// fixed ASCII prefix, a detail that is either the exception's own words or a
// constant, control bytes and non-ASCII neutralized, an unbounded what() cut
// short, and one template that carries a value-returning body, a void body and
// a string_view body without specialization.

#include "../src/shared/guard.h"

#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>

#include <gtest/gtest.h>

namespace {

using sheller::shared::detail::contained;
using sheller::shared::detail::guard;
using sheller::shared::detail::internal_error_message;
using sheller::shared::detail::kInternalErrorDetailLimit;
using sheller::shared::detail::kInternalErrorPrefix;

// The marker as it reaches a host: prefix, one space, then the detail. Spelled
// out once here so a change to the guard's rendering shows up as a compile error
// rather than as a message the assertions happen to accept.
const std::string kMarker = std::string{kInternalErrorPrefix} + " ";

TEST(SharedGuardMessage, CarriesTheFixedPrefix)
{
    const std::string message = internal_error_message(std::runtime_error("boom"));
    EXPECT_EQ(message.rfind(kInternalErrorPrefix, 0), 0U) << message;
    EXPECT_NE(message.find("boom"), std::string::npos) << message;
}

TEST(SharedGuardMessage, DistinguishesNoDetailFromEmptyWhat)
{
    // The bare form and an exception whose what() came back empty both land on
    // the same constant text: the host sees "nothing translatable", not a
    // message that merely looks truncated.
    const std::string bare = internal_error_message();
    EXPECT_EQ(bare, kMarker + "uncaught exception without a description");
    struct quiet_error final : std::exception {
        [[nodiscard]] const char* what() const noexcept override
        {
            return "";
        }
    };
    EXPECT_EQ(internal_error_message(quiet_error{}), bare);
}

TEST(SharedGuardMessage, PrefixAloneNeedsNoAllocation)
{
    // The fallback path in contained() hands out the prefix alone, which only
    // stays allocation-free while the prefix fits the small-string buffer. This
    // is the assertion that keeps that promise honest: growing the marker past
    // the buffer would make the "heap exhausted" path allocate - the failure the
    // fallback exists to avoid.
    EXPECT_LE(kInternalErrorPrefix.size(), 15U)
        << "kInternalErrorPrefix outgrew the small-string buffer; the contained() fallback "
           "would allocate on an exhausted heap";
    const auto carried = contained([](std::string message) { return message; },
                                   []() -> std::string { throw std::bad_alloc(); });
    EXPECT_EQ(carried, std::string{kInternalErrorPrefix});
}

TEST(SharedGuardMessage, NeutralizesControlBytesAndNonAscii)
{
    // A diagnostic that crosses a library boundary must not smuggle control
    // codes or bytes with no defined encoding. Printable ASCII and newline
    // survive; everything else becomes '?'. The odd bytes go through
    // push_back: a constant cast straight into char trips MSVC's C4310.
    std::string mixed = "ok";
    mixed.push_back('\x01');
    mixed.push_back('\x7F');
    mixed += " end\nnext";
    EXPECT_EQ(internal_error_message(std::runtime_error(mixed)), kMarker + "ok?? end\nnext");

    std::string high = "a";
    high.push_back('\xC3');
    high.push_back('\xA9');
    high += "b";
    EXPECT_EQ(internal_error_message(std::runtime_error(high)), kMarker + "a??b");

    // Locale independence in one line: the same input renders identically no
    // matter what the host's C locale is, because nothing here formats numbers
    // or dates.
    EXPECT_EQ(internal_error_message(std::runtime_error("1,000")), kMarker + "1,000");
}

TEST(SharedGuardMessage, BoundsTheDetail)
{
    const std::string long_text(static_cast<std::size_t>(kInternalErrorDetailLimit) + 400, 'x');
    const std::string message = internal_error_message(std::runtime_error(long_text));
    EXPECT_NE(message.find("...[truncated]"), std::string::npos) << "the cut has to be visible";
    EXPECT_EQ(message, kMarker + std::string(kInternalErrorDetailLimit, 'x') + "...[truncated]");

    // Exactly at the limit there is no truncation marker.
    const std::string at_limit(kInternalErrorDetailLimit, 'y');
    EXPECT_EQ(internal_error_message(std::runtime_error(at_limit)), kMarker + at_limit);
}

TEST(SharedGuardCall, ReturnsTheBodyValueWhenNothingThrows)
{
    int side_effect = 0;
    const auto result = guard(
        [&] {
            side_effect = 1;
            return 42;
        },
        [](std::string) { return -1; });
    EXPECT_EQ(result, 42);
    EXPECT_EQ(side_effect, 1);
}

TEST(SharedGuardCall, MapsAStdExceptionThroughTheStrategy)
{
    const auto result =
        guard([]() -> std::string { throw std::runtime_error("no memory for the ledger"); },
              [](std::string message) { return message; });
    EXPECT_EQ(result, kMarker + "no memory for the ledger");
}

TEST(SharedGuardCall, MapsAForeignThrowWithoutLosingTheShape)
{
    // Not derived from std::exception: still contained, still mapped, with the
    // constant text rather than a guess at what was thrown. The body declares
    // its return type - a lambda whose only statement is a throw would deduce
    // void, and void is exactly the shape this case is not about.
    const auto result =
        guard([]() -> std::string { throw 7; }, [](std::string message) { return message; });
    EXPECT_EQ(result, internal_error_message());
}

TEST(SharedGuardCall, CarriesAVoidBody)
{
    int calls = 0;
    guard([&] { ++calls; }, [](std::string) {});
    EXPECT_EQ(calls, 1);

    calls = 0;
    guard(
        [&] {
            ++calls;
            throw std::bad_alloc();
        },
        [&calls](std::string) { calls = 100; });
    EXPECT_EQ(calls, 100) << "the body ran and the strategy ran; nothing escaped";
}

TEST(SharedGuardCall, CarriesAStringViewBody)
{
    // The version-string entry's shape: an empty view on containment, and the
    // body's own view handed back untouched on success.
    const std::string held = "2.1";
    const auto ok = guard([&] { return std::string_view{held}; },
                          [](std::string) -> std::string_view { return {}; });
    EXPECT_EQ(ok, "2.1");
    const auto failed = guard([]() -> std::string_view { throw std::bad_alloc(); },
                              [](std::string) -> std::string_view { return {}; });
    EXPECT_TRUE(failed.empty());
}

TEST(SharedGuardCall, MessageIsNotAddressBearing)
{
    // Two contained throws of the same kind render the same text: nothing here
    // appends a per-run address, which would make the message unreadable as a
    // diff and useless as a stable marker.
    const auto first = guard([]() -> std::string { throw std::bad_alloc(); },
                             [](std::string message) { return message; });
    const auto second = guard([]() -> std::string { throw std::bad_alloc(); },
                              [](std::string message) { return message; });
    EXPECT_EQ(first, second);
    EXPECT_EQ(first.rfind(kInternalErrorPrefix, 0), 0U) << first;
}

} // namespace
