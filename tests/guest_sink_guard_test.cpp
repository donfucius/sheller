// The engine's guard at its guest-output delivery point.
//
// syscalls::WriteSink's function pointer is engine::sink_trampoline, built in
// exactly one place (src/engine/syscall_dispatch.cpp:33), and the trampoline is
// the frame that calls the host's std::function. That makes it the only first-party
// frame between a guest NtWriteFile and host code, so it is where a host callback
// that breaks the "must not throw" contract has to be contained - the alternative
// is unwinding into unicorn's syscall helper, a C frame with no unwind info, which
// on POSIX is std::terminate rather than an unwind - the frames above it belong to
// unicorn, which has no unwind info to give back, so the export layer cannot be the
// safety net on this path.
//
// These cases call the trampoline directly, which is what makes them portable: the
// containment is a property of this frame, not of the capture route that would
// otherwise be needed to reach it with a real guest. The end-to-end property - a
// guest that writes several times, an event stream that does not notice the throw -
// is asserted in syscall_e2e_test.cpp over the multi-write sample, where the
// Windows capture route exists to produce one.
//
// Everything that throws here throws from the test, which is host-side code and
// keeps exceptions; the engine translation unit under test contains no exception
// mechanism of its own beyond its one handler (tests/engine_nothrow_gate.cmake
// allowlists exactly its try and its catch, and nothing else in it).

#include "rebuild_state.h"
#include "syscall_policy.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using sheller::engine::sink_trampoline;

std::string as_text(const std::uint8_t* data, const std::size_t size)
{
    return std::string(data, data + size);
}

// A sink that records what it was handed and throws on the call numbered
// throw_on - throwing *before* recording, which is what a broken host does: it
// never gets its bytes into whatever it was forwarding them to. The throw counter
// is the part that makes the rest of the assertions mean something: without it, a
// case where the callback was never reached would look exactly like a case where
// it was reached, threw, and was contained.
struct ThrowingSink {
    std::vector<std::string> received;
    int entered = 0;
    int thrown = 0;
    int throw_on = 0; // 0 = never; otherwise the Nth delivery throws

    void operator()(const std::uint8_t* data, const std::size_t size)
    {
        ++entered;
        if (entered == throw_on) {
            ++thrown;
            throw std::runtime_error("the host's write sink is broken");
        }
        received.push_back(as_text(data, size));
    }
};

void deliver(std::function<void(const std::uint8_t*, std::size_t)>& target, const char* text)
{
    const std::string bytes{text};
    sink_trampoline(&target, reinterpret_cast<const std::uint8_t*>(bytes.data()), bytes.size());
}

} // namespace

TEST(GuestSinkGuard, ThrowingSinkLosesOnlyTheCallThatThrew)
{
    ThrowingSink host;
    host.throw_on = 2;
    std::function<void(const std::uint8_t*, std::size_t)> sink{std::ref(host)};

    // The call that throws must not propagate out of the trampoline. If it did,
    // this line is where the test dies instead of asserting anything.
    deliver(sink, "one");
    deliver(sink, "two");
    deliver(sink, "three");

    EXPECT_EQ(host.entered, 3) << "reached three times to be contained three times";
    EXPECT_EQ(host.thrown, 1) << "the middle call has to actually have thrown";
    // The throwing call's bytes are the only ones lost, and the calls after it
    // still arrive at the same sink in the order the guest wrote them.
    EXPECT_EQ(host.received, (std::vector<std::string>{"one", "three"}));
}

TEST(GuestSinkGuard, TheHandlerIsCatchAllNotATypedCatch)
{
    // A host that throws something outside std::exception - another library's
    // type, or a bare integer - is the case that a typed catch would miss, and
    // the whole reason the contract says "must not throw" rather than "must not
    // throw std::exception".
    int calls = 0;
    std::function<void(const std::uint8_t*, std::size_t)> sink{
        [&calls](const std::uint8_t*, const std::size_t) {
            ++calls;
            if (calls == 1) {
                throw 42; // NOLINT: the point of the case is a non-std throw
            }
            if (calls == 2) {
                throw "a string literal";
            }
        }};

    deliver(sink, "one");
    deliver(sink, "two");
    deliver(sink, "three");

    EXPECT_EQ(calls, 3);
}

TEST(GuestSinkGuard, EmptySinkIsDisabledWithoutTheHandlerBeingAsked)
{
    // "Empty means disabled" is the SyscallRunOptions rule for every optional
    // callback, and the trampoline implements it with a test the handler does not
    // enclose. What this case can prove is the outcome the host sees: an empty
    // sink neither stops the run nor latches anything, because the same target
    // delivers the moment it holds a callable. What it cannot prove is where the
    // emptiness test sits - calling an empty std::function raises
    // std::bad_function_call, which this handler would swallow, so "checked" and
    // "called and caught" are not distinguishable from out here. The placement
    // that design asks for is a structural claim, and the two checks that hold it
    // are the construction-site grep (one site, so there is one frame to read) and
    // the gate's allowlist - not a test that cannot tell the two spellings apart.
    std::function<void(const std::uint8_t*, std::size_t)> sink;

    deliver(sink, "ignored");

    int reached = 0;
    sink = [&reached](const std::uint8_t*, const std::size_t) { ++reached; };
    deliver(sink, "seen");
    EXPECT_EQ(reached, 1) << "the trampoline still delivers after an empty stretch";
}

TEST(GuestSinkGuard, TheSinkStructForwardsWithoutAddingASecondGuard)
{
    // WriteSink::write_bytes only checks the function pointer and forwards; the
    // containment is in the trampoline. Wiring them the way syscall_dispatch.cpp
    // does and driving it through the POD struct is what shows there is exactly
    // one handler on this path, not one per layer.
    ThrowingSink host;
    host.throw_on = 1;
    std::function<void(const std::uint8_t*, std::size_t)> sink{std::ref(host)};
    const sheller::syscalls::WriteSink write_sink{&sink, &sink_trampoline};

    const std::string text{"every"};
    write_sink.write_bytes(reinterpret_cast<const std::uint8_t*>(text.data()), text.size());

    EXPECT_EQ(host.entered, 1);
    EXPECT_EQ(host.thrown, 1) << "the throw has to come back through the struct's forwarder";
    EXPECT_TRUE(host.received.empty()) << "and the one write it came through is the one lost";
}
