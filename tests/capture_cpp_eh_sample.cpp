// C++ EH corpus for the engine-side dispatcher: MSVC C++
// on purpose - the throw chain (__CxxThrowException -> RaiseException ->
// RtlRaiseException -> NtRaiseException) and the frame handlers
// (__CxxFrameHandler4 in vcruntime140_1) must run as real guest code against
// the engine dispatch. The destructor markers make the unwind second pass
// observable: the inner marker dies before the outer one, both before the
// catch body. Output "EDC", exit 0x5678.

#include <windows.h>

typedef unsigned long u32;

extern "C" {
void thunk_write(const char* buffer, u32 length);
void thunk_terminate(u32 code);
}

struct Marker {
    const char* tag;
    explicit Marker(const char* t) : tag(t)
    {
    }
    Marker(const Marker&) = delete;
    Marker& operator=(const Marker&) = delete;
    ~Marker();
};

__declspec(noinline) Marker::~Marker()
{
    thunk_write(tag, 1);
}

__declspec(noinline) void thrower()
{
    throw 0x1234; // the exception object rides the stack, no heap needed
}

int main()
{
    try {
        Marker outer("D");
        {
            Marker inner("E");
            thrower();
        }
    } catch (int value) {
        // the catch funclet reads the exception object: wrong value means the
        // handoff between the throw record and the funclet diverged
        thunk_write(value == 0x1234 ? "C" : "X", 1);
    }
    thunk_terminate(0x5678);
}
