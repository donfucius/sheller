// C++ EH corpus, engine-dispatch entry: an ACCESS VIOLATION
// probe faults inside C++ code with live objects, so the engine synthesizes
// the dispatch and ITS walk opens __CxxFrameHandler4 frames - the C++ routing,
// the DISPATCHER_CONTEXT layout and the real handler execution are on this
// path. The real vcruntime machinery completes the unwind (handler4 drives
// RtlUnwindEx as guest code). /EHa: catch(...) accepts the hardware AV.
// Output "FEDBC" (faulter destructor, inner destructor, outer destructor,
// catch body, post-try), exit 0x5678.

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

__declspec(noinline) void faulter()
{
    Marker fault_frame("F");
    *(volatile int*)0 = 0x1234; // the write AV probe: the engine catches this
    thunk_write("MISSED", 6);   // must never run
}

int main()
{
    try {
        Marker outer("D");
        {
            Marker inner("E");
            faulter();
        }
    } catch (...) {
        // the exception was absorbed: the markers' destruction order proves
        // the unwind pass ran (inner first), the "B" marker proves the catch
        // body funclet itself executed, and the C marker after the try
        // proves the dispatch resumed instead of crashing
        thunk_write("B", 1);
    }
    thunk_write("C", 1);
    thunk_terminate(0x5678);
}
