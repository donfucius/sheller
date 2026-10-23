// Cross-section transfer sample: entry_main lives in the default
// .text and calls a function placed in an explicitly declared second
// executable section - the call across sections is what the xfer event
// observes. MSVC C on purpose: ml64 custom segments came out as unnamed
// zero-VA sections, and the compiler emits the section plus its unwind
// entries correctly. No CRT: direct syscall thunk only, custom entry.

#pragma section("text2", execute, read)

typedef unsigned long u32;

void thunk_terminate(u32 code);

#pragma code_seg(push, "text2")
__declspec(noinline) void f2_xfer_entry(void)
{
    // Terminating from inside text2 keeps the transfer count deterministic:
    // exactly one cross-section call, no return leg.
    thunk_terminate(0x5678);
}
#pragma code_seg(pop)

void entry_main(void)
{
    f2_xfer_entry();
    thunk_terminate(0xDEADC0DE); // must never run
}
