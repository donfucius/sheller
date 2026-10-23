// Delay-then-cross-section sample: a counter loop with a guest-visible write
// (so the burn-loop probe neither fast-forwards it nor caches an exit), then
// the same .text -> text2 transfer as capture_xfer_sample. The unpack test
// sets a 1 ms wall clock: the write makes the probe admit the loop as compute
// and re-arm further out, so the delay spans several legs and the transfer
// ends the last one - past the clock crossing, and with no leg-boundary clock
// check in between (probe legs continue ahead of it). Only the xfer stop's
// veto of the finish-time recomputation can keep the dump (and the repair)
// alive. No CRT: direct syscall thunk only, custom entry.

#pragma section("text2", execute, read)

typedef unsigned long u32;

void thunk_terminate(u32 code);

volatile u32 g_delay_sink;

#pragma code_seg(push, "text2")
__declspec(noinline) void f2_xfer_entry(void)
{
    thunk_terminate(0x5678);
}
#pragma code_seg(pop)

void entry_main(void)
{
    for (u32 i = 0; i < 100000; ++i) {
        g_delay_sink = i;
    }
    f2_xfer_entry();
    thunk_terminate(0xDEADC0DE); // must never run
}
