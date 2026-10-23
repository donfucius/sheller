// Unknown-image attribution corpus: a hand-mapped image the Ldr list never
// enumerates, crafted into the captured snapshot by the test as contiguous
// MEM_IMAGE regions at the fixed base below. The sample calls into the
// image (the synthesized module's .text), crosses the section boundary
// into text2 (one event) and the same-section hop (silent), checks the
// MBI/MII answers its pages give (region semantics for MBI, the
// synthesized module extent for MII where the class is answered at all),
// then faults inside the image - the dispatch must stay the pre-synthesis
// non-module shape (unhandled crash) in both dispatch modes. The test also
// crafts the same snapshot with MEM_PRIVATE payload regions (no synthesis
// possible) so the fidelity-mode dispatch outcome can be compared against
// the pre-synthesis world. Every guest-side check dies with a distinct
// 0xDEADn code, so the expected run outcome is only ever the unhandled
// crash. MSVC C + ml64 thunks, no CRT: /ENTRY:entry_main, kernel32 imports.

#include <windows.h>

typedef unsigned long u32;

// The query bypasses kernel32 (see allocjump corpus): the engine's answer
// is pinned directly.
__declspec(dllimport) LONG __stdcall NtQueryVirtualMemory(void* process_handle, void* base_address,
                                                          unsigned long information_class,
                                                          void* buffer, ULONG_PTR length,
                                                          ULONG_PTR* return_length);

extern void thunk_terminate(u32 code);

// The crafted image's fixed identity; the test writes the regions here.
// Layout: headers page (RO), the .text page (RX, the section exactly
// covering it) and the text2 page (RWX) carrying the return marker, the
// same-section silent hop and the faulting leg at +0x800.
static unsigned char* const kImageBase = (unsigned char*)0x7F5000000000ULL;

void entry_main(void)
{
    // One kernel32 call: the cross-module xfer whose render must spell the
    // absolute first-section name after the wire-grid fix.
    void* scratch = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (scratch == NULL) {
        thunk_terminate(0xDEAD1);
    }

    // MBI for a synthesized .text page answers the module-base region's
    // facts - region semantics, not the module extent, not the fragment.
    // The checks gate on MEM_IMAGE: the test also crafts the same bytes as
    // MEM_PRIVATE regions (the pre-synthesis world) for the fidelity-mode
    // comparison, and the private world answers the fragment region.
    MEMORY_BASIC_INFORMATION mbi;
    ULONG_PTR return_length = 0;
    if (NtQueryVirtualMemory((void*)(LONG_PTR)-1, kImageBase + 0x1500, 0, &mbi, sizeof mbi,
                             &return_length) != 0) {
        thunk_terminate(0xDEAD2);
    }
    if (mbi.Type == MEM_IMAGE) {
        if (mbi.BaseAddress != (void*)kImageBase || mbi.RegionSize != 0x1000) {
            thunk_terminate(0xDEAD4);
        }
        if (mbi.Protect != PAGE_READONLY) {
            thunk_terminate(0xDEAD5);
        }
        // MII answers the synthesized module extent where the class is
        // answered at all (the engine mode rejects it; the fidelity seam
        // answers it for the real ntdll's exception-table lookup).
        struct {
            void* image_base;
            ULONG_PTR size_of_image;
        } mii;
        if (NtQueryVirtualMemory((void*)(LONG_PTR)-1, kImageBase + 0x1500, 6, &mii, sizeof mii,
                                 &return_length) == 0) {
            if (mii.image_base != (void*)kImageBase || mii.size_of_image != 0x3000) {
                thunk_terminate(0xDEAD6);
            }
        }
    }

    // Leg 1: into .text, across the section boundary into text2 (one
    // event), through the same-section hop (silent) and back.
    const u32 marker = ((u32(WINAPI*)(void))(kImageBase + 0x1000))();
    if (marker != 0x33333333u) {
        thunk_terminate(0xDEAD7);
    }

    // Leg 2: the fault inside the synthesized image. The image carries no
    // exception directory, so both dispatch modes must resolve it the
    // pre-synthesis way: a non-module frame, unhandled.
    ((void(WINAPI*)(void))(kImageBase + 0x2800))();
    thunk_terminate(0xDEAD9); // must never run
}
