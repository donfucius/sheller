// Alloc-jump corpus for the runtime-region classification: the
// unpacker's headline sequence as guest code - VirtualAlloc private data
// memory, write a payload, protect it executable, jump in. The payload
// reads TEB/PEB from inside the allocation (the engine's reader-fact
// guard must record it), flips its own page to a same-class executable
// protection (the xfer identity key must survive), and returns its
// marker. A second allocation repeats the jump under a fresh origin, and
// the MBI answers for the split allocation must match the carved map.
// Exit 0x3333 only when every step checked out. MSVC C + ml64 thunks,
// no CRT: /ENTRY:entry_main, kernel32 imports only.

#include <windows.h>

typedef unsigned long u32;

// The query bypasses kernel32: VirtualQueryEx hands NtQueryVirtualMemory
// an internal temp buffer and its copy-out path rewrote fields, so the
// corpus pins the Nt answer directly (the same answer the MBI seam writes).
__declspec(dllimport) LONG __stdcall NtQueryVirtualMemory(void* process_handle, void* base_address,
                                                          unsigned long information_class,
                                                          void* buffer, ULONG_PTR length,
                                                          ULONG_PTR* return_length);

extern void thunk_terminate(u32 code);

// Payload A, called at base+0x10: reads TEB/PEB through the segment
// bases (both pages sit in the behavior read windows, so the reader-fact
// guard sees a runtime-region pc), then re-protects its own page to
// PAGE_EXECUTE_READWRITE - the same private-exec class it runs under -
// and returns the marker with the protect BOOL in bit 28. The rip-relative
// displacements pin the buffer layout: the VirtualProtect pointer rides
// base+0x00, the payload derives its own base with a rip-relative lea.
static const unsigned char kPayloadA[] = {
    0x48, 0x83, 0xEC, 0x28,                               // sub rsp, 0x28
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00, // mov rax, gs:[60h]
    0x0F, 0xB7, 0x50, 0x02,                               // movzx edx, word [rax+2]
    0x48, 0x8D, 0x0D, 0xD8, 0xFF, 0xFF, 0xFF,             // lea rcx, [rip-28h] (own base)
    0xBA, 0x00, 0x10, 0x00, 0x00,                         // mov edx, 0x1000
    0x41, 0xB8, 0x40, 0x00, 0x00, 0x00,                   // mov r8d, 40h (RWX)
    0x4C, 0x8D, 0x4C, 0x24, 0x20,                         // lea r9, [rsp+20h]
    0x48, 0x8B, 0x05, 0xC1, 0xFF, 0xFF, 0xFF,             // mov rax, [rip-3Fh] (fn ptr)
    0xFF, 0xD0,                                           // call rax
    0x44, 0x89, 0xC0,                                     // mov r8d, eax (BOOL)
    0x41, 0xC1, 0xE0, 0x1C,                               // shl r8d, 28 (TRUE -> bit 28)
    0xB8, 0x11, 0x11, 0x11, 0x11,                         // mov eax, 11111111h
    0x09, 0xC0,                                           // or eax, r8d
    0x48, 0x83, 0xC4, 0x28,                               // add rsp, 0x28
    0xC3,                                                 // ret
};

// Payload B, called at base+0x00: the allocation-boundary twin.
static const unsigned char kPayloadB[] = {
    0xB8, 0x22, 0x22, 0x22, 0x22, // mov eax, 22222222h
    0xC3,                         // ret
};

void entry_main(void)
{
    // Two private data allocations: page 0 of the first carries the
    // payload, page 1 stays data, so the executable protect splits the
    // allocation into a carved record and an untouched tail.
    unsigned char* a = (unsigned char*)VirtualAlloc(NULL, 0x2000, MEM_COMMIT | MEM_RESERVE,
                                                    PAGE_READWRITE);
    if (a == NULL) {
        thunk_terminate(0xDEAD1);
    }
    *(void**)a = (void*)&VirtualProtect; // the payload's self-protect entry
    for (unsigned i = 0; i < sizeof kPayloadA; ++i) {
        a[0x10 + i] = kPayloadA[i];
    }
    DWORD old_protect = 0;
    if (!VirtualProtect(a, 0x1000, PAGE_EXECUTE_READ, &old_protect)) {
        thunk_terminate(0xDEAD2);
    }
    const u32 marker_a = ((u32(WINAPI*)(void))(a + 0x10))();
    if (marker_a != 0x11111111u) {
        // bit 28 carries the payload's self-protect BOOL result
        thunk_terminate(marker_a == 0x11111111u ? 0xDEA61 : 0xDEA62);
    }

    unsigned char* b = (unsigned char*)VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                                    PAGE_READWRITE);
    if (b == NULL) {
        thunk_terminate(0xDEAD4);
    }
    for (unsigned i = 0; i < sizeof kPayloadB; ++i) {
        b[i] = kPayloadB[i];
    }
    if (!VirtualProtect(b, 0x1000, PAGE_EXECUTE_READ, &old_protect)) {
        thunk_terminate(0xDEAD5);
    }
    if (((u32(WINAPI*)(void))b)() != 0x22222222u) {
        thunk_terminate(0xDEAD6);
    }

    // MBI answers must match the carved map: the protected page answers
    // the payload's same-class flip, the untouched page keeps the original
    // record (its extent answer is the original allocation, by contract).
    MEMORY_BASIC_INFORMATION mbi_protected;
    ULONG_PTR return_length = 0;
    if (NtQueryVirtualMemory((void*)(LONG_PTR)-1, a, 0, &mbi_protected, sizeof mbi_protected,
                             &return_length) != 0) {
        thunk_terminate(0xDEA70);
    }
    if (mbi_protected.State != MEM_COMMIT) {
        thunk_terminate(0xDEA71);
    }
    if (mbi_protected.Protect != PAGE_EXECUTE_READWRITE) {
        thunk_terminate(0xDEA72);
    }
    if (mbi_protected.Type != MEM_PRIVATE) {
        thunk_terminate(0xDEA73);
    }
    if (mbi_protected.RegionSize != 0x1000) {
        thunk_terminate(0xDEA74);
    }
    MEMORY_BASIC_INFORMATION mbi_data;
    if (NtQueryVirtualMemory((void*)(LONG_PTR)-1, a + 0x1000, 0, &mbi_data, sizeof mbi_data,
                             &return_length) != 0) {
        thunk_terminate(0xDEA80);
    }
    if (mbi_data.State != MEM_COMMIT) {
        thunk_terminate(0xDEA81);
    }
    if (mbi_data.Protect != PAGE_READWRITE) {
        thunk_terminate(0xDEA82);
    }
    if (mbi_data.Type != MEM_PRIVATE) {
        thunk_terminate(0xDEA83);
    }
    thunk_terminate(0x3333);
}
