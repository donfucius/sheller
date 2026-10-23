// Synthetic capture sample: a real compiler-built Windows PE with a TLS
// callback that would set the marker byte at process attach. The capture path
// zeroes the TLS callback array before the loader runs, so the marker must
// still read 0 inside the snapshot while the loader-built TLS structures
// exist. main never runs: the capture path patches the entry into a spin
// before the loader even starts.

#include <windows.h>

__declspec(dllexport) volatile unsigned char g_marker = 0;

void NTAPI tls_callback(PVOID handle, DWORD reason, PVOID reserved)
{
    (void)handle;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        g_marker = 1;
    }
}

#pragma section(".CRT$XLB", long, read)
__declspec(allocate(".CRT$XLB")) const PIMAGE_TLS_CALLBACK g_tls_callbacks[] = {tls_callback, NULL};

// Keeps the linker's TLS directory template alive so .CRT$XLB is collected.
#pragma comment(linker, "/INCLUDE:_tls_used")

int main(void) { return 0; }
