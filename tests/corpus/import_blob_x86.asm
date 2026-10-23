; x86 import blob: calls VirtualAlloc via the IAT (stdcall, args on
; the stack), proves the page is writable, then ExitProcess(1122h).
; NASM owns every displacement and table offset - no hand-computed jumps.
; Layout contract with the test: the import descriptor block starts at
; blob offset 0x40 (rva 0x1040) so the test can point DataDirectory[1] at it.
BITS 32
org 0x401000

start:
    push 4                  ; PAGE_READWRITE
    push 0x3000             ; MEM_RESERVE | MEM_COMMIT
    push 0x1000             ; size
    push 0                  ; process
    call [iat + 0]          ; VirtualAlloc
    test eax, eax
    je dead
    mov byte [eax], 0x42
    mov al, [eax]
    cmp al, 0x42
    mov ecx, 0x1122
    jmp term
dead:
    mov ecx, 0xDEAD
term:
    push ecx                ; exit code
    call [iat + 4]          ; ExitProcess (stdcall, one arg)
.spin:
    jmp .spin

    times (0x40 - ($ - start)) db 0

import_descriptor:
    dd oft - 0x400000       ; OriginalFirstThunk (rva)
    dd 0                    ; TimeDateStamp
    dd 0                    ; ForwarderChain
    dd name_k32 - 0x400000  ; Name (rva)
    dd iat - 0x400000       ; FirstThunk = IAT (rva)
    dd 0, 0, 0, 0, 0        ; terminating descriptor

oft:
    dd hn_alloc - 0x400000  ; hint/name: VirtualAlloc
    dd hn_exit - 0x400000   ; hint/name: ExitProcess
    dd 0

iat:
    dd hn_alloc - 0x400000
    dd hn_exit - 0x400000
    dd 0

    ; hint/name entries: 2-byte hint + NUL-terminated name
pad_to_hn:
    times (0x90 - (pad_to_hn - start)) db 0
hn_alloc:
    dw 0
    db "VirtualAlloc", 0
hn_exit:
    dw 0
    db "ExitProcess", 0
name_k32:
    db "KERNEL32.dll", 0
