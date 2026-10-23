; x86 by-hash shellcode: walk PEB32->Ldr->InMemoryOrderModuleList,
; verify MZ at each DllBase, count valid modules, terminate.
; Expected exit code: 4 (sample + ntdll + kernel32 + kernelbase).
; SysWOW64 shapes: fs:[30h] PEB, PEB+0Ch Ldr, Ldr+14h InMemoryOrderModuleList;
; node = InMemoryOrderLinks, entry = node-8, DllBase = node+10h.
; Termination: raw int 0x2e, eax = 1002h, edx -> args block
; ([edx] = handle, [edx+4] = exit code).
BITS 32
org 0

start:
    sub esp, 28h
    mov eax, [fs:30h]      ; PEB32
    mov ecx, [eax + 0Ch]   ; PEB_LDR_DATA32
    mov ebx, ecx
    add ebx, 14h           ; InMemoryOrderModuleList head
    mov esi, [ebx]         ; first node
    xor ecx, ecx           ; count
.walk:
    cmp esi, ebx
    je .done
    mov eax, [esi + 10h]   ; DllBase
    test eax, eax
    jz .next
    movzx edx, word [eax]
    cmp edx, 5A4Dh         ; 'MZ'
    jne .next
    inc ecx
.next:
    mov esi, [esi]         ; LIST_ENTRY32.Flink
    jmp .walk
.done:
    mov dword [esp], 0xFFFFFFFF  ; NtCurrentProcess
    mov [esp + 4], ecx           ; exit code = module count
    lea edx, [esp]
    mov eax, 1002h
    int 0x2e
.spin:
    jmp .spin
