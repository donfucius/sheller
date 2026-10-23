; by-hash shellcode: walk PEB->Ldr->InMemoryOrderModuleList,
; verify MZ at each DllBase, count valid modules, terminate.
; Expected exit code: 4 (sample + ntdll + kernel32 + kernelbase).
BITS 64
org 0

start:
    sub rsp, 28h
    mov rax, [gs:60h]
    mov rcx, [rax + 0x18]
    mov rdx, [rcx + 0x20]
    mov r8, rcx
    add r8, 0x20
    xor r9, r9
.walk:
    cmp rdx, r8
    je .done
    mov rax, [rdx + 0x20]
    test rax, rax
    jz .next
    movzx ecx, word [rax]
    cmp cx, 0x5A4D
    jne .next
    inc r9
.next:
    mov rdx, [rdx]
    jmp .walk
.done:
    mov r10, -1
    mov edx, r9d
    mov eax, 1002h
    syscall
    jmp $
