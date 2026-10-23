; x86 multi-thread smoke: same semantics as thread_blob.asm in
; 32-bit via int 2e. The int 2e path maps [edx] = arg0 (handle ptr out),
; [edx+4] = arg1 (start / exit code), [edx+8] = arg2 (argument).
; org 0x401000: the wrapper embeds the blob at rva 0x1000 of image base
; 0x400000, so absolute references resolve for the loaded location.
BITS 32
org 0x401000

start:
    sub esp, 30h
    mov dword [esp], 0              ; thread handle out
    mov dword [esp + 4], thread_proc
    mov dword [esp + 8], shared_slot
    lea edx, [esp]
    mov eax, 1003h
    int 0x2e                        ; NtCreateThreadEx

    mov ecx, [esp]                  ; the created handle (ignored by wait)
    mov dword [esp + 4], 0          ; timeout placeholder block
    lea edx, [esp]
    mov eax, 1005h
    int 0x2e                        ; NtWaitForSingleObject (blocks, yields)

    mov eax, [shared_slot]          ; the handoff value
    mov dword [esp], 0              ; handle
    mov dword [esp + 4], eax        ; exit code
    mov dword [esp], -1             ; ProcessHandle = current process (NULL
    lea edx, [esp]                  ; would return STATUS_PENDING instead)
    mov eax, 1002h
    int 0x2e                        ; NtTerminateProcess
.spin:
    jmp .spin

thread_proc:
    mov eax, [esp + 4]              ; argument = &shared_slot
    mov dword [eax], 5678h
    mov dword [esp], 0              ; handle
    mov dword [esp + 4], 0          ; exit code
    lea edx, [esp]
    mov eax, 1004h
    int 0x2e                        ; NtTerminateThread
.spin2:
    jmp .spin2

shared_slot:
    dd 0
