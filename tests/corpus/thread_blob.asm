; multi-thread injector sample: the main thread creates a worker
; via NtCreateThreadEx (synthetic 1003h, register ABI: rcx = &handle out,
; rdx = start routine, r8 = argument), the worker writes 1234h into the
; shared slot and terminates via NtTerminateThread (1004h), the main thread
; waits via NtWaitForSingleObject (1005h, yields once and resumes satisfied),
; verifies the handoff and exits with the slot value as the process code via
; NtTerminateProcess (1002h).
; org 0x401000: the wrapper embeds the blob at rva 0x1000 of image base
; 0x400000, so absolute references resolve for the loaded location.
BITS 64
org 0x401000

start:
    sub rsp, 38h
    mov qword [rsp + 20h], 0        ; thread handle out
    lea rdx, [thread_proc]          ; StartRoutine
    lea r8, [shared_slot]           ; Argument
    lea rcx, [rsp + 20h]            ; &ThreadHandle
    mov eax, 1003h
    syscall                         ; NtCreateThreadEx

    mov ecx, [rsp + 20h]            ; the created handle (ignored by wait)
    xor edx, edx                    ; not alertable
    xor r8d, r8d                    ; timeout = NULL (infinite)
    mov eax, 1005h
    syscall                         ; NtWaitForSingleObject (blocks, yields)

    mov eax, [shared_slot]          ; the handoff value
    mov edx, eax                    ; ExitCode (arg 2)
    mov ecx, -1                     ; ProcessHandle = current process (native
    mov eax, 1002h                  ; idiom; NULL would return STATUS_PENDING
    syscall                         ; NtTerminateProcess and keep the caller
.spin:                              ; alive in the detach walk)
    jmp .spin

thread_proc:                        ; rcx = &shared_slot
    mov dword [rcx], 1234h
    xor ecx, ecx                    ; handle
    xor edx, edx                    ; exit code
    mov eax, 1004h
    syscall                         ; NtTerminateThread
.spin2:
    jmp .spin2

shared_slot:
    dq 0
