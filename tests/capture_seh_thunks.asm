; Direct-syscall thunks for the SEH sample (see capture_seh_sample.c) plus a
; fastfail entry: int 29h (__fastfail) bypasses every handler by definition,
; so it never reaches the guest dispatch and the engine must crash the run.

.code

; void thunk_write(const char* buffer, unsigned long length)
; NtWriteFile(handle=0, event=0, apc=0, apcctx=0, iosb=0, buffer, length, 0, 0)
; Stack args land at [rsp+28h..] so the engine's syscall reader (which reads
; arg5 at the Windows stub convention, kStackArgsOffset) sees them.
thunk_write proc
    mov r10, rcx                 ; buffer
    mov r11, rdx                 ; length
    sub rsp, 50h
    xor ecx, ecx
    xor edx, edx
    xor r8d, r8d
    xor r9d, r9d
    mov qword ptr [rsp+28h], 0   ; iosb
    mov [rsp+30h], r10           ; buffer
    mov [rsp+38h], r11           ; length
    mov qword ptr [rsp+40h], 0   ; key
    mov qword ptr [rsp+48h], 0   ; byte offset
    mov eax, 1000h
    syscall
    add rsp, 50h
    ret
thunk_write endp

; void thunk_terminate(unsigned long code)
; NtTerminateProcess(handle=-1, code)
thunk_terminate proc
    mov r10, -1                 ; ProcessHandle
    mov edx, ecx                ; ExitCode (fastcall: the code arrives in ecx)
    mov eax, 1002h
    syscall
    ret
thunk_terminate endp

; void entry_fastfail(void)
entry_fastfail proc
    mov ecx, 8                   ; FAST_FAIL_FATAL_APP_EXIT
    int 29h
    ret
entry_fastfail endp

end
