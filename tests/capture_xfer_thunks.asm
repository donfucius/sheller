; Direct-syscall thunk for the xfer sample (see capture_xfer_sample.c):
; terminates the guest with the caller's exit code through the policy
; handler's NtTerminateProcess.

.code
thunk_terminate proc
    mov edx, ecx
    mov r10, -1
    mov rax, 1002h
    syscall
    ret
thunk_terminate endp
end
