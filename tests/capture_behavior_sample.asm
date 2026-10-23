; Synthetic behavior sample: the entry chain triggers the
; read-mode signals - the PEB walk ([gs:60h] -> [PEB+18h]), the BeingDebugged
; probe ([PEB+2]) and a call $+5 / pop GetPC pair - then a direct syscall
; with an unregistered number (default deny + the direct-syscall signal) and
; a clean NtTerminateProcess(1234h) exit. The capture path patches the entry
; into a spin before the real loader runs; in the emulator the restored
; entry executes exactly this chain.
.code
entry proc
    sub rsp, 28h
    ; PEB walk + BeingDebugged probe (rax stays the PEB pointer)
    mov rax, gs:[60h]
    mov bl, [rax+2]
    mov rbx, [rax+18h]
    ; GetPC: call $+5 (zero displacement) then pop rcx
    call next1
next1:
    pop rcx
    ; direct syscall: unregistered number -> default deny in rax
    mov eax, 0BEEFh
    syscall
    ; NtTerminateProcess(handle=-1, exit code 1234h)
    mov r10, -1
    mov edx, 1234h
    mov eax, 1002h
    syscall
    add rsp, 28h
    ret
entry endp
end
