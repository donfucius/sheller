; x86 SEH smoke: a raw FS:[0] registration record routes the
; access-violation write to a custom handler; the handler patches Eip past
; the fault and returns ExceptionContinueExecution, so the guest resumes
; into the success path ("caught" via the write builtin, then 0x5678).
; x86 dispatch walks the FS:[0] chain directly (no .pdata), so a raw record
; needs no unwind tables and no CRT: the whole point of the smoke.
; Position-independent throughout (org 0 blob, call/pop for its one string).
; System-service entry: int 2Eh, eax = number, edx = argument block
; (arg1..arg4 at +0..+0xC, arg5..arg7 at +0x10..+0x18 - the engine aims the
; stack-arg window at edx+0x10). Numbers: 1000h write, 1002h terminate.
; x86 CONTEXT: Eip +0xB8. EXCEPTION_RECORD: code +0, flags +4.
; EXCEPTION_CONTINUE_EXECUTION = 0, EXCEPTION_CONTINUE_SEARCH = 1.
BITS 32
org 0

start:
    sub esp, 8                  ; registration record: [esp]=next, [esp+4]=handler
    mov eax, [fs:0]             ; chain head so far (0 / 0FFFFFFFFh sentinel)
    mov [esp], eax
    call .here
.here:
    pop eax                     ; eax = runtime VA of .here
    lea ecx, [eax + (handler - .here)]
    mov [esp + 4], ecx
    mov [fs:0], esp             ; install

    xor eax, eax
    mov dword [eax], 11111111h  ; the AV probe (6 bytes: C7 00 11 11 11 11)

    ; == control resumes here: the handler patched Eip past the fault ==
    sub esp, 20h                ; argument block
    call .after_str
    db "caught"
.after_str:
    pop ecx
    mov [esp + 14h], ecx        ; arg6 buffer
    mov dword [esp + 18h], 6    ; arg7 length
    mov dword [esp], 0          ; arg1 handle
    mov dword [esp + 4], 0      ; arg2
    mov dword [esp + 8], 0      ; arg3
    mov dword [esp + 0Ch], 0    ; arg4
    lea edx, [esp]
    mov eax, 1000h              ; write builtin
    int 2Eh

    mov dword [esp], 0FFFFFFFFh ; arg1 handle = NtCurrentProcess
    mov dword [esp + 4], 5678h  ; arg2 exit code
    lea edx, [esp]
    mov eax, 1002h              ; terminate builtin
    int 2Eh
.spin:
    jmp .spin                   ; must never run

; The exception handler (cdecl): [esp+4]=record, [esp+8]=frame, [esp+0Ch]=ctx.
; Preserves every register but eax (the verdict).
handler:
    mov ecx, [esp + 4]          ; ExceptionRecord
    cmp dword [ecx], 0C0000005h
    jne .search
    cmp dword [ecx + 4], 0      ; first chance: no unwind flags
    jne .search
    mov edx, [esp + 0Ch]        ; ContextRecord
    add dword [edx + 0B8h], 6   ; Eip: skip the 6-byte faulting store
    xor eax, eax                ; ExceptionContinueExecution
    ret
.search:
    mov eax, 1                  ; ExceptionContinueSearch
    ret
