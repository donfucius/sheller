// SEH __finally corpus: the unwind second pass must run
// the termination handler of frames it unwinds past. The fault is caught by
// an outer __except; the inner frame's __finally body runs during the unwind,
// before the __except body. Output "FX", exit 0x5678. The language handler is
// self-provided (static-CRT-only symbol, no DLL exports it) with real
// __finally semantics on the unwind pass.

#include <windows.h>

typedef unsigned long u32;

void thunk_write(const char* buffer, u32 length);
void thunk_terminate(u32 code);

// -- language handler for the scope tables (see capture_seh_sample.c) --------

typedef struct _SCOPE_TABLE {
    ULONG Count;
    struct {
        ULONG BeginAddress;
        ULONG EndAddress;
        ULONG HandlerAddress; // filter RVA, or the EXCEPTION_* constant
        ULONG JumpTarget;     // __except body RVA; 0 marks a __finally scope
                              // (HandlerAddress is then the finally body)
    } ScopeRecord[1];
} SCOPE_TABLE_FIXUP;

VOID WINAPI RtlUnwindEx(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord,
                        PVOID ReturnValue, PCONTEXT OriginalContext, PVOID HistoryTable);

static VOID run_finally(const SCOPE_TABLE_FIXUP* scope, ULONG index, ULONG_PTR image_base,
                        ULONG site, PEXCEPTION_RECORD record, PVOID frame, PCONTEXT context,
                        PDISPATCHER_CONTEXT dispatch)
{
    (void)site;
    const ULONG body = scope->ScopeRecord[index].HandlerAddress;
    if (body == 0) {
        return;
    }
    // __finally bodies are plain calls during the unwind (real
    // __C_specific_handler semantics): the body returns normally.
    void (*finally_body)(PEXCEPTION_RECORD, PVOID, PCONTEXT, PDISPATCHER_CONTEXT) =
        (void (*)(PEXCEPTION_RECORD, PVOID, PCONTEXT, PDISPATCHER_CONTEXT))(image_base + body);
    finally_body(record, frame, context, dispatch);
}

EXCEPTION_DISPOSITION __C_specific_handler(PEXCEPTION_RECORD ExceptionRecord,
                                           PVOID EstablisherFrame, PCONTEXT ContextRecord,
                                           PDISPATCHER_CONTEXT DispatcherContext)
{
    const DISPATCHER_CONTEXT* dispatch = DispatcherContext;
    const unsigned char* unwind =
        (const unsigned char*)(dispatch->ImageBase + dispatch->FunctionEntry->UnwindData);
    const ULONG count_codes = unwind[2];
    const ULONG handler_slot = 4 + ((count_codes + 1u) & ~1u) * 2;
    const SCOPE_TABLE_FIXUP* scope = (const SCOPE_TABLE_FIXUP*)(unwind + handler_slot + 4);

    if ((ExceptionRecord->ExceptionFlags & EXCEPTION_UNWINDING) != 0) {
        // unwind pass: run every __finally scope covering ControlPc, reverse
        const ULONG pc = (ULONG)(dispatch->ControlPc - dispatch->ImageBase);
        for (ULONG i = scope->Count; i > 0; --i) {
            const ULONG idx = i - 1;
            const ULONG begin = scope->ScopeRecord[idx].BeginAddress;
            const ULONG end = scope->ScopeRecord[idx].EndAddress;
            if (pc < begin || pc >= end) {
                continue;
            }
            if (scope->ScopeRecord[idx].JumpTarget == 0) {
                run_finally(scope, idx, dispatch->ImageBase, pc, ExceptionRecord, EstablisherFrame,
                            ContextRecord, DispatcherContext);
            }
        }
        return ExceptionContinueSearch;
    }

    const ULONG pc = (ULONG)(dispatch->ControlPc - dispatch->ImageBase);
    for (ULONG i = 0; i < scope->Count; ++i) {
        if (pc < scope->ScopeRecord[i].BeginAddress || pc >= scope->ScopeRecord[i].EndAddress) {
            continue;
        }
        const ULONG handler = scope->ScopeRecord[i].HandlerAddress;
        if (scope->ScopeRecord[i].JumpTarget == 0) {
            continue; // __finally: no verdict in the search pass
        }
        if (handler == EXCEPTION_CONTINUE_SEARCH) {
            continue;
        }
        if (handler == EXCEPTION_CONTINUE_EXECUTION) {
            return ExceptionContinueExecution;
        }
        if (handler != EXCEPTION_EXECUTE_HANDLER) {
            const u32 (*filter)(PEXCEPTION_RECORD, PVOID) =
                (const u32 (*)(PEXCEPTION_RECORD, PVOID))(dispatch->ImageBase + handler);
            const u32 verdict = filter(ExceptionRecord, EstablisherFrame);
            if (verdict == EXCEPTION_CONTINUE_SEARCH) {
                continue;
            }
            if (verdict == EXCEPTION_CONTINUE_EXECUTION) {
                return ExceptionContinueExecution;
            }
        }
        RtlUnwindEx(EstablisherFrame, dispatch->ImageBase + scope->ScopeRecord[i].JumpTarget,
                    ExceptionRecord, 0, ContextRecord, NULL);
        break;
    }
    return ExceptionContinueSearch;
}

// -- the sample itself ---------------------------------------------------------

void inner_frame(void)
{
    __try {
        *(volatile u32*)0 = 0x11111111u; // write AV probe
        thunk_write("MISSED", 6);        // must never run
    } __finally {
        thunk_write("F", 1); // the unwind second pass runs this exactly once
    }
}

static u32 outer_filter(void)
{
    return EXCEPTION_EXECUTE_HANDLER;
}

void entry_main(void)
{
    __try {
        inner_frame();
    } __except (outer_filter()) {
        thunk_write("X", 1);
        thunk_terminate(0x5678);
    }
    thunk_terminate(0xDEADC0DE); // must never run
}
