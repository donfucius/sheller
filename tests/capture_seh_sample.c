// SEH-driven synthetic sample for the exception-dispatch slice: two nested
// __try frames around a faulting probe prove the full guest dispatch path -
// the engine synthesizes EXCEPTION_RECORD/CONTEXT, the real
// ntdll!KiUserExceptionDispatcher walks both unwind frames, and the outer
// handler resumes into the syscall epilogue. MSVC C on purpose: x64 dispatch
// needs the .pdata/.xdata unwind tables the compiler emits (plain ml64 has
// none, and RtlLookupFunctionEntry fails without them). No CRT: direct
// syscall thunks only, custom entry point.

#include <windows.h>

typedef unsigned long u32;

void thunk_write(const char* buffer, u32 length);
void thunk_terminate(u32 code);

// -- language handler for the scope tables ------------------------------------
//
// cl bakes __C_specific_handler into the .xdata of every __try function;
// with the CRT stripped that symbol has no definition, so the sample provides
// its own. The job is small: interpret the scope table, run the filters, and
// hand the actual unwinding to ntdll's RtlUnwindEx - every hard part of the
// dispatch stays in the real ntdll code the snapshot mapped.

typedef struct _SCOPE_TABLE {
    ULONG Count;
    struct {
        ULONG BeginAddress;
        ULONG EndAddress;
        ULONG HandlerAddress; // filter RVA, or the EXCEPTION_* constant
        ULONG JumpTarget;     // __except body RVA for EXECUTE_HANDLER
    } ScopeRecord[1];
} SCOPE_TABLE_FIXUP;

// The last argument is PUNWIND_HISTORY_TABLE (the lookup cache). NULL is
// always legal; the dispatcher context is NOT a history table - passing it
// lets ntdll's lookup cache results into the DC bytes and then read them
// back as cached entries (the walk dies on a NULL FunctionTable).
VOID WINAPI RtlUnwindEx(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord,
                        PVOID ReturnValue, PCONTEXT OriginalContext, PVOID HistoryTable);

EXCEPTION_DISPOSITION __C_specific_handler(PEXCEPTION_RECORD ExceptionRecord,
                                           PVOID EstablisherFrame, PCONTEXT ContextRecord,
                                           PDISPATCHER_CONTEXT DispatcherContext)
{
    const DISPATCHER_CONTEXT* dispatch = DispatcherContext;
    // UNWIND_INFO: byte 2 is CountOfCodes (byte 3 is FrameRegister:Offset),
    // then CountOfCodes 2-byte slots padded to an even count; the language
    // -handler RVA sits right after the padding, and the scope table follows
    // that handler RVA - inline (Count first), not via a pointer.
    const unsigned char* unwind =
        (const unsigned char*)(dispatch->ImageBase + dispatch->FunctionEntry->UnwindData);
    const ULONG count_codes = unwind[2];
    const ULONG handler_slot = 4 + ((count_codes + 1u) & ~1u) * 2;
    const SCOPE_TABLE_FIXUP* scope = (const SCOPE_TABLE_FIXUP*)(unwind + handler_slot + 4);

    if ((ExceptionRecord->ExceptionFlags & EXCEPTION_UNWINDING) != 0) {
        // C scope tables carry no termination handlers; the frame that asked
        // for the unwind is the unwind target and is not called again.
        return ExceptionContinueSearch;
    }

    const ULONG pc = (ULONG)(dispatch->ControlPc - dispatch->ImageBase);
    for (ULONG i = 0; i < scope->Count; ++i) {
        if (pc < scope->ScopeRecord[i].BeginAddress || pc >= scope->ScopeRecord[i].EndAddress) {
            continue;
        }
        const ULONG handler = scope->ScopeRecord[i].HandlerAddress;
        if (handler == EXCEPTION_CONTINUE_SEARCH) {
            continue;
        }
        if (handler == EXCEPTION_CONTINUE_EXECUTION) {
            return ExceptionContinueExecution;
        }
        if (handler != EXCEPTION_EXECUTE_HANDLER) {
            // A filter function: first pass asks it for the verdict.
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
        // EXECUTE_HANDLER: unwind to this frame and resume at the handler
        // body. RtlUnwindEx runs the second pass and transfers control; it
        // does not return on success.
        RtlUnwindEx(EstablisherFrame, dispatch->ImageBase + scope->ScopeRecord[i].JumpTarget,
                    ExceptionRecord, 0, ContextRecord, NULL);
        break;
    }
    return ExceptionContinueSearch;
}

// -- the sample itself ---------------------------------------------------------

static u32 inner_filter(void)
{
    return EXCEPTION_CONTINUE_SEARCH; // keep walking: the outer frame handles
}

void inner_frame(void)
{
    __try {
        *(volatile u32*)0 = 0x11111111u; // write AV probe: the sample's trigger
        thunk_write("MISSED", 6);        // must never run
    } __except (inner_filter()) {
        thunk_write("INNER", 5); // must never run
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
        // The dispatch walked both frames; control flows through this
        // handler into the syscall epilogue.
        thunk_write("caught", 6);
        thunk_terminate(0x5678);
    }
    thunk_terminate(0xDEADC0DE); // must never run
}
