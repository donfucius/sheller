// VEH-driven sample for the exception-dispatch slice: registers a vectored
// handler through the real ntdll!RtlAddVectoredExceptionHandler (replay runs
// the registration as guest code, so the snapshot needs no pre-seeded list)
// and then faults twice. The engine dispatch must consult the vectored list
// BEFORE the structured walk: the first fault defers to the __except
// (EXCEPTION_CONTINUE_SEARCH) but leaves an observable marker, the second is
// resumed through the handler-rewritten CONTEXT
// (EXCEPTION_CONTINUE_EXECUTION - NtContinue semantics, the snapshot is not
// what resumes). Both verdicts are observable in the output stream. MSVC C
// on purpose: same unwind-table requirement as capture_seh_sample.

#include <windows.h>

typedef unsigned long u32;

void thunk_write(const char* buffer, u32 length);
void thunk_terminate(u32 code);

// -- language handler for the scope tables ------------------------------------
//
// cl bakes __C_specific_handler into the .xdata of every __try function and
// the stripped CRT has no definition: the sample provides it, exactly like
// capture_seh_sample does (see there for the walk commentary).

typedef struct _SCOPE_TABLE {
    ULONG Count;
    struct {
        ULONG BeginAddress;
        ULONG EndAddress;
        ULONG HandlerAddress; // filter RVA, or the EXCEPTION_* constant
        ULONG JumpTarget;     // __except body RVA for EXECUTE_HANDLER
    } ScopeRecord[1];
} SCOPE_TABLE_FIXUP;

VOID WINAPI RtlUnwindEx(PVOID TargetFrame, PVOID TargetIp, PEXCEPTION_RECORD ExceptionRecord,
                        PVOID ReturnValue, PCONTEXT OriginalContext, PVOID HistoryTable);

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

// -- the vectored handler + probes ---------------------------------------------

static char g_veh_saw = 'n'; // 'v' once the VEH handler ran
static u32 g_fault = 0;      // which probe is in flight

// The second probe's resume point: an empty noinline function whose body is
// a bare ret. probe2 is a leaf with no prologue, so at its fault [rsp] still
// holds the return address into entry_main - resuming here pops it and lands
// right after the probe call.
__declspec(noinline) static void probe2_done(void)
{
}

__declspec(noinline) static void probe2(void)
{
    *(volatile u32*)0 = 0x22222222u; // the AV probe the VEH handler skips
}

LONG WINAPI veh_handler(PEXCEPTION_POINTERS pointers)
{
    if (pointers->ExceptionRecord->ExceptionCode != 0xC0000005) {
        return EXCEPTION_CONTINUE_SEARCH;
    }
    ++g_fault;
    if (g_fault == 1) {
        g_veh_saw = 'v';
        return EXCEPTION_CONTINUE_SEARCH; // the structured frame owns it
    }
    pointers->ContextRecord->Rip = (ULONG64)(void*)&probe2_done;
    return EXCEPTION_CONTINUE_EXECUTION; // resume past the probe
}

void entry_main(void)
{
    RtlAddVectoredExceptionHandler(0, veh_handler);

    __try {
        *(volatile u32*)0 = 0x11111111u; // fault 1: VEH defers, SEH catches
        thunk_write("MISSED", 6);        // must never run
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        thunk_write(&g_veh_saw, 1); // 'v': the vectored walk ran first
        thunk_write("1", 1);
    }

    probe2();            // fault 2: VEH resumes past it
    thunk_write("2", 1); // reached only via the rewritten CONTEXT

    thunk_terminate(0x5678);
    thunk_terminate(0xDEADC0DE); // must never run
}
