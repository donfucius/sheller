// sheller export macro - the marker that lets a declaration cross the shared
// library boundary. The product surface is the set of SHELLER_API declarations
// whose definitions live in src/shared/api.cpp; every other name a public
// header declares is the internal face - reachable by a consumer that links
// the static core, never present in the dynamic symbol table.
//
// Three shapes, one macro:
//   building the shared library (SHELLER_BUILDING_SHARED, defined PRIVATE on
//   that target alone)   dllexport on Windows, default visibility elsewhere.
//                        Not empty on POSIX: the static core is compiled with
//                        -fvisibility=hidden, so an empty macro here would
//                        export nothing at all.
//   consuming it         dllimport on Windows (import thunks + import library),
//                        nothing elsewhere.
//   the static core      never sees SHELLER_BUILDING_SHARED, so here the macro
//                        expands to dllimport on Windows. MSVC rejects a
//                        definition of a dllimport function, which is what
//                        makes "public name = product interface" a linker fact
//                        instead of a convention: the static core carries the
//                        implementation under the internal names in
//                        src/*/*_detail.h and src/api/wiring.h.
//
// Only include is <version>, the standard feature-test header: the consumer
// check at the bottom needs the library feature macros, and a version macro
// alone cannot tell whether the standard library in use actually ships what the
// exported signatures return. No third-party and no platform header - __declspec
// needs none.

#ifndef SHELLER_EXPORT_H
#define SHELLER_EXPORT_H

#include <version>

#if defined(_WIN32)
#if defined(SHELLER_BUILDING_SHARED)
#define SHELLER_API __declspec(dllexport)
#else
#define SHELLER_API __declspec(dllimport)
#endif
#else
#if defined(SHELLER_BUILDING_SHARED)
#define SHELLER_API __attribute__((visibility("default")))
#else
#define SHELLER_API
#endif
#endif

// ---------------------------------------------------------------------------
// Consumer contract. Everything that crosses this boundary is a C++ standard
// library type passed by value or by reference - std::expected,
// std::filesystem::path, std::vector, std::string, std::function, std::span -
// so the two sides have to agree on more than the six signatures. What can be
// checked at compile time is checked at the bottom of this header; the rest is
// binding on the consumer and is stated here because this is the one header
// every consumer is guaranteed to read.
//
// Lifetime:
//   * Do not unload the library while a log sink is installed, while anything it
//     returned is alive, or while a std::string_view it handed out
//     (unicorn_version_string) is in use. All of those reach into the library:
//     the sink's target was allocated on the consumer side but is owned by the
//     library's state, and the version view points at storage inside it.
//
// Callbacks: three host callbacks can be entered from inside this library - the
// log sink, the guest output sink, and the host event observer - and each is
// entered through a first-party frame that carries a handler. Not throwing stays
// the host's obligation in all three cases; what the library guarantees is the
// consequence of breaking it, and the consequence has one shape: the item in
// flight is dropped, the call or the run continues, the process is not
// terminated, and that is the behaviour on both platforms.
//   * A log sink must not throw, must not call back into the log facade and must
//     not block. The record is delivered on the host's thread while a
//     non-recursive mutex is held by an RAII guard, so re-entering deadlocks and
//     blocking stalls every thread that logs. The lock comes back whether a throw
//     is caught here or unwinds past it - what catching it here buys is that a
//     host's logging call never becomes an exception arriving in the host's own
//     frame, which is the outcome a diagnostic channel must not be able to
//     produce. The dropped record is not counted and is not echoed anywhere: the
//     library writes no host standard stream at any level.
//   * A guest output sink (SyscallRunOptions::write_sink, reached from
//     AnalysisOptions::run) must not throw. A sink that throws loses that one
//     write: the bytes handed to the throwing call are dropped, the writes after
//     it still arrive at the same sink in guest order, and nothing about the run
//     changes - the syscall handler still returns STATUS_SUCCESS, the ledger still
//     records the write, so the event stream and the run statistics are what they
//     would have been had the callback returned normally. Delivery into a sink is
//     pure observation: no engine decision depends on it. This is the log sink's
//     rule at the engine's other host-callback delivery point (the trampoline in
//     src/engine/rebuild_state.cpp, which is where syscalls::WriteSink's function
//     pointer is built), and it is the same rule rather than a second one: dropped,
//     not counted, not echoed, no log record about it.
//   * The host event observer is a different case and is guarded: it runs on the
//     engine's hook path, where an unwinding host exception would once have crossed
//     exception-free engine frames; those frames now carry unwind info, and the
//     guard is what keeps a throw from that callback altering a run's verdict.
//   * No C++ exception crosses any of the six entries. A failure inside the
//     library is reported through the entry's own result type, with the message
//     prefixed "internal error:"; a host never has to wrap a call in try/catch,
//     and the resources of the failed run (emulator instance, mapped regions,
//     capture temporaries) are released before the answer comes back.
//
// Concurrency:
//   * The six entry points may be called from several threads at once. The state of a
//     run belongs to that call - the emulator instance, the mapped regions and the
//     capture temporaries are built inside it and released when it returns, and they
//     never cross a thread boundary.
//   * Mutable process-wide state is exactly two things, each already synchronized:
//     the log sink (a non-recursive mutex guarding both the install and the delivery,
//     src/engine/log_state.cpp:28) and the one-shot unpack entry's work-directory
//     counter (std::atomic, src/api/unpack.cpp:79). Everything else at process scope
//     is read-only after initialization - the API description table
//     (src/behavior/api_descriptions.cpp:81) and the three diagnostic site switches
//     (src/engine/diag_trace.h) are function-local statics, whose initialization is
//     thread-safely once-only, and the wrapper-name generator is thread_local
//     (src/runtime/capture/capture.cpp:826), so no two threads share one. The census
//     behind that claim is a text scan of the library for static, thread_local and
//     namespace-scope objects, so it covers static storage only: state reached through
//     a pointer, which two hosts could share, is covered instead by the concurrency
//     tests and by a ThreadSanitizer build (see tests/README.md).
//   * Three exceptions ride that rule rather than contradict it. Sink callbacks are
//     serialized by the same mutex and must neither block nor re-enter the facade -
//     the Callbacks clause above. Concurrent unpack_sample calls must pass distinct
//     work directories, or leave the field empty and let the counter name a
//     process-unique one for each call. And the Windows capture route starts a real
//     process per call, so concurrency there costs processes: correct, not cheap.
//
// Build configuration:
//   * C++23 or newer on the consumer side, with a standard library that provides
//     std::expected. Checked below through the library feature macro rather than
//     __cplusplus: g++-13 at -std=c++23 still reports __cplusplus == 202100L
//     (measured), and a version macro says nothing about whether <expected>
//     actually exists.
//   * Do not define SHELLER_BUILDING_SHARED in a consumer: it flips the macro to
//     the export shape, so the consumer would be defining the product names
//     itself instead of importing them.
//   * Windows: the consumer's configuration must match the one this library was
//     built in. _ITERATOR_DEBUG_LEVEL follows the configuration and changes the
//     layout of std::string and std::vector while leaving the decorated names
//     identical, so a debug consumer against a release library is silent memory
//     corruption rather than a link error.
//   * POSIX: the consumer must not enable _GLIBCXX_DEBUG against a library built
//     without it - container layout again, names unchanged. A
//     _GLIBCXX_USE_CXX11_ABI mismatch is deliberately not checked: it changes
//     the mangled names (the __cxx11 inline namespace), so it fails at link time
//     naming the symbol, which is loud enough.
//   * The third-party runtimes this library was built against are private to it
//     (neither is on the export face). On Windows they are separate DLLs and
//     must sit next to the consumer's executable; elsewhere they are linked in
//     and there is nothing to deploy. A host that embeds its own copy therefore
//     ends up with two instances in the process - no symbol collision, but no
//     sharing either.
//   * The one handle that escapes is the void* the diagnostic entry-hit callback
//     receives (SyscallRunOptions::diag_entry_hit): it is the library's own
//     emulator instance. Read registers or memory through this library's entry
//     points only - handing that pointer to a different emulator copy is
//     undefined behaviour, not a diagnostics quirk.
// ---------------------------------------------------------------------------

// These are #error checks rather than static_asserts on purpose: every macro
// they test may legitimately be undefined, and an undefined macro reads as 0
// inside a constant expression, which would turn the guard into decoration.
// The configuration checks run only for a consumer of the shared library -
// SHELLER_LIB_ABI_* are PUBLIC definitions on that target - because a consumer
// of the static core compiles the core itself and has no boundary to mismatch
// across. The feature check below is unconditional: it is about this header
// being usable at all.
// The messages stay short on purpose: a long #error gets folded by the formatter
// into a continued directive, and the explanation belongs to the contract above.
#if !defined(__cpp_lib_expected) || (__cpp_lib_expected < 202202L)
#error "sheller: C++23 with std::expected is required - see the consumer contract above"
#endif

#if defined(_WIN32) && defined(SHELLER_LIB_ABI_DEBUG)
#if defined(_DEBUG) && (SHELLER_LIB_ABI_DEBUG == 0)
#error "sheller: debug consumer against a release library - _ITERATOR_DEBUG_LEVEL differs"
#elif !defined(_DEBUG) && (SHELLER_LIB_ABI_DEBUG != 0)
#error "sheller: release consumer against a debug library - _ITERATOR_DEBUG_LEVEL differs"
#endif
#endif

#if defined(SHELLER_LIB_ABI_GLIBCXX_DEBUG)
#if defined(_GLIBCXX_DEBUG) && (SHELLER_LIB_ABI_GLIBCXX_DEBUG == 0)
#error "sheller: consumer enables _GLIBCXX_DEBUG, the library was built without it"
#elif !defined(_GLIBCXX_DEBUG) && (SHELLER_LIB_ABI_GLIBCXX_DEBUG != 0)
#error "sheller: library built with _GLIBCXX_DEBUG, the consumer is not"
#endif
#endif

#endif // SHELLER_EXPORT_H
