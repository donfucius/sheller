# Embedding sheller

This document is the integration guide for a host that links sheller as a library.
It covers the decisions a host has to make. It is not the contract: the normative
text for what crosses the library boundary is the consumer-contract block in
[include/sheller/export.h](../include/sheller/export.h), and this file deliberately
does not restate the parts of it that the header enforces at compile time. Where
those matter here, the section points at the header and says what each check is for.

Three more documents stay in sync with the delivered surface: [README.md](../README.md)
(what the project is and how to build it), [cli.md](cli.md) (the `sheller` command line:
flags, the report's two event levels, the attribution conventions, determinism) and
[tests/README.md](../tests/README.md) (how the surface is verified).

## Getting the library

The delivery is an install prefix. From a configured and built tree:

```
cmake --install <build-dir> --prefix <prefix> --config Release
```

`--config` matters only for a multi-config generator (Visual Studio); on a
single-config generator the configuration is already fixed.

The prefix holds:

| Path | Contents |
| --- | --- |
| `bin/` | the `sheller` command line; on Windows also `sheller.dll` and the third-party runtimes it needs (`unicorn.dll`, `Zydis.dll`) |
| `lib/` | on Linux `libsheller.so`, `libsheller.so.0` and `libsheller.so.0.1.0`; on Windows the import library `sheller.lib` |
| `include/sheller/` | the public headers, the same set as in the source tree |
| `lib/cmake/sheller/` | `shellerConfig.cmake`, `shellerConfigVersion.cmake`, `shellerTargets.cmake`, `shellerAbiConfig.cmake` |

A consumer needs one package call and one target:

```cmake
find_package(sheller CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE sheller::sheller)
```

The include directory comes with the target, so nothing has to be spelled out by
hand, and no environment variable is part of "installed": the shipped command line
resolves the library through a `$ORIGIN`-relative run path on Linux and through the
same directory on Windows.
[tests/install-consumer/](../tests/install-consumer) is that one-package consumer,
and `tests/install-consumer/run.cmake` configures, builds and runs it against a
throwaway prefix - it is the end-to-end judge for everything in this section, and it
is deliberately not part of the default test set because it needs an installed
prefix.

The library is also linked directly by the project's own command line, which is the
reference host for everything below: [src/cli/main.cpp](../src/cli/main.cpp).

### Version numbers, and what they promise

`project()` in [CMakeLists.txt](../CMakeLists.txt) is the only place the version is
written down. The library file name, the SONAME and the package version all derive
from it. The public header keeps checked-in literals
([include/sheller/version.h](../include/sheller/version.h)) because the header must
stay a readable file that the header-boundary checks can grep without a configure
step - so a gate reconciles them: [tests/version_gate.cmake](../tests/version_gate.cmake),
run in the default test set on both platforms as `version_consistency`. If a version
is bumped in one place and not the other, the build stops naming both places.

On Linux the library's SONAME is `libsheller.so.0`: the name plus the major version
only, so a patch or minor release under the same major does not require a consumer
to re-link. What that promises is stated in the header and repeated here because it
is easy to over-read: everything that crosses the boundary is a C++ standard library
type (`std::expected`, `std::filesystem::path`, `std::vector`, `std::string`,
`std::function`, `std::span`), so "compatible within one SONAME" is a claim about
layouts, not about names. The mechanism covers half of it - the *set* of exported
names is reconciled against a checked-in list by
[tests/export_surface_gate.cmake](../tests/export_surface_gate.cmake), which fails on
one name more or one name less. Nothing checks the six signatures or the layout of
the types they carry. That half is held by a rule: **a change that breaks it goes in
the same commit as a major-version bump.** That is a decision, not an oversight, and
a host should treat the rule as the guarantee it is.

### Build-side requirements

C++23 with a standard library that provides `std::expected`; the debug/release
configuration has to match the library's on Windows; `_GLIBCXX_DEBUG` must not be
enabled against this library on POSIX. All three are compile-time `#error` checks at
the bottom of [include/sheller/export.h](../include/sheller/export.h), and they fire
from an installed tree as well as from the source tree - the package records the
configuration the library was actually built in, precisely so that a debug consumer
of a release library cannot read as a match. What each check is for is written in
that header; the reason `std::string` and `std::vector` layout is the sensitive part
is that the decorated names do not change when the layout does.

Two more are not checked and are worth knowing:

* `_GLIBCXX_USE_CXX11_ABI` mismatch is deliberately not checked, because it changes
  the mangled names and therefore fails loudly at link time. That is loud enough.
* The host must build with control-flow protection off (`/guard:cf-`).
  [CMakeLists.txt](../CMakeLists.txt) applies that to first-party targets, with the
  reason next to the flag: unicorn's TCG crashes in a CFG-enabled host process, and
  every engine binary executes TCG-generated code in-process. A host that enables CFG
  in its own translation units is not protected by the library's choice.

The third-party runtimes this library was built against are private to it: on Windows
they arrive as `unicorn.dll` and `Zydis.dll` next to the executable, elsewhere they
are linked in. They are not on the export face, so a host that also embeds its own
copy ends up with two instances in the process - no symbol collision, but no sharing
either.

## What the library gives you

Six entry points, all declared in the public headers and all defined in
[src/shared/api.cpp](../src/shared/api.cpp):

| Entry | Header | What it is for |
| --- | --- | --- |
| `sheller::analyze` (path form) | [include/sheller/analysis.h](../include/sheller/analysis.h) | analyse a snapshot or a sample file |
| `sheller::analyze` (bytes form) | the same header | the same analysis from a buffer in memory |
| `sheller::unpack_sample` | the same header | one-shot unpack: run, dump, repair, write the artifacts |
| `sheller::capture::run` | [include/sheller/capture.h](../include/sheller/capture.h) | produce a v1 snapshot from a live process (Windows hosts) |
| `sheller::log::set_sink` | [include/sheller/log.h](../include/sheller/log.h) | install the host's diagnostic sink and threshold |
| `sheller::unicorn_version_string` | [include/sheller/version.h](../include/sheller/version.h) | the version of the emulator actually linked in |

No C++ exception crosses any of them. A failure inside the library comes back through
the entry's own result type with the message prefixed `internal error:`, and the
resources of the failed run are released before the answer arrives. A host does not
need to wrap a call in `try`/`catch`.

`sheller::version_string()` and the `version_major` / `version_minor` /
`version_patch` accessors are header-side compile-time facts, not exports.

Everything a public header declares beyond those six - `snapshot::Writer` and
`snapshot::Reader`, `run_snapshot_syscalls`, `repair_dump`, `log::write`,
`capture::run_to_buffer`, `capture_available`, the inline name tables - is the
internal face: reachable by a host that links the static core, absent from the dynamic
symbol table. [tests/export_surface_gate.cmake](../tests/export_surface_gate.cmake)
reconciles the built library's exported name set against the checked-in lists, symbol
by symbol, on both platforms.

A consumer binary walks **one** link route - the shared library or the static core,
never both. A binary holding both keeps two copies of the process state, the log sink
being the visible one, and the two halves then disagree silently.

**Public-surface change in this release.** `behavior::BehaviorSignal` and
`AnalysisArtifacts::signals` are retired: the rules layer's judgments are event
types now (`EventTypeId` 12..24, fixed names in `kEventTypeNames`), delivered in
`AnalysisArtifacts::semantic_events` and counted in `event_counts` like any other
event; `AnalysisArtifacts::oep_candidates` is derived from the `oep-candidate`
events in first-occurrence order. `UnpackOptions::report_dir` is gone, and
`UnpackOutcome::repair` carries the structured `RepairSummary` (per-region verdict,
uncovered thunks, residual audit, OEP application) - no report file exists.
`UnpackOptions::timeline` lights the bounded window-side ledger that the full event
level merges into the report. The engine-to-rules `BehaviorFact` channel now lives
in an internal header (`src/engine/behavior_fact.h`); hosts see those facts as
forwarded events (`mem-read`/`mem-write`/`sample-code`), never as a separate
artifact. There is no source-compatible shim: recompile against this header set.

## Diagnostics

### The sink

The library writes nothing anywhere unless the host asks it to. There is exactly one
channel and it is process-wide:

```cpp
sheller::log::set_sink(
    [](sheller::log::level sev, std::string_view message) {
        // hand it to your logger
    },
    sheller::log::level::kWarning); // the minimum level that reaches the callback
```

Three properties of that call are the whole design:

* **Uninstalled means silent.** An empty sink disables the channel; there is no
  fallback output and no default destination. Passing an empty sink is how you go
  back to silent.
* **The threshold is filtered library-side**, so a record below it never reaches the
  callback and never gets rendered.
* **There is no "log file path" API, on purpose.** The library does not open files
  for its own diagnostics; putting them in a file is a few lines inside your sink:

```cpp
#include <fstream>

static std::ofstream log_file{"analysis.log", std::ios::app};

sheller::log::set_sink(
    [](sheller::log::level sev, std::string_view message) {
        log_file << static_cast<int>(sev) << ' ' << message << '\n';
        log_file.flush();
    },
    sheller::log::level::kInfo);
```

The shipped command line is the reference host for this wiring: its `--log-level`
option (`debug|warn|info|error`, on each subcommand that reaches the library) moves
the facade's threshold and the renderer's own level together, so a record the library
passes is not then dropped by the rendering layer. See
`install_log_sink` and `apply_log_level` in
[src/cli/main.cpp](../src/cli/main.cpp).

### Where a record is delivered, and what that means for your callback

A diagnostic record is delivered **on the thread that produced it** - which is often
the thread calling `analyze` - and the library holds a non-recursive mutex across the
delivery. Two obligations follow, and they are in the header as well:

* **Do not block in the sink.** Blocking stalls every thread that logs.
* **Do not call back into the log facade from the sink.** The mutex is not recursive,
  so re-entering deadlocks.

A sink that throws is contained: that one record is dropped, the process is not
terminated, and the behaviour is the same on both platforms. Not throwing stays your
obligation - the containment is about the consequence, not a licence.

### Trace records need two more things to be switched on

The engine's diagnostic traces (the ones that describe what the emulator decided, as
opposed to what the guest did) are gated by a site switch in addition to your
threshold. The three switches are environment variables, read once per process:

| Switch | What it turns on |
| --- | --- |
| `SHELLER_SEH_TRACE` | guest exception dispatch, and the per-instruction fidelity hooks installed only under it |
| `SHELLER_LOOP_GATE_TRACE` | loop-gate window summaries and the run verdict distribution |
| `SHELLER_FILE_TRACE` | guest file-serve decisions |

So a trace record needs: the switch set **and** your threshold at or below debug **and**
a sink installed. Setting the environment variable alone cannot make the library write
anything, because with no sink there is nowhere for the record to go. The default cost
of a disabled site is one boolean; the rendering (and its one allocation) happens only
for a record somebody asked for.

Because the switches are cached on first use, a process that wants one set has to set
it before the first record is produced - a test that toggles it mid-run will see the
value from before. The spelling is in
[src/engine/diag_trace.h](../src/engine/diag_trace.h).

## Events

`AnalysisOptions` has one subscription slot for the host, and it is **per call**, not
process-wide:

```cpp
sheller::AnalysisOptions options{};
options.event_type_mask = (1ULL << static_cast<std::uint16_t>(sheller::EventTypeId::kSyscall))
                        | (1ULL << static_cast<std::uint16_t>(sheller::EventTypeId::kXfer));
options.event_observer = [](sheller::EventTypeId type,
                           const sheller::EventPreamble& preamble,
                           std::span<const std::uint8_t> fields) {
    // type, seq/tid/pc in preamble, and the type-specific fields for that event
};
```

* `event_type_mask` is a 64-bit mask in which bit `i` selects `EventTypeId` value `i`.
  A type whose bit is clear never invokes the callback - not "invokes and discards",
  zero crossings. Types with an id above 63 cannot be addressed at all. `0` selects
  nothing.
* The observer is **teed** with the facade's own internal wiring: subscribing does not
  displace the layers that build the event stream, and turning the behavior tier off
  does not remove your subscription. The judgments the rules layer emits arrive
  through the same callback after the event that triggered them, and forwarded
  facts (`mem-read`/`mem-write`/`sample-code`) arrive as their own events.
* `SyscallRunOptions`' own `event_sink` and `stub_sink` are facade-owned: settings
  a host puts on them are ignored, because they complete the internal wiring. The
  engine-to-rules fact channel rides beside the options as an internal type
  (`src/engine/behavior_fact.h`), so it has no public slot at all. Host
  subscription goes through `event_observer`.
* **The callback runs on the engine's hook path.** Do not allocate there, do not do
  I/O there, do not block there, do not throw. A throw from this callback is caught
  for you - that is what keeps a broken observer from changing a run's verdict - but
  the run pays for the catch every time one happens.
* **If you drop events, count the drops.** A host-side ring that overflows silently
  turns a complete picture into a sample, and the library cannot see your buffer. The
  library's own window tier is honest about its loss instead: it reports
  `timeline_dropped` and `timeline_truncated` on the artifacts, and the exact whole-run
  counts are in `event_counts` regardless of what the window kept.

### How much event traffic to expect

Three orders of magnitude apart, and the choice of tier is the main thing that
determines whether an embedding is fast:

* **Transfer events (`kXfer`) and the default column** are low-volume. These are
  control-flow crossings, interpreted facts (syscalls, API calls, exceptions, thread
  creation, `cpuid`, `rdtsc`), the sample-code accesses into system modules
  (`mem-read`/`mem-write`) and the low-frequency judgments. The default column has
  no count cap and evicts nothing, so its cost grows with the run, not with a fixed
  ceiling. Other page accesses stay in the counts and the window tier.
* **The window tier** (`options.timeline = true`) is a bounded ring: a fixed-capacity
  window, with overflow made visible by `timeline_dropped` / `timeline_truncated`
  rather than hidden. This is the tier to use when you want an ordered picture without
  an unbounded buffer; it is what the full event level merges into the report.
* **Instruction-level observation** is not a delivery tier. `kBlockExec`, the
  forwarded `sample-code` stream and the high-frequency `smc-execute` judgment are
  produced per guest block / instruction; a real sample runs millions of operations,
  which is why subscribing to them means subscribing to a fire hose, and why the mask
  exists. The facade's own low-frequency judgments never depend on that window. If
  you think you want every instruction, what you usually want is the window plus the
  default column.

Budgets bound a run - `run.max_instructions` (0 means unlimited) and `run.timeout_ms`
- and the run reports which of them stopped it, so a host can pick a cheap ceiling for
triage and raise it for depth.

`run.xfer_number` (and `UnpackOptions::xfer_number`) stops before the landing block of
the Nth execution transfer (1-based; `0` = off; not an event-stream seq). The stop is a
success: `SyscallRunStats::xfer_stop` is set, `terminated` stays false, and the dump is
eligible. `SyscallRunStats::xfers` counts transfers only while the xfer gate is active
(an event sink, a non-zero target, or the `esp+xfer` goal, whose ordinal arming needs
the source block's tracked identity) and outside burn-loop probe speculation, so `0`
does not mean the run executed none, and a report's `kXfer` ordinal is not necessarily
the same number to arm. The stop vetoes the finish-time wall-clock recomputation, so a
wall clock crossed inside the leg the transfer ends does not turn the stop into a
timeout. `analyze` reaches the field
through the existing `AnalysisOptions::run` pass-through; `unpack_sample` copies it into
its own run options.

The esp stop goals ride the same option family: `run.esp_stop_goal` (and
`UnpackOptions::esp_stop_goal`) takes `kStopAtRestore` (stop at the confirmed
entry stack restore) or `kArmThenNextXfer` (arm there, stop at the next
transfer). Every confirmed restore also emits the passive `kStackRestore` event
to the event sink on any instrumented run, whether or not a goal was
requested; the confirmation windows on the entry's statically scanned save
area, and an entry that saves no registers there is a silent miss. A hit sets
`SyscallRunStats::esp_stop` (`esp+xfer` sets `xfer_stop` too, with `xfers`
carrying the hit ordinal) under the same successful-stop contract.

## Guest output

A guest's `NtWriteFile` bytes are delivered to `options.run.write_sink`:

```cpp
options.run.write_sink = [](const std::uint8_t* data, std::size_t size) {
    // forward them wherever the host wants guest output to go
};
```

* **Empty means disabled**, decided at the call site, so a host that does not want
  guest output pays nothing for it.
* **The library writes guest output nowhere else** - never your `stdout`, never a
  file. A host that wants the guest's bytes on `stdout` has to forward them itself;
  that is what the command line's `--guest-stdout` does.
* **Your callback must not throw.** If it does, that one write is dropped and nothing
  else changes: the writes after it still arrive at the same sink in guest order, the
  syscall handler still answers success, the event ledger still records the write, and
  the run's event stream and statistics are what they would have been. The guest
  cannot observe the loss. This is the same rule the log sink is given, at the
  engine's other host-callback delivery point, with the same three "no" answers: not
  counted, not echoed to a standard stream, not logged.

## Lifetime and unloading

* Do not unload the library while a log sink is installed, while anything the library
  returned is still alive, or while a `std::string_view` it handed out (
  `unicorn_version_string`) is in use. The sink's target was allocated on your side
  but is owned by the library's process-wide state, and the version view points at
  storage inside the library.
* The artifacts you get back (`AnalysisArtifacts`, `UnpackOutcome`) are yours to keep
  after the call returns; they hold their own storage.
* The one handle that escapes is the `void*` the diagnostic entry-hit callback receives
  (`SyscallRunOptions::diag_entry_hit`): it is the library's own emulator instance.
  Read registers or memory through this library's entry points only.

## Concurrency

The six entries may be called from several threads at once: the state of a run -
emulator instance, mapped regions, capture temporaries - belongs to that call and
never crosses a thread boundary. Mutable process-wide state is exactly two things,
both already synchronized: the log sink (a non-recursive mutex guarding install and
delivery) and the one-shot unpack entry's work-directory counter (atomic). Three
things ride that rule rather than contradicting it:

* sink callbacks are serialized by that same mutex and must neither block nor re-enter;
* concurrent `unpack_sample` calls must pass distinct work directories, or leave the
  field empty and let the counter name a process-unique one for each call;
* the Windows capture route starts a real process per call, so concurrency there costs
  processes - correct, not cheap.

The census behind that claim is a text scan of the library for `static`, `thread_local`
and namespace-scope objects, so it covers static storage only. State reached through a
pointer is covered by the concurrency tests instead, and by a ThreadSanitizer build -
see [tests/README.md](../tests/README.md) for what that does and does not claim.

## Capability boundary off Windows

* **Snapshot production is Windows-only.** `sheller::capture::run` needs to suspend a
  real process and re-photograph its memory, so off Windows it returns a structured
  capture-class failure with the message "the snapshot capture route is only supported
  on Windows hosts" rather than a link error or a partial answer
  ([src/runtime/capture/capture_stub.cpp](../src/runtime/capture/capture_stub.cpp)).
* **Snapshot replay is portable.** The v1 snapshot format is host-independent, so
  `analyze` on a snapshot file or its bytes behaves the same on either platform. This
  is how a corpus captured on Windows is analysed elsewhere.
* **Sample input takes a different route off Windows.** `analyze` on a sample routes
  to capture on Windows and elsewhere to construction plus replay
  (`src/engine/loader_route.cpp` / `src/runtime/craft/craft.cpp`, reached through
  `src/api/analysis.cpp`): the sample and the synthetic system modules are serialized
  into a v1 container, and the same snapshot pipeline the capture route uses executes
  it. The container carries the sample's Ldr entry and the module pages, so the
  attribution probe feeds the behavior tier and the repair verdict matches the
  capture route's shape (`complete` on the packed corpus). PE32 sample input is
  refused on these hosts with a named capture-class failure instead of entering the
  32-bit path. The construction route reads the module directory from
  `AnalysisOptions::run.synthetic_module_dir` (the CLI locates `synth_modules`
  next to the executable); an empty value is the missing-directory failure.
  `AnalysisOptions::input_kind` forces either route; forcing a route that
  contradicts the input fails rather than being second-guessed.
* `unpack_sample` exists on both platforms through those routes and delivers the same
  artifact shape (`.unp` + report + structured verdict); the executed world differs
  in module naming and address layout, so an event-stream comparison across hosts
  belongs to the same-container replay (`--from-snapshot`), not to two constructions.

## Licensing

sheller is GPL-2.0-only, the same license as unicorn
([LICENSE](../LICENSE)). Linking it into your product makes your product a work that
distributes GPL code, with the obligations that comes with - source availability,
license notice, and the questions around linking that are for your lawyers, not for
this file. Nothing here is legal advice; settle the compliance question before you
ship an embedded build, because it is a distribution decision, not a technical one.

## The C ABI question

There is no C interface today, and none is scheduled. If one comes it will be
**additive**: the six C++ entries stay as they are and a `extern "C"` layer of plain
structures is placed in front of them, forwarding. That future shape is the reason
for two choices you can see from here: the six signatures do not grow (no new
overloads, no defaulted parameters), and the failure classification in the result
types is meant to map one-to-one onto error codes. The known cost of routing that
layer through the existing entries is that internal errors and run errors share a
result kind, so a C layer would not distinguish them without extra work.

## Verifying a delivered build

The claims in this file are checked by the build, not by prose:

| What | Where |
| --- | --- |
| the package installs and a prefix-only consumer configures, builds and runs | [tests/install-consumer/](../tests/install-consumer) |
| the exported name set matches the checked-in list, both platforms | [tests/export_surface_gate.cmake](../tests/export_surface_gate.cmake) |
| the version a host can read equals the version `project()` declares | [tests/version_gate.cmake](../tests/version_gate.cmake) |
| no public header reaches a third-party header | the CI header-boundary step |
| the engine writes no host standard stream | [tests/engine_stdstream_gate.cmake](../tests/engine_stdstream_gate.cmake) |
| the engine carries no exception mechanism except its two delivery points | [tests/engine_nothrow_gate.cmake](../tests/engine_nothrow_gate.cmake) |
| a throwing sink loses that item and nothing else | `Log.ThrowingSinkDropsThatRecordAndNothingElse`, `GuestSinkGuard.*`, `SyscallRunGuestSink.*` |
