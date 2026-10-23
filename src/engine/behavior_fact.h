// The engine->rules fact channel - internal only. The engine observes these
// facts inside its own hooks and hands them over as plain values; the rules
// layer never touches unicorn. A fact is not a delivery surface: the facade
// forwards the window facts into the event stream (mem-read / mem-write /
// sample-code), so nothing in the public headers names this type or offers a
// slot for it - the channel rides beside the public run options, never on
// them.

#ifndef SHELLER_ENGINE_BEHAVIOR_FACT_H
#define SHELLER_ENGINE_BEHAVIOR_FACT_H

#include <sheller/syscallrun.h>

#include <array>
#include <cstdint>
#include <expected>
#include <filesystem>
#include <functional>
#include <vector>

namespace sheller::engine {

// Pure-data facts for the behavior layer (only guest facts cross the seam).
struct BehaviorFact {
    enum class Kind : std::uint8_t {
        // addr/size/value read at pc: a read inside a monitored memory
        // window (TEB/PEB/KUSER/BeingDebugged pages); reads outside the
        // windows never cross this seam.
        kMemRead,
        // first-touch write of addr/size by pc: the fault-based write
        // ledger's per-page hook feeds it, so the cost stays O(pages).
        kMemWrite,
        // instruction bytes at pc inside a monitored code window. A
        // monitored code window is an address range the engine watches
        // per-instruction: the sample's own image span plus runtime
        // private-executable allocations - the regions where shellcode and
        // unpacked code self-locate (GetPC-class patterns live here).
        // Instructions in system modules (ntdll/kernel32, the bulk of any
        // run) stay outside every window and cost zero crossings.
        kCode,
        // protection result: base in addr, new protection in size, byte
        // size in aux
        kProtect,
        // cpuid leaf queried in aux (leaf value only; results answered by
        // the engine)
        kCpuidLeaf,
        // burn-loop fast-forward: a block cycle at pc spun aux iterations
        // with zero guest-visible writes and no syscalls, and the engine
        // forced its natural exit (pure-counter / clock-wait delay family)
        kLoopSkip,
    };
    Kind kind{};
    std::uint64_t pc{};   // faulting / querying rip (0 for cpuid)
    std::uint64_t addr{}; // read/write/protect base
    std::uint64_t aux{};  // read value; protect size; cpuid leaf
    std::uint32_t size{}; // read/write width; protect: new protection value
    // kMemWrite: true when the faulting writer is sample code (sample image or
    // a private-executable region). The forwarding layer carries it so the
    // report can keep system-code infrastructure writes out of the default
    // detail column.
    bool writer_sample_code{};
    // Code fact: the instruction bytes starting at pc.
    std::uint8_t length{};
    std::array<std::uint8_t, 15> bytes{};
};

// The fact seam's carrier: passed beside (not inside) the public run options,
// so SyscallRunOptions carries no fact slot at all. Empty = the engine
// registers none of the fact hooks (no monitored windows, no per-instruction
// crossings); the callback runs on hook hot paths and must not allocate or
// do IO.
struct FactChannel {
    std::function<void(const BehaviorFact&)> behavior_sink{};
};

namespace detail {

// The public run entries with the fact channel attached; the public entries
// in <sheller/syscallrun.h> delegate here with an empty channel.
std::expected<SyscallRunStats, SyscallRunFailure>
run_snapshot_syscalls_with_facts(const std::filesystem::path& snapshot_path,
                                 const SyscallRunOptions& options, const FactChannel& facts);
std::expected<SyscallRunStats, SyscallRunFailure>
run_snapshot_syscalls_with_facts(const std::vector<std::uint8_t>& snapshot,
                                 const SyscallRunOptions& options, const FactChannel& facts);
std::expected<SyscallRunStats, SyscallRunFailure>
run_pe_file_with_facts(const std::filesystem::path& pe_path, const SyscallRunOptions& options,
                       const FactChannel& facts);

} // namespace detail

} // namespace sheller::engine

#endif // SHELLER_ENGINE_BEHAVIOR_FACT_H
