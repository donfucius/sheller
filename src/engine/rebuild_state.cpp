#include "rebuild_state.h"

#include <cstdio>

namespace sheller::engine {

std::uint32_t protection_to_perms(const std::uint32_t protection)
{
    if ((protection & kPageGuard) != 0) {
        // The thread stack is captured as PAGE_GUARD|PAGE_READWRITE —
        // the kernel auto-commits those pages on touch without a visible
        // exception. Map them readable so reads work; writes still fault
        // WRITE_PROT into the ledger (and the write-prot grant flips the
        // page fully RW).
        if ((protection & kPageReadwrite) != 0) {
            return UC_PROT_READ;
        }
        return UC_PROT_NONE;
    }
    switch (protection & 0xFFu) {
    case kPageReadonly:
        return UC_PROT_READ;
    case kPageReadwrite:
    case kPageWritecopy:
        return UC_PROT_READ | UC_PROT_WRITE;
    case kPageExecute:
        return UC_PROT_EXEC;
    case kPageExecuteRead:
        return UC_PROT_READ | UC_PROT_EXEC;
    case kPageExecuteReadwrite:
    case kPageExecuteWritecopy:
        return UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC;
    default:
        return UC_PROT_NONE;
    }
}

std::string fold_name(std::string_view name)
{
    std::string out;
    for (const char c : name) {
        out.push_back(static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c));
    }
    return out;
}

// The one place the engine hands guest output bytes to a host callback: this
// trampoline is what syscalls::WriteSink's function pointer holds, and it is
// built exactly once (src/engine/syscall_dispatch.cpp:33), so guarding it covers
// every handler that writes guest output now and later.
//
// The host contract is that this callback does not throw
// (include/sheller/export.h). When it does, the write is dropped and the run
// continues. That is the same rule the log facade applies to a throwing sink
// (src/engine/log_state.cpp:write), applied at the other of the engine's two
// host-callback delivery points - one rule, two delivery points, not two rules.
//
// Three things this does NOT do, each a decision rather than an omission:
//   * it is not counted. A count needs an outlet, and every outlet costs more
//     than the number is worth here: a new out parameter changes one of the six
//     exported signatures, and the library logs nothing here for the reason
//     below. If observable dropped-byte counts are ever wanted, the extension
//     point is a per-run counter out of SyscallRunOptions, designed together
//     with the C-shaped out parameters, not a number invented in the trampoline.
//   * it is not echoed to stderr. The library writes no host standard stream at
//     any level - a rule with a gate on it
//     (tests/engine_stdstream_gate.cmake) - and a fallback print is exactly the
//     kind of exception that gate exists to catch.
//   * no log record is emitted about it. It would be technically possible (this
//     path is not the log's own broken-callback case), and it is still wrong:
//     emitting would take the log mutex on the guest's hot path, a host whose
//     write sink throws is a host whose log sink probably throws too, so the
//     record may not arrive, and above all it would make this drop look
//     different from the log facade's drop - which is the one thing the shared
//     rule above cannot survive.
//
// What the guest observes is nothing: the handler still returns STATUS_SUCCESS
// and the ledger still records the write, so the event stream and the run
// statistics are the same as if the callback had not thrown. Delivery into a
// sink is pure observation; no engine decision depends on it.
void sink_trampoline(void* const context, const std::uint8_t* data, const std::size_t size)
{
    auto& sink = *static_cast<std::function<void(const std::uint8_t*, std::size_t)>*>(context);
    // Empty means the guest output has no destination and the write costs
    // nothing (specs/syscall-policy's "empty = zero cost"). The test stays
    // outside the handler: it is not part of what the handler is there for, and
    // folding it in would hide the two different reasons this function has for
    // not calling.
    if (sink) {
        try {
            sink(data, size);
        } catch (...) {
            // Deliberately empty: dropping this write is the decision, above.
        }
    }
}

uc_mode guest_query_mode(uc_engine* const uc)
{
    size_t mode = UC_MODE_64;
    uc_query(uc, UC_QUERY_MODE, &mode);
    return static_cast<uc_mode>(mode);
}

std::uint64_t read_rip(uc_engine* const uc)
{
    if (guest_query_mode(uc) == UC_MODE_32) {
        std::uint32_t eip = 0;
        uc_reg_read(uc, UC_X86_REG_EIP, &eip);
        return eip;
    }
    std::uint64_t rip = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    return rip;
}

void write_rip(uc_engine* const uc, const std::uint64_t value)
{
    if (guest_query_mode(uc) == UC_MODE_32) {
        const auto eip = static_cast<std::uint32_t>(value);
        uc_reg_write(uc, UC_X86_REG_EIP, &eip);
        return;
    }
    uc_reg_write(uc, UC_X86_REG_RIP, &value);
}

std::uint64_t read_rsp(uc_engine* const uc)
{
    if (guest_query_mode(uc) == UC_MODE_32) {
        std::uint32_t esp = 0;
        uc_reg_read(uc, UC_X86_REG_ESP, &esp);
        return esp;
    }
    std::uint64_t rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    return rsp;
}

void write_rsp(uc_engine* const uc, const std::uint64_t value)
{
    if (guest_query_mode(uc) == UC_MODE_32) {
        const auto esp = static_cast<std::uint32_t>(value);
        uc_reg_write(uc, UC_X86_REG_ESP, &esp);
        return;
    }
    uc_reg_write(uc, UC_X86_REG_RSP, &value);
}

std::uint64_t read_guest_u64(uc_engine* const uc, const std::uint64_t address)
{
    std::uint64_t value = 0;
    uc_mem_read(uc, address, &value, sizeof value);
    return value;
}

std::uint32_t read_guest_u32(uc_engine* const uc, const std::uint64_t address)
{
    std::uint32_t value = 0;
    uc_mem_read(uc, address, &value, sizeof value);
    return value;
}

} // namespace sheller::engine
