// Win32 -> Nt layer-name equivalents: the interception
// layer consults this to re-emit a synthetic zero-record kSyscall alongside
// the apicall, so the loader route's Nt timeline matches what the snapshot
// route would observe. Pure data; the behavior layer re-exports the same
// pairs for presentation.

#ifndef SHELLER_SYSCALLS_WIN32_NT_EQUIVALENCE_H
#define SHELLER_SYSCALLS_WIN32_NT_EQUIVALENCE_H

#include <optional>
#include <string_view>

namespace sheller::syscalls {

// The Nt-layer equivalent for a Win32 export name ("VirtualAlloc" ->
// "NtAllocateVirtualMemory"); nullopt when no equivalence is recorded.
std::optional<std::string_view> win32_nt_equivalent(std::string_view win32_name);

} // namespace sheller::syscalls

#endif // SHELLER_SYSCALLS_WIN32_NT_EQUIVALENCE_H
