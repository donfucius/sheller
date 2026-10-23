// Loader route public entry: run a PE
// file through the built-in loader - address-space construction, section
// copy, relocations, TLS callbacks - and the standard syscall run loop.
// Symmetric with run_snapshot_syscalls: budgets, timeout, dump and behavior
// seams are the same structures.

#ifndef SHELLER_PELOADER_H
#define SHELLER_PELOADER_H

#include <sheller/syscallrun.h>

#include <filesystem>

namespace sheller::engine {

std::expected<SyscallRunStats, SyscallRunFailure> run_pe_file(const std::filesystem::path& pe_path,
                                                              const SyscallRunOptions& options);

} // namespace sheller::engine

#endif // SHELLER_PELOADER_H
