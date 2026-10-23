// Guest object families the syscall handlers play: sections (the object
// manager's section directory - KnownDLL resolution, pagefile and file-backed
// creates, view mapping) and files (host-backed file
// semantics). The dispatch site lives in the syscall dispatch TU.

#ifndef SHELLER_ENGINE_GUEST_OBJECTS_H
#define SHELLER_ENGINE_GUEST_OBJECTS_H

#include "rebuild_state.h"

#include <optional>

namespace sheller::engine {

// Section objects: declarations for the dispatch
// site - implementations sit with the interception helpers.
void apply_open_section(SyscallRunState& state, uc_engine* uc, const syscalls::SyscallFrame& frame,
                        syscalls::SyscallOutcome& outcome);
void apply_create_section(SyscallRunState& state, uc_engine* uc,
                          [[maybe_unused]] const syscalls::SyscallFrame& frame,
                          syscalls::SyscallOutcome& outcome);
void apply_map_view_of_section(SyscallRunState& state, uc_engine* uc,
                               [[maybe_unused]] const syscalls::SyscallFrame& frame,
                               syscalls::SyscallOutcome& outcome);

// Minimal file-object semantics. Resolve a guest
// OBJECT_ATTRIBUTES' ObjectName to a host filesystem path; returns nullopt
// when the name is unreadable or the host object is absent (the failure
// status rides the outcome). Existing directories - including DOS drive
// roots - resolve with directory=true: the real loader's DLL search-path
// iteration opens those probes to succeed.
struct ResolvedGuestPath {
    std::filesystem::path host;
    bool directory{};
};
std::optional<ResolvedGuestPath> resolve_guest_file_path(SyscallRunState& state, uc_engine* uc,
                                                         const std::uint64_t objattr,
                                                         syscalls::SyscallOutcome& outcome);
void apply_create_file(SyscallRunState& state, uc_engine* uc, const syscalls::SyscallFrame& frame,
                       syscalls::SyscallOutcome& outcome);
void apply_read_file(SyscallRunState& state, uc_engine* uc, const syscalls::SyscallFrame& frame,
                     syscalls::SyscallOutcome& outcome);
void apply_query_file(SyscallRunState& state, uc_engine* uc, const syscalls::SyscallFrame& frame,
                      syscalls::SyscallOutcome& outcome);
void apply_query_attributes(SyscallRunState& state, uc_engine* uc,
                            const syscalls::SyscallFrame& frame, syscalls::SyscallOutcome& outcome);

} // namespace sheller::engine

#endif // SHELLER_ENGINE_GUEST_OBJECTS_H
