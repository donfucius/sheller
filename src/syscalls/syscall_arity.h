// Nt signature arity: form-parameter counts per Nt
// function name, generated from the same manifest as the behavior layer's
// description table (counts and names cannot drift independently - an
// invariant test pins it). The dispatch-time decoded tier consults this;
// unknown names fall back to the raw four-register tier.

#ifndef SHELLER_SYSCALLS_ARITY_H
#define SHELLER_SYSCALLS_ARITY_H

#include <cstdint>
#include <optional>
#include <string_view>

namespace sheller::syscalls {

// Form-parameter count for an Nt function name ("NtCreateFile" -> 11);
// nullopt when the name is not in the generated table.
std::optional<std::uint32_t> nt_arg_count(std::string_view name);

} // namespace sheller::syscalls

#endif // SHELLER_SYSCALLS_ARITY_H
