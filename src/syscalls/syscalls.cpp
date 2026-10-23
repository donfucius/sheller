// Syscalls module placeholder: guest syscall interception and policy table.

#include <string_view>

namespace sheller::syscalls {

std::string_view module_name()
{
    return "syscalls";
}

} // namespace sheller::syscalls
