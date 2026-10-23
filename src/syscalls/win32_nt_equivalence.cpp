#include "win32_nt_equivalence.h"

#include <algorithm>
#include <array>
#include <utility>

namespace sheller::syscalls {
namespace {

constexpr std::array<std::pair<std::string_view, std::string_view>, 10> kEquivalents{{
    {"VirtualAlloc", "NtAllocateVirtualMemory"},
    {"VirtualProtect", "NtProtectVirtualMemory"},
    {"VirtualFree", "NtFreeVirtualMemory"},
    {"LoadLibraryA", "LdrLoadDll"},
    {"LoadLibraryW", "LdrLoadDll"},
    {"CreateFileA", "NtCreateFile"},
    {"CreateFileW", "NtCreateFile"},
    {"ReadFile", "NtReadFile"},
    {"WriteFile", "NtWriteFile"},
    {"ExitProcess", "NtTerminateProcess"},
}};

} // namespace

std::optional<std::string_view> win32_nt_equivalent(const std::string_view win32_name)
{
    const auto it = std::find_if(kEquivalents.begin(), kEquivalents.end(),
                                 [&](const auto& pair) { return pair.first == win32_name; });
    if (it == kEquivalents.end()) {
        return std::nullopt;
    }
    return it->second;
}

} // namespace sheller::syscalls
