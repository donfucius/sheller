#include "syscall_number_map.h"

#include <unicorn/unicorn.h>

#include <cstring>
#include <string_view>
#include <utility>

namespace sheller::syscalls {
namespace {

// Minimal in-image PE header access: the offsets mirror winnt.h positions
// already pinned by the capture module's pe_headers.h; self-drawn here so
// the syscalls module keeps its own portable minimum. The export directory
// is DataDirectory[0].
constexpr std::size_t kELfanewOffset = 0x3C;
constexpr std::size_t kOptionalHeaderOffset = 24;
constexpr std::size_t kMagicOffset = 0;
constexpr std::size_t kExportDirectoryOffset = 0x70;
constexpr std::size_t kExportDirSizeOffset = 0x74;
constexpr std::size_t kNumberOfFunctionsOffset = 0x14;
constexpr std::size_t kNumberOfNamesOffset = 0x18;
constexpr std::size_t kAddressOfFunctionsOffset = 0x1C;
constexpr std::size_t kAddressOfNamesOffset = 0x20;
constexpr std::size_t kAddressOfNameOrdinalsOffset = 0x24;
constexpr std::uint32_t kPeSignature = 0x00004550;
constexpr std::uint16_t kPe32PlusMagic = 0x20B;
constexpr std::uint16_t kPe32Magic = 0x10B;
constexpr std::size_t kDataDirectoryOffset64 = 0x70; // optional+0x70 (PE32+)
constexpr std::size_t kDataDirectoryOffset32 = 0x60; // optional+0x60 (PE32)
constexpr std::size_t kMaxExportNames = 8192;
constexpr std::size_t kMaxExportNameLength = 63;

std::uint16_t read_guest_u16(uc_engine* const uc, const std::uint64_t address)
{
    std::uint16_t value = 0;
    uc_mem_read(uc, address, &value, sizeof value);
    return value;
}

std::uint32_t read_guest_u32(uc_engine* const uc, const std::uint64_t address)
{
    std::uint32_t value = 0;
    uc_mem_read(uc, address, &value, sizeof value);
    return value;
}

// One bounded read with the NUL inside the window; export names are short.
bool read_guest_c_string(uc_engine* const uc, const std::uint64_t address,
                         std::array<char, kExportNameBytes>& out)
{
    std::array<char, kExportNameBytes> bytes{};
    if (uc_mem_read(uc, address, bytes.data(), bytes.size()) != UC_ERR_OK) {
        return false;
    }
    bytes[bytes.size() - 1] = '\0';
    out = bytes;
    return true;
}

} // namespace

std::vector<ExportedFunction> enumerate_exports(uc_engine* const uc,
                                                const std::uint64_t module_base)
{
    std::vector<ExportedFunction> exports;
    const auto pe_offset = read_guest_u32(uc, module_base + kELfanewOffset);
    if (read_guest_u32(uc, module_base + pe_offset) != kPeSignature) {
        return exports;
    }
    const auto optional = module_base + pe_offset + kOptionalHeaderOffset;
    const auto magic = read_guest_u16(uc, optional + kMagicOffset);
    if (magic != kPe32PlusMagic && magic != kPe32Magic) {
        return exports;
    }
    // the export directory itself is identically shaped; only its slot
    // position in the optional header differs
    const auto dir_offset =
        magic == kPe32PlusMagic ? kDataDirectoryOffset64 : kDataDirectoryOffset32;
    const auto export_rva = read_guest_u32(uc, optional + dir_offset);
    const auto export_size = read_guest_u32(uc, optional + dir_offset + 4);
    if (export_rva == 0 || export_size == 0) {
        return exports;
    }
    const auto functions_va =
        read_guest_u32(uc, module_base + export_rva + kAddressOfFunctionsOffset);
    const auto names_va = read_guest_u32(uc, module_base + export_rva + kAddressOfNamesOffset);
    const auto ordinals_va =
        read_guest_u32(uc, module_base + export_rva + kAddressOfNameOrdinalsOffset);
    const auto number_of_names =
        read_guest_u32(uc, module_base + export_rva + kNumberOfNamesOffset);

    const auto bounded_names =
        number_of_names < kMaxExportNames ? number_of_names : kMaxExportNames;
    exports.reserve(bounded_names);
    for (std::uint32_t i = 0; i < bounded_names; ++i) {
        const auto name_rva = read_guest_u32(uc, module_base + names_va + 4 * i);
        if (name_rva == 0) {
            continue;
        }
        const auto ordinal = read_guest_u16(uc, module_base + ordinals_va + 2 * i);
        const auto function_rva = read_guest_u32(uc, module_base + functions_va + 4ULL * ordinal);
        if (function_rva == 0 ||
            (function_rva >= export_rva && function_rva < export_rva + export_size)) {
            continue; // forwarder: not callable code in this image
        }
        ExportedFunction entry;
        entry.address = module_base + function_rva;
        entry.slot_va = module_base + functions_va + 4ULL * ordinal;
        if (!read_guest_c_string(uc, module_base + name_rva, entry.name)) {
            continue;
        }
        exports.push_back(std::move(entry));
    }
    return exports;
}

std::optional<std::uint32_t> syscall_stub_number(uc_engine* const uc,
                                                 const std::uint64_t function_va)
{
    std::array<std::uint8_t, 16> bytes{};
    if (uc_mem_read(uc, function_va, bytes.data(), bytes.size()) != UC_ERR_OK) {
        return std::nullopt;
    }
    // Canonical Win10+ x64 ntdll stub: mov r10, rcx; mov eax, imm32; syscall.
    static constexpr std::array<std::uint8_t, 4> kStubPrefix{0x4C, 0x8B, 0xD1, 0xB8};
    if (bytes[0] == kStubPrefix[0] && bytes[1] == kStubPrefix[1] && bytes[2] == kStubPrefix[2] &&
        bytes[3] == kStubPrefix[3]) {
        return static_cast<std::uint32_t>(bytes[4]) | (static_cast<std::uint32_t>(bytes[5]) << 8) |
               (static_cast<std::uint32_t>(bytes[6]) << 16) |
               (static_cast<std::uint32_t>(bytes[7]) << 24);
    }
    // x86 wow64 ntdll stub: mov eax, imm32; mov edx, transition; call edx.
    // The number sits at +1; the wow64 call pattern (BA..FF D2) keeps the
    // match off plain `mov eax` code.
    if (bytes[0] == 0xB8 && bytes[5] == 0xBA && bytes[10] == 0xFF && bytes[11] == 0xD2) {
        return static_cast<std::uint32_t>(bytes[1]) | (static_cast<std::uint32_t>(bytes[2]) << 8) |
               (static_cast<std::uint32_t>(bytes[3]) << 16) |
               (static_cast<std::uint32_t>(bytes[4]) << 24);
    }
    // x86 wow64 base-check stub: mov eax, imm32; call $+0; pop edx; cmp byte
    // [edx+0x14], 0x4b — NtQueryInformationProcess's family carries its own
    // preferred-base check before reaching the transition. Number at +1.
    if (bytes[0] == 0xB8 && bytes[5] == 0xE8 && bytes[10] == 0x5A && bytes[11] == 0x80 &&
        bytes[12] == 0x7A && bytes[14] == 0x4B) {
        return static_cast<std::uint32_t>(bytes[1]) | (static_cast<std::uint32_t>(bytes[2]) << 8) |
               (static_cast<std::uint32_t>(bytes[3]) << 16) |
               (static_cast<std::uint32_t>(bytes[4]) << 24);
    }
    return std::nullopt;
}

std::optional<std::uint64_t> resolve_export(uc_engine* const uc, const std::uint64_t module_base,
                                            const std::string_view name)
{
    for (const auto& export_entry : enumerate_exports(uc, module_base)) {
        if (name == std::string_view(export_entry.name.data())) {
            return export_entry.address;
        }
    }
    return std::nullopt;
}

std::vector<SyscallNumberEntry> enumerate_ntdll_syscalls(uc_engine* const uc,
                                                         const std::uint64_t ntdll_base)
{
    std::vector<SyscallNumberEntry> entries;
    for (const auto& export_entry : enumerate_exports(uc, ntdll_base)) {
        const auto name = std::string_view(export_entry.name.data());
        if (name.size() < 3 || name.substr(0, 2) != "Nt") {
            continue;
        }
        if (const auto number = syscall_stub_number(uc, export_entry.address); number.has_value()) {
            SyscallNumberEntry item;
            item.number = *number;
            std::memcpy(item.name.data(), export_entry.name.data(), kExportNameBytes);
            entries.push_back(std::move(item));
        }
    }
    return entries;
}
} // namespace sheller::syscalls
