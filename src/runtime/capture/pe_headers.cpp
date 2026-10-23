#include "pe_headers.h"

#include <cstring>

namespace sheller::capture {

PeError parse_pe_headers(const std::uint8_t* data, const std::size_t size, PeImageInfo& info)
{
    if (size < sizeof(DosHeader)) {
        return PeError::kBufferTooSmall;
    }
    const auto& dos = *reinterpret_cast<const DosHeader*>(data);
    if (dos.e_magic != kMzSignature) {
        return PeError::kBufferTooSmall;
    }
    if (dos.e_lfanew < 0 || static_cast<std::uint64_t>(dos.e_lfanew) + sizeof(NtHeaders64) > size) {
        return PeError::kDosHeader;
    }
    const auto& nt = *reinterpret_cast<const NtHeaders64*>(data + dos.e_lfanew);
    if (nt.signature != kPeSignature) {
        return PeError::kNtHeader;
    }
    info.machine = nt.file_header.machine;
    if (info.machine == kMachineI386) {
        // PE32 x86 headers: smaller optional header with a 4-byte ImageBase
        if (dos.e_lfanew + sizeof(NtHeaders32) > size) {
            return PeError::kDosHeader;
        }
        const auto& nt32 = *reinterpret_cast<const NtHeaders32*>(data + dos.e_lfanew);
        if (nt32.optional_header.magic != kPe32Magic) {
            return PeError::kOptionalHeader;
        }
        info.bitness = 32;
        info.preferred_base = nt32.optional_header.image_base;
        info.entry_rva = nt32.optional_header.address_of_entry_point;
        if (nt32.optional_header.number_of_rva_and_sizes <= kTlsDirectoryIndex) {
            return PeError::kNone;
        }
        const DataDirectory& tls = nt32.optional_header.data_directory[kTlsDirectoryIndex];
        info.tls_directory_rva = tls.virtual_address;
        info.has_tls = tls.virtual_address != 0;
        return PeError::kNone;
    }
    if (info.machine != kMachineAmd64) {
        return PeError::kOptionalHeader;
    }
    if (nt.optional_header.magic != kPe32PlusMagic) {
        return PeError::kOptionalHeader;
    }
    info.bitness = 64;
    info.preferred_base = nt.optional_header.image_base;
    info.entry_rva = nt.optional_header.address_of_entry_point;
    if (nt.optional_header.number_of_rva_and_sizes <= kTlsDirectoryIndex) {
        return PeError::kNone;
    }
    const DataDirectory& tls = nt.optional_header.data_directory[kTlsDirectoryIndex];
    info.tls_directory_rva = tls.virtual_address;
    info.has_tls = tls.virtual_address != 0;
    return PeError::kNone;
}

std::string_view pe_error_message(const PeError error)
{
    switch (error) {
    case PeError::kNone:
        return "ok";
    case PeError::kBufferTooSmall:
        return "not a PE file (DOS header missing)";
    case PeError::kDosHeader:
        return "broken PE file (e_lfanew out of range)";
    case PeError::kNtHeader:
        return "broken PE file (PE signature missing)";
    case PeError::kOptionalHeader:
        return "not a PE32+ x64 image";
    }
    return "unknown PE parse error";
}

} // namespace sheller::capture
