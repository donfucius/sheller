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
    info.is_dll = (nt.file_header.characteristics & 0x2000) != 0; // IMAGE_FILE_DLL
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
    case PeError::kBadImports:
        return "broken PE file (import directory malformed)";
    }
    return "unknown PE parse error";
}

namespace {

std::uint32_t read_u32(const std::uint8_t* p)
{
    std::uint32_t v = 0;
    std::memcpy(&v, p, sizeof v);
    return v;
}

std::uint64_t read_u64(const std::uint8_t* p)
{
    std::uint64_t v = 0;
    std::memcpy(&v, p, sizeof v);
    return v;
}

// Section table walk for RVA -> file offset. Returns npos when the RVA is
// outside every section (callers treat that as malformed imports).
constexpr std::size_t kRvaUnmapped = static_cast<std::size_t>(-1);

std::size_t rva_to_offset(const std::uint8_t* data, const std::size_t size,
                          const std::int32_t e_lfanew, const bool pe32plus, const std::uint32_t rva)
{
    const auto& nt = *reinterpret_cast<const NtHeaders64*>(data + e_lfanew);
    const std::size_t opt_size = nt.file_header.size_of_optional_header;
    const std::size_t section_table = e_lfanew + 24 + opt_size;
    const std::uint16_t sections = nt.file_header.number_of_sections;
    const std::uint32_t headers_size =
        pe32plus
            ? reinterpret_cast<const NtHeaders64*>(data + e_lfanew)->optional_header.size_of_headers
            : reinterpret_cast<const NtHeaders32*>(data + e_lfanew)
                  ->optional_header.size_of_headers;
    if (rva < headers_size) {
        return rva; // header block: RVA == file offset
    }
    for (std::uint16_t i = 0; i < sections; ++i) {
        const std::size_t s = section_table + i * 40;
        if (s + 40 > size) {
            return kRvaUnmapped;
        }
        const std::uint32_t va = read_u32(data + s + 12);
        std::uint32_t span = read_u32(data + s + 8); // VirtualSize
        const std::uint32_t raw = read_u32(data + s + 16);
        const std::uint32_t ptr = read_u32(data + s + 20);
        if (span == 0 || span > raw) {
            span = raw; // slack in VirtualSize: bound by the raw extent
        }
        if (rva >= va && rva < va + span) {
            const std::size_t offset = ptr + (rva - va);
            return offset < size ? offset : kRvaUnmapped;
        }
    }
    return kRvaUnmapped;
}

constexpr std::size_t kMaxImportModules = 64;
constexpr std::size_t kMaxThunksPerModule = 512;

} // namespace

PeError parse_imports(const std::uint8_t* data, const std::size_t size,
                      std::vector<PeImportThunk>& out)
{
    out.clear();
    if (size < sizeof(DosHeader)) {
        return PeError::kBufferTooSmall;
    }
    const auto& dos = *reinterpret_cast<const DosHeader*>(data);
    if (dos.e_magic != kMzSignature) {
        return PeError::kBufferTooSmall;
    }
    if (dos.e_lfanew < 0 || static_cast<std::uint64_t>(dos.e_lfanew) + sizeof(NtHeaders32) > size) {
        return PeError::kDosHeader;
    }
    const auto& nt = *reinterpret_cast<const NtHeaders64*>(data + dos.e_lfanew);
    if (nt.signature != kPeSignature) {
        return PeError::kNtHeader;
    }
    const bool pe32plus = nt.file_header.machine == kMachineAmd64;
    if (!pe32plus && nt.file_header.machine != kMachineI386) {
        return PeError::kOptionalHeader;
    }
    const std::size_t dir_base = dos.e_lfanew + 24 + (pe32plus ? 112 : 96); // data directories
    if (dir_base + 16 > size) {
        return PeError::kBadImports;
    }
    const std::uint32_t import_rva = read_u32(data + dir_base + 8); // directory[1]
    if (import_rva == 0) {
        return PeError::kNone; // no imports is a valid shape
    }
    const std::size_t thunk_width = pe32plus ? 8 : 4;
    for (std::size_t d = 0; d < kMaxImportModules; ++d) {
        const std::size_t desc = rva_to_offset(data, size, dos.e_lfanew, pe32plus,
                                               import_rva + static_cast<std::uint32_t>(d * 20));
        if (desc == kRvaUnmapped || desc + 20 > size) {
            return PeError::kBadImports;
        }
        const std::uint32_t name_rva = read_u32(data + desc + 12);
        if (read_u32(data + desc) == 0 && name_rva == 0) {
            return PeError::kNone; // terminator
        }
        const std::size_t name_off = rva_to_offset(data, size, dos.e_lfanew, pe32plus, name_rva);
        if (name_off == kRvaUnmapped) {
            return PeError::kBadImports;
        }
        std::string module;
        for (std::size_t i = name_off; i < size && data[i] != 0 && module.size() < 64; ++i) {
            module.push_back(static_cast<char>(data[i]));
        }
        std::uint32_t thunk_rva = read_u32(data + desc); // OriginalFirstThunk
        if (thunk_rva == 0) {
            thunk_rva = read_u32(data + desc + 16); // fall back to FirstThunk
        }
        for (std::size_t t = 0; t < kMaxThunksPerModule; ++t) {
            const std::size_t thunk_off =
                rva_to_offset(data, size, dos.e_lfanew, pe32plus,
                              thunk_rva + static_cast<std::uint32_t>(t * thunk_width));
            if (thunk_off == kRvaUnmapped || thunk_off + thunk_width > size) {
                // The RVA mapped but the slot runs past the host buffer: a
                // truncated file would turn the read into an overread.
                return PeError::kBadImports;
            }
            const std::uint64_t value =
                pe32plus ? read_u64(data + thunk_off) : read_u32(data + thunk_off);
            if (value == 0) {
                break; // thunk terminator
            }
            const bool by_ordinal =
                pe32plus ? (value & 0x8000000000000000ull) != 0 : (value & 0x80000000ull) != 0;
            PeImportThunk thunk;
            thunk.module = module;
            if (by_ordinal) {
                thunk.ordinal = static_cast<std::uint16_t>(value & 0xFFFF);
            } else {
                const std::size_t hint_off = rva_to_offset(data, size, dos.e_lfanew, pe32plus,
                                                           static_cast<std::uint32_t>(value));
                if (hint_off == kRvaUnmapped || hint_off + 2 >= size) {
                    return PeError::kBadImports;
                }
                for (std::size_t i = hint_off + 2;
                     i < size && data[i] != 0 && thunk.name.size() < 128; ++i) {
                    thunk.name.push_back(static_cast<char>(data[i]));
                }
                if (thunk.name.empty()) {
                    return PeError::kBadImports;
                }
            }
            out.push_back(std::move(thunk));
        }
    }
    return PeError::kNone;
}

} // namespace sheller::capture
