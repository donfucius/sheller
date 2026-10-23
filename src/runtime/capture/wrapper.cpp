#include "wrapper.h"

#include <algorithm>
#include <cstring>
#include <string>

namespace sheller::capture {
namespace {

constexpr std::uint32_t kFileAlignment = 0x200;
constexpr std::uint32_t kSectionAlignment = 0x1000;
// Both layouts round the header block to one file-alignment unit, so the
// section raw data always starts here.
constexpr std::uint32_t kSectionHeaderOffsetX64 =
    0x148; // DOS40 + sig4 + COFF20 + opt240 (112 + 16*8 dirs)
constexpr std::uint32_t kSectionHeaderOffsetX86 =
    0x138; // DOS40 + sig4 + COFF20 + opt224 (96 + 16*8 dirs)
constexpr std::uint32_t kSizeOfHeaders = kFileAlignment;
constexpr std::uint32_t kSectionRva = kSectionAlignment;

constexpr std::uint16_t kMachineX64 = 0x8664;
constexpr std::uint16_t kMachineX86 = 0x014C;
constexpr std::uint16_t kOptionalHeaderMagicX64 = 0x020B;
constexpr std::uint16_t kOptionalHeaderMagicX86 = 0x010B;
constexpr std::uint32_t kSectionCharacteristics = 0x60000020; // CODE | EXECUTE | READ
constexpr std::uint16_t kImageCharacteristics = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

std::uint32_t align_up(const std::uint32_t value, const std::uint32_t alignment)
{
    return (value + alignment - 1) / alignment * alignment;
}

void store16(std::vector<std::uint8_t>& out, const std::size_t offset, const std::uint16_t value)
{
    out[offset] = static_cast<std::uint8_t>(value & 0xFF);
    out[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

void store32(std::vector<std::uint8_t>& out, const std::size_t offset, const std::uint32_t value)
{
    out[offset] = static_cast<std::uint8_t>(value & 0xFF);
    out[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    out[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    out[offset + 3] = static_cast<std::uint8_t>((value >> 24) & 0xFF);
}

} // namespace

std::string_view wrap_error_message(const WrapError error)
{
    switch (error) {
    case WrapError::kNone:
        return "ok";
    case WrapError::kEmptyBlob:
        return "shellcode blob is empty";
    case WrapError::kTooLarge:
        return "shellcode blob exceeds the wrapper capacity";
    case WrapError::kTempDirUnavailable:
        return "cannot resolve the host temporary directory";
    }
    return "unknown wrap error";
}

Status wrap_status(const WrapError error)
{
    return error == WrapError::kTempDirUnavailable ? Status::kCaptureFailed : Status::kNotX64Pe;
}

bool looks_like_pe(const std::span<const std::uint8_t> bytes)
{
    return bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z';
}

std::expected<std::vector<std::uint8_t>, WrapError>
wrap_blob(const WrapArch arch, const std::span<const std::uint8_t> blob)
{
    if (blob.empty()) {
        return std::unexpected(WrapError::kEmptyBlob);
    }
    if (blob.size() > kMaxBlobBytes) {
        return std::unexpected(WrapError::kTooLarge);
    }

    const bool is_x64 = arch == WrapArch::kX64;
    const auto blob_size = static_cast<std::uint32_t>(blob.size());
    const auto raw_size = align_up(blob_size, kFileAlignment);
    const auto image_size =
        kSectionRva + std::max(align_up(blob_size, kSectionAlignment), kSectionAlignment);

    std::vector<std::uint8_t> out;
    out.assign(kSizeOfHeaders + raw_size, 0);

    // DOS header: the classic minimal stub, e_lfanew points at 0x40.
    out[0] = 'M';
    out[1] = 'Z';
    store16(out, 0x02, 0x0003); // bytes on last page
    store16(out, 0x04, 0x0001); // pages in file
    store16(out, 0x0C, 0x0001); // header size in paragraphs
    store16(out, 0x18, 0x0040); // minimum allocation
    store32(out, 0x3C, 0x40);   // e_lfanew

    // PE signature + COFF file header.
    store32(out, 0x40, 0x00004550); // "PE\0\0"
    const std::size_t coff = 0x44;
    store16(out, coff + 0x00, is_x64 ? kMachineX64 : kMachineX86);
    store16(out, coff + 0x02, 1);                    // one section
    store32(out, coff + 0x08, 0);                    // time stamp: determinism
    store16(out, coff + 0x10, is_x64 ? 0xF0 : 0xE0); // SizeOfOptionalHeader
    store16(out, coff + 0x12, kImageCharacteristics);

    const std::size_t opt = coff + 0x14;
    // Optional header (PE32+ 0x70 / PE32 0xE0). PE32 diverges only in the
    // BaseOfData field, the ImageBase width and the 4-byte stack/heap sizes.
    store16(out, opt + 0x00, is_x64 ? kOptionalHeaderMagicX64 : kOptionalHeaderMagicX86);
    out[opt + 0x02] = 1;                   // major linker version
    store32(out, opt + 0x04, raw_size);    // SizeOfCode
    store32(out, opt + 0x10, kSectionRva); // AddressOfEntryPoint = section head
    store32(out, opt + 0x14, kSectionRva); // BaseOfCode
    if (is_x64) {
        store32(out, opt + 0x18, 0x00400000); // ImageBase (classic low base)
    } else {
        store32(out, opt + 0x18, kSectionRva); // BaseOfData (PE32 only)
        store32(out, opt + 0x1C, 0x00400000);  // ImageBase
    }
    store32(out, opt + 0x20, kSectionAlignment);
    store32(out, opt + 0x24, kFileAlignment);
    store16(out, opt + 0x28, 6); // OS version 6.0
    store16(out, opt + 0x2C, 0); // image version 0.0
    store16(out, opt + 0x30, 6); // subsystem version 6.0
    store32(out, opt + 0x34, 0); // Win32 version value
    store32(out, opt + 0x38, image_size);
    store32(out, opt + 0x3C, kSizeOfHeaders);
    store32(out, opt + 0x40, 0); // checksum: not verified for EXE images
    store16(out, opt + 0x44, 3); // subsystem: console
    store16(out, opt + 0x46, 0); // dll characteristics: no ASLR, no relocs
    if (is_x64) {
        store32(out, opt + 0x48, 0x00100000);
        store32(out, opt + 0x4C, 0); // stack reserve
        store32(out, opt + 0x50, 0x00001000);
        store32(out, opt + 0x54, 0); // stack commit
        store32(out, opt + 0x58, 0x00100000);
        store32(out, opt + 0x5C, 0); // heap reserve
        store32(out, opt + 0x60, 0x00001000);
        store32(out, opt + 0x64, 0);  // heap commit
        store32(out, opt + 0x68, 0);  // loader flags
        store32(out, opt + 0x6C, 16); // NumberOfRvaAndSizes
    } else {
        store32(out, opt + 0x48, 0x00100000); // stack reserve
        store32(out, opt + 0x4C, 0x00001000); // stack commit
        store32(out, opt + 0x50, 0x00100000); // heap reserve
        store32(out, opt + 0x54, 0x00001000); // heap commit
        store32(out, opt + 0x58, 0);          // loader flags
        store32(out, opt + 0x5C, 16);         // NumberOfRvaAndSizes
    }
    // data directories: all zero (no imports, no relocs, no exceptions table)

    // Section header: ".text", the blob rides here and the entry is its head.
    const std::size_t sec = is_x64 ? kSectionHeaderOffsetX64 : kSectionHeaderOffsetX86;
    std::memcpy(out.data() + sec, ".text", 5);
    store32(out, sec + 0x08, blob_size);      // VirtualSize
    store32(out, sec + 0x0C, kSectionRva);    // VirtualAddress
    store32(out, sec + 0x10, raw_size);       // SizeOfRawData
    store32(out, sec + 0x14, kSizeOfHeaders); // PointerToRawData
    store32(out, sec + 0x24, kSectionCharacteristics);
    store32(out, opt + 0x10, kSectionRva); // AddressOfEntryPoint = section head

    // Blob bytes right after the header block, zero padding to raw size.
    std::memcpy(out.data() + kSizeOfHeaders, blob.data(), blob.size());
    return out;
}

} // namespace sheller::capture
