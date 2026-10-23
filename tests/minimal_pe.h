// Synthetic minimal x64 PE the real Windows loader accepts: one RWX code
// section, zero imports, hand-crafted in code (no compiler, no checked-in
// binaries - synthetic samples first). The with_tls variant
// carries a TLS directory whose callback would set a marker byte, plus a
// .reloc section covering the TLS self-referencing pointers - the kernel may
// map the image anywhere, and the loader fixes those up before TLS data is
// touched. The capture path must keep the callback from ever running in the
// real process.

#pragma once

#include "pe_headers.h"

#include <array>
#include <cstdint>
#include <vector>

namespace sheller_test {

namespace capture = sheller::capture;

inline constexpr std::uint64_t kImageBase = 0x140000000;
inline constexpr std::uint32_t kTextRva = 0x1000;
inline constexpr std::uint32_t kEntryPointRva = 0x1000;
inline constexpr std::uint32_t kMarkerRva = 0x1100;
inline constexpr std::uint32_t kCallbackRva = 0x1200;
inline constexpr std::uint32_t kCallbacksArrayRva = 0x1210;
inline constexpr std::uint32_t kTlsIndexRva = 0x1220;
inline constexpr std::uint32_t kTlsDirectoryRva = 0x1240;
inline constexpr std::uint32_t kRelocRva = 0x3000;
inline constexpr std::size_t kPeFileSize = 0x4000;

// Mirror of IMAGE_SECTION_HEADER - only what the fixture needs to fill.
struct SectionHeader {
    std::uint8_t name[8];
    std::uint32_t virtual_size;
    std::uint32_t virtual_address;
    std::uint32_t size_of_raw_data;
    std::uint32_t pointer_to_raw_data;
    std::uint32_t pointer_to_relocations;
    std::uint32_t pointer_to_linenumbers;
    std::uint16_t number_of_relocations;
    std::uint16_t number_of_linenumbers;
    std::uint32_t characteristics;
};
static_assert(sizeof(SectionHeader) == 40);

// Mirror of one IMAGE_BASE_RELOCATION entry word: DIR64 type in the high
// nibble, page offset in the low 12 bits.
constexpr std::uint16_t reloc_entry(const std::uint32_t rva)
{
    return static_cast<std::uint16_t>(0xA000 | (rva & 0xFFF));
}

inline std::vector<std::uint8_t> make_minimal_pe(const bool with_tls)
{
    std::vector<std::uint8_t> image(kPeFileSize, std::uint8_t{0});
    auto* const base = image.data();
    const auto at = [&](const std::uint32_t rva) { return base + rva; };
    const auto write_qword = [&](const std::uint32_t rva, const std::uint64_t value) {
        for (unsigned i = 0; i < 8; ++i) {
            at(rva)[i] = static_cast<std::uint8_t>(value >> (8 * i));
        }
    };

    auto& dos = *reinterpret_cast<capture::DosHeader*>(base);
    dos.e_magic = capture::kMzSignature;
    dos.e_lfanew = 0x80;

    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(base + dos.e_lfanew);
    nt.signature = capture::kPeSignature;
    nt.file_header.machine = capture::kMachineAmd64;
    nt.file_header.number_of_sections = with_tls ? 2 : 1;
    nt.file_header.size_of_optional_header = sizeof(capture::OptionalHeader64);
    nt.file_header.characteristics = 0x0002; // IMAGE_FILE_EXECUTABLE_IMAGE

    auto& optional = nt.optional_header;
    optional.magic = capture::kPe32PlusMagic;
    optional.size_of_code = 0x1000;
    optional.address_of_entry_point = kEntryPointRva;
    optional.image_base = kImageBase;
    optional.section_alignment = 0x1000;
    optional.file_alignment = 0x1000;
    optional.major_operating_system_version = 6;
    optional.major_subsystem_version = 6;
    optional.size_of_image = 0x4000;
    optional.size_of_headers = 0x1000;
    optional.subsystem = 3; // console
    optional.number_of_rva_and_sizes = capture::kDataDirectoryCount;
    if (with_tls) {
        optional.data_directory[capture::kTlsDirectoryIndex] = capture::DataDirectory{
            .virtual_address = kTlsDirectoryRva, .size = sizeof(capture::TlsDirectory64)};
        optional.data_directory[5] = // IMAGE_DIRECTORY_ENTRY_BASERELOC
            capture::DataDirectory{.virtual_address = kRelocRva, .size = 28};
    }

    const auto write_section = [&](const unsigned index, const char* const name,
                                   const std::uint32_t rva, const std::uint32_t characteristics) {
        auto& header = *reinterpret_cast<SectionHeader*>(
            base + dos.e_lfanew + sizeof(capture::NtHeaders64) + index * sizeof(SectionHeader));
        header = SectionHeader{
            .name = {static_cast<std::uint8_t>(name[0]), static_cast<std::uint8_t>(name[1]),
                     static_cast<std::uint8_t>(name[2]), static_cast<std::uint8_t>(name[3]),
                     static_cast<std::uint8_t>(name[4]), 0, 0, 0},
            .virtual_size = 0x1000,
            .virtual_address = rva,
            .size_of_raw_data = 0x1000,
            .pointer_to_raw_data = rva,
            .pointer_to_relocations = 0,
            .pointer_to_linenumbers = 0,
            .number_of_relocations = 0,
            .number_of_linenumbers = 0,
            .characteristics = characteristics};
    };
    write_section(0, ".text", kTextRva, 0xE00000E0); // CODE | DATA | EXECUTE | READ | WRITE
    if (with_tls) {
        write_section(1, ".reloc", kRelocRva, 0x42000040); // INIT_DATA | READ | DISCARDABLE
    }

    // Entry: sixteen nops. The capture path patches the first two bytes into
    // the spin and saves these originals into the snapshot metadata.
    for (unsigned i = 0; i < 16; ++i) {
        at(kEntryPointRva)[i] = 0x90;
    }

    if (with_tls) {
        // Callback: mov byte ptr [rip + disp32], 1 ; ret (would set the marker)
        const auto marker_disp = static_cast<std::int32_t>(kMarkerRva - kCallbackRva - 7);
        at(kCallbackRva)[0] = 0xC6;
        at(kCallbackRva)[1] = 0x05;
        for (unsigned i = 0; i < 4; ++i) {
            at(kCallbackRva)[2 + i] = static_cast<std::uint8_t>(marker_disp >> (8 * i));
        }
        at(kCallbackRva)[6] = 0x01;
        at(kCallbackRva)[7] = 0xC3;

        write_qword(kCallbacksArrayRva, kImageBase + kCallbackRva);
        // the zero terminator right after the first entry stays zero
        write_qword(kTlsDirectoryRva, kImageBase + 0x1300);     // raw data start
        write_qword(kTlsDirectoryRva + 8, kImageBase + 0x1300); // raw data end
        write_qword(kTlsDirectoryRva + 16, kImageBase + kTlsIndexRva);
        write_qword(kTlsDirectoryRva + 24, kImageBase + kCallbacksArrayRva);
        // size_of_zero_fill and characteristics stay zero

        // Base relocations (DIR64) for every image-absolute pointer above:
        // the callback array entry and the four TLS directory fields. The
        // loader applies these before TLS data is initialized; at the capture
        // snapshot point they are NOT yet applied, which is why the capture
        // path relocates the callback pointer by the actual base delta.
        const auto write_u32 = [&](const std::uint32_t rva, const std::uint32_t value) {
            for (unsigned i = 0; i < 4; ++i) {
                at(rva)[i] = static_cast<std::uint8_t>(value >> (8 * i));
            }
        };
        const std::array<std::uint16_t, 6> entries = {
            reloc_entry(kCallbacksArrayRva),
            reloc_entry(kTlsDirectoryRva),
            reloc_entry(kTlsDirectoryRva + 8),
            reloc_entry(kTlsDirectoryRva + 16),
            reloc_entry(kTlsDirectoryRva + 24),
            0, // pad entry keeps the block 4-byte aligned
        };
        write_u32(kRelocRva, 0x1000); // block PageRVA
        write_u32(kRelocRva + 4, static_cast<std::uint32_t>(8 + 2 * entries.size()));
        for (unsigned i = 0; i < entries.size(); ++i) {
            at(kRelocRva + 8)[2 * i] = static_cast<std::uint8_t>(entries[i] & 0xFF);
            at(kRelocRva + 8)[2 * i + 1] = static_cast<std::uint8_t>(entries[i] >> 8);
        }
        // terminating block (PageRVA = 0, BlockSize = 0) stays zeroed
    }
    return image;
}

} // namespace sheller_test
