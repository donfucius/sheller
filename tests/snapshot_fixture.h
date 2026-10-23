// Crafted in-memory snapshots for the tests that drive the engine entry directly:
// one RWX image page carrying the guest code, a stack page and a TEB page, with the
// entry's first bytes duplicated into the metadata the run restores before executing.
// Lifted verbatim from tests/analysis_facade_test.cpp, which was the only owner of it,
// so the trace-routing test can drive the same guest code rather than a second
// approximation of it. The addresses are the fixture's contract: the engine restores
// original_entry_bytes at the entry, so the code has to be what those bytes say.
#pragma once

#include <sheller/snapshot.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <span>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace sheller_test {

namespace snapshot = sheller::snapshot;

constexpr std::uint32_t kPageReadwrite = 0x04;
constexpr std::uint32_t kPageExecuteReadwrite = 0x40;
constexpr std::uint32_t kMemImage = 0x1000000;
constexpr std::uint32_t kMemPrivate = 0x20000;

constexpr std::uint64_t kImageBase = 0x00400000;
constexpr std::uint64_t kStackRegionBase = 0x07F00000;
constexpr std::uint64_t kStackVa = kStackRegionBase + 0x800;
constexpr std::size_t kRegionSize = 0x1000;

constexpr std::uint64_t kEflagsReservedOne = 1U << 1;
constexpr std::uint64_t kEflagsParity = 1U << 2;
constexpr std::uint64_t kEflagsZero = 1U << 6;
constexpr std::uint64_t kEflagsInterruptEnable = 1U << 9;
constexpr std::uint64_t kFixtureRflags =
    kEflagsReservedOne | kEflagsParity | kEflagsZero | kEflagsInterruptEnable;

// mov rcx, -1 ; mov rdx, 0x1234 ; mov eax, 0x1002 (NtTerminateProcess) ;
// syscall - the guest-contract terminate: rcx=-1 ends the replay, rdx is
// the exit code.
constexpr std::array<std::uint8_t, 21> kTerminateCode{0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,
                                                      0x48, 0xC7, 0xC2, 0x34, 0x12, 0x00, 0x00,
                                                      0xB8, 0x02, 0x10, 0x00, 0x00, 0x0F, 0x05};

// The write fixture: NtWriteFile (0x1000) with Buffer at [rsp+0x30] and
// Length at [rsp+0x38] (the builtin's stack-argument contract), then the
// terminate sequence.
constexpr std::uint64_t kBufferVa = kImageBase + 0x800;
constexpr std::array<std::uint8_t, 54> kWriteCode{
    0x48, 0xB8, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, kBufferVa
    0x48, 0x89, 0x44, 0x24, 0x30,                               // mov [rsp+0x30], rax
    0x48, 0xC7, 0x44, 0x24, 0x38, 0x03, 0x00, 0x00, 0x00,       // mov qword [rsp+0x38], 3
    0xB8, 0x00, 0x10, 0x00, 0x00,                               // mov eax, 0x1000
    0x0F, 0x05,                                                 // syscall
    0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,                   // mov rcx, -1
    0x48, 0xC7, 0xC2, 0x34, 0x12, 0x00, 0x00,                   // mov rdx, 0x1234
    0xB8, 0x02, 0x10, 0x00, 0x00,                               // mov eax, 0x1002
    0x0F, 0x05};                                                // syscall

// Two NtWriteFile calls before the terminate, from two buffers 0x20 apart in the
// same page. The single-write fixture above cannot show ordering - one chunk
// arrives whatever the delivery order - so this is the sequence the sink case
// below asserts against.
constexpr std::array<std::uint8_t, 83> kTwoWriteCode{
    0x48, 0xB8, 0x00, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, kBufferVa
    0x48, 0x89, 0x44, 0x24, 0x30,                               // mov [rsp+0x30], rax
    0x48, 0xC7, 0x44, 0x24, 0x38, 0x02, 0x00, 0x00, 0x00,       // mov qword [rsp+0x38], 2
    0xB8, 0x00, 0x10, 0x00, 0x00,                               // mov eax, 0x1000
    0x0F, 0x05,                                                 // syscall
    0x48, 0xB8, 0x20, 0x08, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, kBufferVa + 0x20
    0x48, 0x89, 0x44, 0x24, 0x30,                               // mov [rsp+0x30], rax
    0x48, 0xC7, 0x44, 0x24, 0x38, 0x03, 0x00, 0x00, 0x00,       // mov qword [rsp+0x38], 3
    0xB8, 0x00, 0x10, 0x00, 0x00,                               // mov eax, 0x1000
    0x0F, 0x05,                                                 // syscall
    0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF,                   // mov rcx, -1
    0x48, 0xC7, 0xC2, 0x34, 0x12, 0x00, 0x00,                   // mov rdx, 0x1234
    0xB8, 0x02, 0x10, 0x00, 0x00,                               // mov eax, 0x1002
    0x0F, 0x05};                                                // syscall

// "ab" at kBufferVa, "ok\n" at kBufferVa + 0x20.
std::vector<std::uint8_t> two_write_buffer()
{
    std::vector<std::uint8_t> buffer(0x20 + 3, std::uint8_t{0});
    buffer[0] = 'a';
    buffer[1] = 'b';
    buffer[0x20] = 'o';
    buffer[0x21] = 'k';
    buffer[0x22] = '\n';
    return buffer;
}

snapshot::Registers fixture_registers(const std::uint64_t entry_va)
{
    snapshot::Registers registers{};
    registers.gpr[static_cast<std::size_t>(snapshot::Gpr::kRsp)] = kStackVa;
    registers.rip = entry_va;
    registers.rflags = kFixtureRflags;
    return registers;
}

snapshot::Metadata fixture_metadata(const std::uint64_t entry_va)
{
    snapshot::Metadata metadata{};
    metadata.peb_address = 0x07F20000; // unmapped: the Ldr walk truncates, the
                                       // attribution probe still succeeds with
                                       // an empty module set
    metadata.teb_address = 0x07F10100;
    metadata.image_base = kImageBase;
    metadata.entry_address = entry_va;
    return metadata;
}

// Serializes a crafted snapshot: an RWX image page at kImageBase carrying
// the code, a stack page and a TEB page. The entry's first 16 bytes ride
// original_entry_bytes - the run restores them before executing, so they
// must carry the code start, not zeros.
std::vector<std::uint8_t> craft_snapshot(const std::vector<std::uint8_t>& code,
                                         const std::vector<std::uint8_t>& buffer = {})
{
    std::vector<std::uint8_t> page(kRegionSize, std::uint8_t{0});
    std::copy(code.begin(), code.end(), page.begin());
    if (!buffer.empty()) {
        std::copy(buffer.begin(), buffer.end(), page.begin() + (kBufferVa - kImageBase));
    }
    std::vector<std::uint8_t> stack(kRegionSize, std::uint8_t{0x5A});
    std::vector<std::uint8_t> teb(kRegionSize, std::uint8_t{0});

    auto metadata = fixture_metadata(kImageBase);
    std::copy_n(page.begin(), metadata.original_entry_bytes.size(),
                metadata.original_entry_bytes.begin());

    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(
            snapshot::Header{.version = snapshot::kVersion, .bitness = snapshot::kBitness64}) ||
        !writer.write_registers(fixture_registers(kImageBase)) ||
        !writer.write_metadata(metadata) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kImageBase,
                                                    .size = kRegionSize,
                                                    .protection = kPageExecuteReadwrite,
                                                    .type = kMemImage,
                                                    .content = snapshot::kContentPresent},
                             page.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kStackRegionBase,
                                                    .size = kRegionSize,
                                                    .protection = kPageReadwrite,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             stack.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = 0x07F10000,
                                                    .size = kRegionSize,
                                                    .protection = kPageReadwrite,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             teb.data()) ||
        !writer.finalize_region_count()) {
        EXPECT_TRUE(false) << "crafted snapshot serialization failed";
    }
    const auto str = out.str();
    return {str.begin(), str.end()};
}

// Built on first use (not at static-init time): the serializer reports
// failures through gtest expectations.
const std::vector<std::uint8_t>& terminate_snapshot()
{
    static const std::vector<std::uint8_t> bytes =
        craft_snapshot({kTerminateCode.begin(), kTerminateCode.end()});
    return bytes;
}

const std::vector<std::uint8_t>& write_snapshot_bytes()
{
    static const std::vector<std::uint8_t> bytes =
        craft_snapshot({kWriteCode.begin(), kWriteCode.end()}, {'h', 'i', '\n'});
    return bytes;
}

const std::vector<std::uint8_t>& two_write_snapshot_bytes()
{
    static const std::vector<std::uint8_t> bytes =
        craft_snapshot({kTwoWriteCode.begin(), kTwoWriteCode.end()}, two_write_buffer());
    return bytes;
}

// Two-section xfer fixture: .text runs a counter loop that stores to the
// stack (the guest-visible write keeps the burn-loop probe from
// fast-forwarding the delay), then jumps into text2. The jump is the only
// identity transition, so this snapshot has exactly one xfer target and the
// landing block is the terminate sequence in text2.
//
// The iteration count is load-bearing for the mid-leg wall-clock cases. The
// store makes the probe admit the loop as compute and re-arm its trigger x4
// (8000 -> 32000 -> 128000 -> 512000), so the delay is cut into four legs and
// the transfer lands in the fourth; those legs all leave ahead of the
// leg-boundary clock check, which is what leaves the finish-time
// recomputation as the run's only clock reading. Raising the count so that the
// iterations left after the last re-arm exceed one leg (1M instructions, three
// per iteration here) would let a leg run to its full count, reach that
// boundary check, and flip the case to a timeout.
constexpr std::uint64_t kXferImageSize = 0x3000;
constexpr std::uint32_t kXferTextRva = 0x1000;
constexpr std::uint32_t kXferText2Rva = 0x2000;
constexpr std::uint64_t kXferTextVa = kImageBase + kXferTextRva;
constexpr std::uint64_t kXferText2Va = kImageBase + kXferText2Rva;

inline void put_u16(std::vector<std::uint8_t>& bytes, const std::size_t offset,
                    const std::uint16_t value)
{
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFF);
    bytes[offset + 1] = static_cast<std::uint8_t>(value >> 8);
}

inline void put_u32(std::vector<std::uint8_t>& bytes, const std::size_t offset,
                    const std::uint32_t value)
{
    bytes[offset] = static_cast<std::uint8_t>(value & 0xFF);
    bytes[offset + 1] = static_cast<std::uint8_t>((value >> 8) & 0xFF);
    bytes[offset + 2] = static_cast<std::uint8_t>((value >> 16) & 0xFF);
    bytes[offset + 3] = static_cast<std::uint8_t>(value >> 24);
}

inline void put_u64(std::vector<std::uint8_t>& bytes, const std::size_t offset,
                    const std::uint64_t value)
{
    for (std::size_t byte = 0; byte < 8; ++byte) {
        bytes[offset + byte] = static_cast<std::uint8_t>(value >> (8 * byte));
    }
}

// One section of the crafted images: a name and the RVA it maps to. Every
// section here is a single aligned page of readable executable code, so the
// virtual size and the characteristics are not parameters.
struct PeSection {
    std::string_view name;
    std::uint32_t rva;
};

// The headers of a crafted image fit in one page. A caller that only needs the
// headers of a hand-mapped image slices this much off craft_pe_image's result.
constexpr std::size_t kPeHeadersPageSize = 0x1000;

// A minimal PE32+ image whose section table names each given section, so the
// attribution map refines the code spans to distinct sections. Callers that
// need runnable guest code write it into the section spans afterwards.
inline std::vector<std::uint8_t> craft_pe_image(const std::uint64_t image_base,
                                                const std::uint64_t image_size,
                                                const std::uint32_t entry_rva,
                                                std::span<const PeSection> sections)
{
    std::vector<std::uint8_t> image(static_cast<std::size_t>(image_size), std::uint8_t{0});
    image[0] = 'M';
    image[1] = 'Z';
    put_u32(image, 0x3C, 0x40); // e_lfanew
    put_u32(image, 0x40, 0x00004550);
    put_u16(image, 0x44, 0x8664); // machine: x64
    put_u16(image, 0x46, static_cast<std::uint16_t>(sections.size()));
    put_u16(image, 0x54, 0xF0); // optional-header bytes
    constexpr std::size_t kOptional = 0x58;
    put_u16(image, kOptional, 0x020B); // PE32+
    put_u32(image, kOptional + 16, entry_rva);
    put_u64(image, kOptional + 24, image_base);
    put_u32(image, kOptional + 32, 0x1000); // section alignment
    put_u32(image, kOptional + 36, 0x200);  // file alignment
    put_u32(image, kOptional + 56, static_cast<std::uint32_t>(image_size));
    put_u32(image, kOptional + 60, 0x200); // size of headers
    put_u16(image, kOptional + 68, 3);     // console subsystem
    constexpr std::size_t kSectionTable = kOptional + 0xF0;
    for (std::size_t index = 0; index < sections.size(); ++index) {
        const std::size_t at = kSectionTable + index * 40;
        const auto name = sections[index].name;
        std::copy(name.begin(), name.end(), image.begin() + static_cast<std::ptrdiff_t>(at));
        put_u32(image, at + 8, 0x1000); // virtual size: one page
        put_u32(image, at + 12, sections[index].rva);
        put_u32(image, at + 16, 0x1000); // raw size
        put_u32(image, at + 20, sections[index].rva);
        put_u32(image, at + 36, 0x60000020); // code | execute | read
    }
    return image;
}

// The xfer fixture's image: .text carries the delay loop, text2 the landing
// block that the stop must not let execute.
inline std::vector<std::uint8_t> xfer_image()
{
    constexpr std::array kXferSections{PeSection{".text", kXferTextRva},
                                       PeSection{"text2", kXferText2Rva}};
    auto image = craft_pe_image(kImageBase, kXferImageSize, kXferTextRva, kXferSections);

    constexpr std::array<std::uint8_t, 20> kDelayCode{
        0xB9, 0xE0, 0x93, 0x04, 0x00, // mov ecx, 300000
        0x48, 0x89, 0x04, 0x24,       // mov [rsp], rax
        0xFF, 0xC9,                   // dec ecx
        0x75, 0xF8,                   // jnz -8
        0xB8, 0x00, 0x20, 0x40, 0x00, // mov eax, kXferText2Va
        0xFF, 0xE0};                  // jmp rax
    std::copy(kDelayCode.begin(), kDelayCode.end(),
              image.begin() + static_cast<std::ptrdiff_t>(kXferTextRva));
    constexpr std::array<std::uint8_t, 19> kLandingCode{
        0x48, 0xC7, 0xC1, 0xFF, 0xFF, 0xFF, 0xFF, // mov rcx, -1
        0xBA, 0x34, 0x12, 0x00, 0x00,             // mov edx, 0x1234
        0xB8, 0x02, 0x10, 0x00, 0x00,             // mov eax, 0x1002
        0x0F, 0x05};                              // syscall
    std::copy(kLandingCode.begin(), kLandingCode.end(),
              image.begin() + static_cast<std::ptrdiff_t>(kXferText2Rva));
    return image;
}

inline std::vector<std::uint8_t> craft_xfer_snapshot()
{
    auto image = xfer_image();
    auto metadata = fixture_metadata(kXferTextVa);
    std::copy_n(image.begin() + static_cast<std::ptrdiff_t>(kXferTextRva),
                metadata.original_entry_bytes.size(), metadata.original_entry_bytes.begin());
    std::vector<std::uint8_t> stack(kRegionSize, std::uint8_t{0x5A});
    std::vector<std::uint8_t> teb(kRegionSize, std::uint8_t{0});

    std::ostringstream out;
    snapshot::Writer writer{out};
    if (!writer.write_header(
            snapshot::Header{.version = snapshot::kVersion, .bitness = snapshot::kBitness64}) ||
        !writer.write_registers(fixture_registers(kXferTextVa)) ||
        !writer.write_metadata(metadata) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kImageBase,
                                                    .size = kXferImageSize,
                                                    .protection = kPageExecuteReadwrite,
                                                    .type = kMemImage,
                                                    .content = snapshot::kContentPresent},
                             image.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = kStackRegionBase,
                                                    .size = kRegionSize,
                                                    .protection = kPageReadwrite,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             stack.data()) ||
        !writer.write_region(snapshot::RegionHeader{.base_address = 0x07F10000,
                                                    .size = kRegionSize,
                                                    .protection = kPageReadwrite,
                                                    .type = kMemPrivate,
                                                    .content = snapshot::kContentPresent},
                             teb.data()) ||
        !writer.finalize_region_count()) {
        EXPECT_TRUE(false) << "xfer snapshot serialization failed";
    }
    const auto str = out.str();
    return {str.begin(), str.end()};
}

inline const std::vector<std::uint8_t>& xfer_delay_snapshot_bytes()
{
    static const std::vector<std::uint8_t> bytes = craft_xfer_snapshot();
    return bytes;
}

} // namespace sheller_test
