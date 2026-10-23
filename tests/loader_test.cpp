// Loader core unit tests: parse, layout, relocations and TLS
// extraction are pure byte functions - all driven here without unicorn.

#include "loader.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <vector>

namespace {

using namespace sheller::loader;

// Minimal x64 PE32+ file: headers at 0x0, one section at raw 0x200 mapped at
// RVA 0x1000, a relocation block and a TLS directory inside the section.
// FILE offset = section raw pointer + (RVA - 0x1000) for section bytes.
struct TinyPe {
    std::vector<std::uint8_t> bytes;
    std::uint64_t image_base = 0x140000000ULL;
    std::uint64_t image_size = 0x2000;
    std::uint32_t entry_rva = 0x1000;
    std::uint32_t tls_dir_rva = 0x1000;   // image RVA of the TLS directory
    std::uint32_t reloc_dir_rva = 0x1100; // image RVA of the relocation block

    void put32(std::size_t offset, std::uint32_t value)
    {
        std::memcpy(&bytes[offset], &value, sizeof value);
    }
    void put16(std::size_t offset, std::uint16_t value)
    {
        std::memcpy(&bytes[offset], &value, sizeof value);
    }
    void put64(std::size_t offset, std::uint64_t value)
    {
        std::memcpy(&bytes[offset], &value, sizeof value);
    }
};

TinyPe make_tiny_pe()
{
    TinyPe t;
    t.bytes.assign(0x400, 0);
    t.bytes[0] = 'M';
    t.bytes[1] = 'Z';
    t.put32(0x3C, 0x40);        // e_lfanew
    t.put32(0x40, 0x00004550);  // PE signature
    t.put16(0x44, 0x8664);      // machine AMD64
    t.put16(0x46, 1);           // one section
    t.put16(0x54, 0xF0);        // SizeOfOptionalHeader
    t.put16(0x56, 0x0022);      // characteristics
    t.put16(0x58, 0x020B);      // PE32+
    t.bytes[0x5A] = 1;          // linker major
    t.put32(0x5C, 0x200);       // SizeOfCode
    t.put32(0x68, t.entry_rva); // AddressOfEntryPoint
    t.put32(0x6C, 0x1000);      // BaseOfCode
    t.put64(0x70, t.image_base);
    t.put32(0x78, 0x1000); // SectionAlignment
    t.put32(0x7C, 0x200);  // FileAlignment
    t.put32(0x90, static_cast<std::uint32_t>(t.image_size));
    t.put32(0x94, 0x200); // SizeOfHeaders
    // data directories: [5] relocation, [9] TLS
    t.put32(0xC8 + 5 * 8, t.reloc_dir_rva);
    t.put32(0xC8 + 5 * 8 + 4, 0x10);
    t.put32(0xC8 + 9 * 8, t.tls_dir_rva);
    t.put32(0xC8 + 9 * 8 + 4, 0x40);
    // section header at opt(0x58) + 0xF0 = 0x148: ".text"
    std::memcpy(&t.bytes[0x148], ".text", 5);
    t.put32(0x148 + 8, 0x200);       // VirtualSize
    t.put32(0x148 + 12, 0x1000);     // VirtualAddress
    t.put32(0x148 + 16, 0x200);      // SizeOfRawData
    t.put32(0x148 + 20, 0x200);      // PointerToRawData
    t.put32(0x148 + 36, 0x60000020); // CODE|EXECUTE|READ
    return t;
}

std::uint32_t load32_at(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

TEST(LoaderParse, TinyPeLayoutAndTlsExtraction)
{
    auto tiny = make_tiny_pe();
    // section raw 0x200 maps image RVA 0x1000: the TLS directory sits at file
    // 0x200 with AddressOfCallBacks pointing at the array in file 0x300
    const std::uint64_t callbacks_va = tiny.image_base + 0x1100;
    tiny.put64(0x218, callbacks_va); // AddressOfCallBacks (dir + 0x18)
    const std::uint64_t cb[3] = {tiny.image_base + 0x1200, tiny.image_base + 0x1300, 0};
    std::memcpy(&tiny.bytes[0x300], cb, sizeof cb);

    const auto info = parse_pe(tiny.bytes);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->image_base, tiny.image_base);
    EXPECT_EQ(info->image_size, tiny.image_size);
    EXPECT_EQ(info->entry_rva, 0x1000U);
    EXPECT_EQ(info->sections.size(), 1U);

    auto image = build_image(tiny.bytes, *info);
    ASSERT_TRUE(image.has_value());
    EXPECT_EQ(image->size(), tiny.image_size);

    const auto callbacks = tls_callbacks(*image, *info);
    std::puts("tls-extracted");
    ASSERT_TRUE(callbacks.has_value());
    ASSERT_EQ(callbacks->size(), 2U);
    EXPECT_EQ((*callbacks)[0], tiny.image_base + 0x1200);
    EXPECT_EQ((*callbacks)[1], tiny.image_base + 0x1300);
}

TEST(LoaderReloc, DeltaZeroIsIdempotent)
{
    auto tiny = make_tiny_pe();
    const auto info = parse_pe(tiny.bytes);
    ASSERT_TRUE(info.has_value());
    auto image = build_image(tiny.bytes, *info);
    ASSERT_TRUE(image.has_value());
    // one HIGHLOW entry: image RVA 0x1010 (file 0x210), block size 12
    tiny.put32(0x300, 0x1000);
    tiny.put32(0x304, 0x0C);
    tiny.put16(0x308, 0xA010);
    tiny.put32(0x210, 0xDEADBEEF);
    const auto before = *image;
    ASSERT_TRUE(apply_relocations(*image, *info, 0).has_value());
    EXPECT_EQ(image, before); // delta zero: nothing changes
}

TEST(LoaderReloc, HighLowMovesWithDelta)
{
    auto tiny = make_tiny_pe();
    const auto info = parse_pe(tiny.bytes);
    ASSERT_TRUE(info.has_value());
    auto image = build_image(tiny.bytes, *info);
    ASSERT_TRUE(image.has_value());
    // the relocation block lives in the IMAGE (image rva 0x1100, target 0x1010)
    auto put32i = [&image](std::size_t offset, std::uint32_t value) {
        std::memcpy(&(*image)[offset], &value, sizeof value);
    };
    auto put16i = [&image](std::size_t offset, std::uint16_t value) {
        std::memcpy(&(*image)[offset], &value, sizeof value);
    };
    put32i(0x1100, 0x1000); // block: page rva
    put32i(0x1104, 0x0C);   // block size
    put16i(0x1108, 0xA010); // HIGHLOW, target image rva 0x1010
    put32i(0x1010, 0x00400000);
    const std::uint64_t delta = 0x10000;
    ASSERT_TRUE(apply_relocations(*image, *info, delta).has_value());
    EXPECT_EQ(load32_at(*image, 0x1010), 0x00400000U + static_cast<std::uint32_t>(delta));
}

TEST(LoaderParse, RejectsMismatchedMachineAndGarbage)
{
    auto tiny = make_tiny_pe();
    tiny.put16(0x44, 0x014C); // i386 machine with a PE32+ header: broken shape
    EXPECT_FALSE(parse_pe(tiny.bytes).has_value());

    const std::vector<std::uint8_t> junk(0x300, 0x41);
    EXPECT_FALSE(parse_pe(junk).has_value());

    tiny.put16(0x44, 0x01F0); // PPC: unsupported machine
    EXPECT_FALSE(parse_pe(tiny.bytes).has_value());
}

// Minimal x86 PE32 file: same shape as TinyPe but with the PE32 optional
// header (magic 0x10B, 4-byte ImageBase at optional+0x1C, directories at
// optional+0x60, SizeOfOptionalHeader 0xE0).
TinyPe make_tiny_pe32()
{
    TinyPe t;
    t.image_base = 0x400000ULL; // 32-bit images live under 4GB
    t.bytes.assign(0x400, 0);
    t.bytes[0] = 'M';
    t.bytes[1] = 'Z';
    t.put32(0x3C, 0x40);                                     // e_lfanew
    t.put32(0x40, 0x00004550);                               // PE signature
    t.put16(0x44, 0x014C);                                   // machine i386
    t.put16(0x46, 1);                                        // one section
    t.put16(0x54, 0xE0);                                     // SizeOfOptionalHeader (PE32)
    t.put16(0x56, 0x0102);                                   // characteristics
    t.put16(0x58, 0x010B);                                   // PE32
    t.bytes[0x5A] = 1;                                       // linker major
    t.put32(0x5C, 0x200);                                    // SizeOfCode
    t.put32(0x68, t.entry_rva);                              // AddressOfEntryPoint
    t.put32(0x6C, 0x1000);                                   // BaseOfCode
    t.put32(0x70, 0x2000);                                   // BaseOfData (PE32 only)
    t.put32(0x74, static_cast<std::uint32_t>(t.image_base)); // ImageBase (4 bytes)
    t.put32(0x78, 0x1000);                                   // SectionAlignment
    t.put32(0x7C, 0x200);                                    // FileAlignment
    t.put32(0x90, static_cast<std::uint32_t>(t.image_size));
    t.put32(0x94, 0x200); // SizeOfHeaders
    // data directories at optional(0x58)+0x60 = 0xB8: [5] relocation, [9] TLS
    t.put32(0xB8 + 5 * 8, t.reloc_dir_rva);
    t.put32(0xB8 + 5 * 8 + 4, 0x10);
    t.put32(0xB8 + 9 * 8, t.tls_dir_rva);
    t.put32(0xB8 + 9 * 8 + 4, 0x40);
    // section header at opt(0x58) + 0xE0 = 0x138: ".text"
    std::memcpy(&t.bytes[0x138], ".text", 5);
    t.put32(0x138 + 8, 0x200);       // VirtualSize
    t.put32(0x138 + 12, 0x1000);     // VirtualAddress
    t.put32(0x138 + 16, 0x200);      // SizeOfRawData
    t.put32(0x138 + 20, 0x200);      // PointerToRawData
    t.put32(0x138 + 36, 0x60000020); // CODE|EXECUTE|READ
    return t;
}

TEST(LoaderParse32, LayoutBitnessAndTlsExtraction)
{
    auto tiny = make_tiny_pe32();
    // TLS directory at image RVA 0x1000 (file 0x200): PE32 AddressOfCallBacks
    // is the 4-byte field at +0x0C, entries are 4-byte VAs
    const std::uint32_t callbacks_va = static_cast<std::uint32_t>(tiny.image_base) + 0x1100;
    tiny.put32(0x20C, callbacks_va);
    const std::uint32_t cb[3] = {static_cast<std::uint32_t>(tiny.image_base) + 0x1200,
                                 static_cast<std::uint32_t>(tiny.image_base) + 0x1300, 0};
    std::memcpy(&tiny.bytes[0x300], cb, sizeof cb);

    const auto info = parse_pe(tiny.bytes);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->bitness, kBitness32);
    EXPECT_EQ(info->image_base, tiny.image_base);
    EXPECT_EQ(info->image_size, tiny.image_size);
    EXPECT_EQ(info->entry_rva, 0x1000U);
    EXPECT_EQ(info->sections.size(), 1U);
    EXPECT_EQ(info->sections[0].virtual_address, 0x1000U);

    auto image = build_image(tiny.bytes, *info);
    ASSERT_TRUE(image.has_value());
    EXPECT_EQ(image->size(), tiny.image_size);

    const auto callbacks = tls_callbacks(*image, *info);
    ASSERT_TRUE(callbacks.has_value());
    ASSERT_EQ(callbacks->size(), 2U);
    EXPECT_EQ((*callbacks)[0], tiny.image_base + 0x1200);
    EXPECT_EQ((*callbacks)[1], tiny.image_base + 0x1300);
}

TEST(LoaderParse64, ReportsBitness)
{
    const auto info = parse_pe(make_tiny_pe().bytes);
    ASSERT_TRUE(info.has_value());
    EXPECT_EQ(info->bitness, kBitness64);
}

TEST(LoaderReloc32, HighLowMovesWithSmallDelta)
{
    auto tiny = make_tiny_pe32();
    const auto info = parse_pe(tiny.bytes);
    ASSERT_TRUE(info.has_value());
    auto image = build_image(tiny.bytes, *info);
    ASSERT_TRUE(image.has_value());
    auto put32i = [&image](std::size_t offset, std::uint32_t value) {
        std::memcpy(&(*image)[offset], &value, sizeof value);
    };
    auto put16i = [&image](std::size_t offset, std::uint16_t value) {
        std::memcpy(&(*image)[offset], &value, sizeof value);
    };
    // one HIGHLOW entry in the image: block at RVA 0x1100, target 0x1010
    put32i(0x1100, 0x1000);
    put32i(0x1104, 0x0C);
    put16i(0x1108, 0xA010);
    put32i(0x1010, 0x00400000);
    const std::uint64_t delta = 0x10000;
    ASSERT_TRUE(apply_relocations(*image, *info, delta).has_value());
    EXPECT_EQ(load32_at(*image, 0x1010), 0x00400000U + static_cast<std::uint32_t>(delta));
}

} // namespace
