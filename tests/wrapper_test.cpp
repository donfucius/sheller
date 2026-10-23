// Wrapper unit tests: the wrap is a pure byte function - structure,
// byte fidelity, bounds and architecture symmetry are all checked here
// without unicorn or a real process.

#include "wrapper.h"

#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

namespace {

std::vector<std::uint8_t> blob_of(const std::vector<std::uint8_t>& bytes)
{
    return bytes;
}

std::uint32_t load32(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
    return static_cast<std::uint32_t>(bytes[offset]) |
           (static_cast<std::uint32_t>(bytes[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(bytes[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(bytes[offset + 3]) << 24);
}

std::uint16_t load16(const std::vector<std::uint8_t>& bytes, const std::size_t offset)
{
    return static_cast<std::uint16_t>(bytes[offset] |
                                      (static_cast<std::uint16_t>(bytes[offset + 1]) << 8));
}

TEST(WrapperLooksLikePe, MzMagicOnly)
{
    const std::vector<std::uint8_t> empty;
    const std::vector<std::uint8_t> one{0x4D};
    const std::vector<std::uint8_t> other{0xCC, 0x90, 0x90};
    const std::vector<std::uint8_t> mz{0x4D, 0x5A, 0x00, 0x00};
    EXPECT_FALSE(sheller::capture::looks_like_pe(empty));
    EXPECT_FALSE(sheller::capture::looks_like_pe(one));
    EXPECT_FALSE(sheller::capture::looks_like_pe(other));
    EXPECT_TRUE(sheller::capture::looks_like_pe(mz));
}

TEST(WrapperBlob, ProducesLegalMinimalPe)
{
    const auto blob = blob_of({0xB8, 0x02, 0x10, 0x00, 0x00, 0x0F, 0x05});
    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    ASSERT_TRUE(wrapped.has_value());
    const auto& pe = *wrapped;

    EXPECT_EQ(load16(pe, 0), 0x5A4D);                 // MZ
    EXPECT_EQ(load32(pe, 0x3C), 0x40);                // e_lfanew
    EXPECT_EQ(load32(pe, 0x40), 0x00004550);          // PE signature
    EXPECT_EQ(load16(pe, 0x44), 0x8664);              // machine x64
    EXPECT_EQ(load16(pe, 0x44 + 0x02), 1);            // one section
    EXPECT_EQ(load32(pe, 0x58 + 0x10), 0x1000);       // entry RVA = section head
    EXPECT_EQ(load16(pe, 0x58), 0x020B);              // PE32+
    EXPECT_EQ(load32(pe, 0x58 + 0x38), 0x2000);       // SizeOfImage
    EXPECT_EQ(pe[0x148], 0x2E);                       // section name "."
    EXPECT_EQ(load32(pe, 0x148 + 0x08), blob.size()); // VirtualSize
    EXPECT_EQ(load32(pe, 0x148 + 0x0C), 0x1000);      // VirtualAddress
    EXPECT_EQ(load32(pe, 0x148 + 0x24), 0x60000020);  // CODE|EXECUTE|READ
}

TEST(WrapperBlob, ByteFidelityAtSectionHead)
{
    // a blob that itself starts with MZ-style bytes must survive verbatim
    const std::vector<std::uint8_t> blob = {0x4D, 0x5A, 0xE8, 0x00, 0x00,
                                            0x00, 0x00, 0x59, 0x0F, 0x05};
    const auto wrapped = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    ASSERT_TRUE(wrapped.has_value());
    const auto raw = 0x200; // PointerToRawData of the single section
    for (std::size_t i = 0; i < blob.size(); ++i) {
        ASSERT_EQ((*wrapped)[raw + i], blob[i]) << "byte " << i;
    }
    // entry points at the section head = the blob's first byte
    EXPECT_EQ(load32(*wrapped, 0x58 + 0x10), 0x1000);
}

TEST(WrapperBlob, EmptyAndOversizedAreRejected)
{
    const auto empty = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, {});
    ASSERT_FALSE(empty.has_value());
    EXPECT_EQ(empty.error(), sheller::capture::WrapError::kEmptyBlob);

    std::vector<std::uint8_t> huge(sheller::capture::kMaxBlobBytes + 1, 0x90);
    const auto oversized = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, huge);
    ASSERT_FALSE(oversized.has_value());
    EXPECT_EQ(oversized.error(), sheller::capture::WrapError::kTooLarge);
}

// The capture route turns a wrap failure into a caller-visible status, and the two
// halves of that decision are what a caller acts on: an unusable blob says "go look
// at the sample", an unresolved temporary directory says "the capture could not run".
// Folding the second into the first would send the caller to fix a file that was
// never the problem. Nothing else in the tree reaches that branch - a host with no
// temp directory is not a case the suite can manufacture - so the mapping itself is
// what is pinned here, next to the enum it maps.
TEST(WrapperErrors, EachFailureHasItsOwnMessageAndStatus)
{
    struct Row {
        sheller::capture::WrapError error;
        std::string_view message;
        sheller::capture::Status status;
    };
    const Row rows[] = {
        {sheller::capture::WrapError::kEmptyBlob, "shellcode blob is empty",
         sheller::capture::Status::kNotX64Pe},
        {sheller::capture::WrapError::kTooLarge, "shellcode blob exceeds the wrapper capacity",
         sheller::capture::Status::kNotX64Pe},
        {sheller::capture::WrapError::kTempDirUnavailable,
         "cannot resolve the host temporary directory", sheller::capture::Status::kCaptureFailed},
    };
    for (const auto& row : rows) {
        EXPECT_EQ(sheller::capture::wrap_error_message(row.error), row.message);
        EXPECT_EQ(sheller::capture::wrap_status(row.error), row.status);
    }
    // A third failure that reads like the first one is one failure too many.
    EXPECT_NE(sheller::capture::wrap_error_message(rows[0].error),
              sheller::capture::wrap_error_message(rows[2].error));
    EXPECT_NE(sheller::capture::wrap_status(rows[0].error),
              sheller::capture::wrap_status(rows[2].error));
}

TEST(WrapperBlob, X64X86StructureSymmetry)
{
    const std::vector<std::uint8_t> blob(37, 0x90);
    const auto x64 = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX64, blob);
    const auto x86 = sheller::capture::wrap_blob(sheller::capture::WrapArch::kX86, blob);
    ASSERT_TRUE(x64.has_value());
    ASSERT_TRUE(x86.has_value());

    EXPECT_EQ(load16(*x86, 0x44), 0x014C);         // machine x86
    EXPECT_EQ(load16(*x86, 0x58), 0x010B);         // PE32
    EXPECT_EQ(load32(*x86, 0x58 + 0x10), 0x1000);  // entry RVA = section head
    EXPECT_EQ(load32(*x86, 0x138 + 0x0C), 0x1000); // section RVA (x86 layout)
    EXPECT_EQ(load32(*x64, 0x148 + 0x0C), 0x1000);
    // same blob lands at the same raw offset with the same raw size
    EXPECT_EQ(load32(*x86, 0x138 + 0x10), load32(*x64, 0x148 + 0x10));
}

} // namespace
