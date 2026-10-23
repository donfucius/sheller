// PE header parser tests run on every platform: the parser is portable on
// purpose, fed with the same hand-crafted fixture bytes the Windows capture
// tests map from file.

#include "minimal_pe.h"
#include "pe_headers.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

namespace {

namespace capture = sheller::capture;

TEST(PeHeaders, ParsesMinimalFixture)
{
    for (const bool with_tls : {false, true}) {
        const auto image = sheller_test::make_minimal_pe(with_tls);
        capture::PeImageInfo info;
        const auto error = capture::parse_pe_headers(image.data(), image.size(), info);
        ASSERT_EQ(error, capture::PeError::kNone) << capture::pe_error_message(error);
        EXPECT_EQ(info.machine, capture::kMachineAmd64);
        EXPECT_EQ(info.preferred_base, sheller_test::kImageBase);
        EXPECT_EQ(info.entry_rva, sheller_test::kEntryPointRva);
        EXPECT_EQ(info.has_tls, with_tls);
        if (with_tls) {
            EXPECT_EQ(info.tls_directory_rva, sheller_test::kTlsDirectoryRva);
        }
    }
}

TEST(PeHeaders, RejectsMissingDosHeader)
{
    const std::vector<std::uint8_t> tiny(16, std::uint8_t{0x4D});
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(tiny.data(), tiny.size(), info),
              capture::PeError::kBufferTooSmall);
    EXPECT_EQ(capture::parse_pe_headers(tiny.data(), 0, info), capture::PeError::kBufferTooSmall);
}

TEST(PeHeaders, RejectsBrokenMzSignature)
{
    auto image = sheller_test::make_minimal_pe(false);
    image[0] = 'X';
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kBufferTooSmall);
}

TEST(PeHeaders, RejectsOutOfRangeE_lfanew)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& dos = *reinterpret_cast<capture::DosHeader*>(image.data());
    dos.e_lfanew = -1;
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kDosHeader);
}

TEST(PeHeaders, RejectsBrokenPeSignature)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(image.data() + 0x80);
    nt.signature = 0;
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kNtHeader);
}

TEST(PeHeaders, I386MachineWithPe32PlusHeaderRejected)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(image.data() + 0x80);
    nt.file_header.machine = capture::kMachineI386; // i386 needs PE32 headers
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kOptionalHeader);
}

TEST(PeHeaders, RejectsForeignMachine)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(image.data() + 0x80);
    nt.file_header.machine = 0xAA64; // ARM64
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kOptionalHeader);
}

TEST(PeHeaders, RejectsPe32OptionalHeader)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(image.data() + 0x80);
    nt.optional_header.magic = 0x10B; // PE32
    capture::PeImageInfo info;
    EXPECT_EQ(capture::parse_pe_headers(image.data(), image.size(), info),
              capture::PeError::kOptionalHeader);
}

TEST(PeHeaders, SkipsTlsWhenDirectoryAbsent)
{
    auto image = sheller_test::make_minimal_pe(false);
    auto& nt = *reinterpret_cast<capture::NtHeaders64*>(image.data() + 0x80);
    nt.optional_header.number_of_rva_and_sizes = capture::kTlsDirectoryIndex;
    capture::PeImageInfo info;
    ASSERT_EQ(capture::parse_pe_headers(image.data(), image.size(), info), capture::PeError::kNone);
    EXPECT_FALSE(info.has_tls);
}

} // namespace
