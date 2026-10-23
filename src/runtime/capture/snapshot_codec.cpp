// Snapshot v1 codec: field-level little-endian encode/decode. The byte layout
// is part of the format contract (golden-file tested), so blocks are written
// field by field - never as raw struct images, whose padding and alignment
// would be platform-dependent.

#include <sheller/snapshot.h>

#include <sheller/byte_order.h>

#include <algorithm>
#include <cstring>
#include <istream>
#include <ostream>

namespace sheller::snapshot {

std::string_view error_message(const Error error)
{
    switch (error) {
    case Error::kNone:
        return "ok";
    case Error::kIoFailure:
        return "stream I/O failure";
    case Error::kBadMagic:
        return "not a sheller snapshot file";
    case Error::kUnsupportedVersion:
        return "snapshot format version not supported by this reader";
    case Error::kBitnessMismatch:
        return "snapshot bitness not supported by this reader";
    case Error::kTruncated:
        return "snapshot data truncated";
    case Error::kBadContent:
        return "region content flag is invalid";
    }
    return "unknown snapshot error";
}

Writer::Writer(std::ostream& out) : out_(out)
{
}

std::expected<void, Error> Writer::write_bytes(const void* data, const std::size_t size)
{
    out_.write(static_cast<const char*>(data), static_cast<std::streamsize>(size));
    if (!out_) {
        return std::unexpected(Error::kIoFailure);
    }
    return {};
}

std::expected<void, Error> Writer::write_header(const Header& header)
{
    std::array<std::uint8_t, kHeaderSize> block{};
    std::ranges::copy(kMagic, block.begin());
    le::store_le32(block.data() + kVersionOffset, header.version);
    block[kBitnessOffset] = header.bitness;
    le::store_le32(block.data() + kRegionCountOffset, header.region_count);
    region_count_ = header.region_count;
    return write_bytes(block.data(), block.size());
}

std::expected<void, Error> Writer::write_registers(const Registers& registers)
{
    std::array<std::uint8_t, kRegistersSize> block{};
    for (std::size_t i = 0; i < kGprCount; ++i) {
        le::store_le64(block.data() + i * sizeof(std::uint64_t), registers.gpr[i]);
    }
    le::store_le64(block.data() + kRipOffset, registers.rip);
    le::store_le64(block.data() + kRflagsOffset, registers.rflags);
    return write_bytes(block.data(), block.size());
}

std::expected<void, Error> Writer::write_metadata(const Metadata& metadata)
{
    std::array<std::uint8_t, kMetadataSize> block{};
    le::store_le64(block.data(), metadata.peb_address);
    le::store_le64(block.data() + kMetadataTebOffset, metadata.teb_address);
    le::store_le64(block.data() + kMetadataImageBaseOffset, metadata.image_base);
    le::store_le64(block.data() + kMetadataEntryOffset, metadata.entry_address);
    std::ranges::copy(metadata.original_entry_bytes, block.data() + kMetadataOriginalEntryOffset);
    return write_bytes(block.data(), block.size());
}

std::expected<void, Error> Writer::write_region(const RegionHeader& region,
                                                const std::uint8_t* content)
{
    if (region.content != kContentAbsent && region.content != kContentPresent) {
        return std::unexpected(Error::kBadContent);
    }
    if (region.content == kContentPresent && content == nullptr && region.size != 0) {
        return std::unexpected(Error::kIoFailure);
    }
    std::array<std::uint8_t, kRegionRecordSize> record{};
    le::store_le64(record.data(), region.base_address);
    le::store_le64(record.data() + kRegionSizeOffset, region.size);
    le::store_le32(record.data() + kRegionProtectionOffset, region.protection);
    le::store_le32(record.data() + kRegionTypeOffset, region.type);
    record[kRegionContentFlagOffset] = region.content;
    return write_bytes(record.data(), record.size())
        .and_then([&] -> std::expected<void, Error> {
            if (region.content == kContentPresent && region.size > 0) {
                return write_bytes(content, static_cast<std::size_t>(region.size));
            }
            return {};
        })
        .and_then([&] -> std::expected<void, Error> {
            ++region_count_;
            return {};
        });
}

std::expected<void, Error> Writer::finalize_region_count()
{
    const std::streampos end = out_.tellp();
    if (end < 0) {
        return std::unexpected(Error::kIoFailure);
    }
    out_.seekp(static_cast<std::streamoff>(kRegionCountOffset));
    std::array<std::uint8_t, sizeof(std::uint32_t)> count{};
    le::store_le32(count.data(), region_count_);
    return write_bytes(count.data(), count.size()).and_then([&] -> std::expected<void, Error> {
        out_.seekp(end);
        if (!out_) {
            return std::unexpected(Error::kIoFailure);
        }
        return {};
    });
}

Reader::Reader(std::istream& in) : in_(in)
{
}

Error Reader::read_bytes(void* data, const std::size_t size)
{
    in_.read(static_cast<char*>(data), static_cast<std::streamsize>(size));
    if (in_.bad()) {
        return Error::kIoFailure;
    }
    if (static_cast<std::size_t>(in_.gcount()) != size) {
        return Error::kTruncated;
    }
    return Error::kNone;
}

std::expected<Header, Error> Reader::read_header()
{
    std::array<std::uint8_t, kHeaderSize> block{};
    if (const Error error = read_bytes(block.data(), block.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    if (std::memcmp(block.data(), kMagic, sizeof kMagic) != 0) {
        return std::unexpected(Error::kBadMagic);
    }
    const Header header{
        .version = le::load_le32(block.data() + kVersionOffset),
        .bitness = block[kBitnessOffset],
        .region_count = le::load_le32(block.data() + kRegionCountOffset),
    };
    if (header.version != kVersion) {
        return std::unexpected(Error::kUnsupportedVersion);
    }
    if (header.bitness != kBitness64 && header.bitness != kBitness32) {
        return std::unexpected(Error::kBitnessMismatch);
    }
    header_bitness = header.bitness;
    return header;
}

std::expected<Registers, Error> Reader::read_registers()
{
    std::array<std::uint8_t, kRegistersSize> block{};
    if (const Error error = read_bytes(block.data(), block.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    Registers registers;
    for (std::size_t i = 0; i < kGprCount; ++i) {
        registers.gpr[i] = le::load_le64(block.data() + i * sizeof(std::uint64_t));
    }
    registers.rip = le::load_le64(block.data() + kRipOffset);
    registers.rflags = le::load_le64(block.data() + kRflagsOffset);
    return registers;
}

std::expected<Metadata, Error> Reader::read_metadata()
{
    std::array<std::uint8_t, kMetadataSize> block{};
    if (const Error error = read_bytes(block.data(), block.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    Metadata metadata;
    metadata.bitness = header_bitness;
    metadata.peb_address = le::load_le64(block.data());
    metadata.teb_address = le::load_le64(block.data() + kMetadataTebOffset);
    metadata.image_base = le::load_le64(block.data() + kMetadataImageBaseOffset);
    metadata.entry_address = le::load_le64(block.data() + kMetadataEntryOffset);
    std::ranges::copy(block.data() + kMetadataOriginalEntryOffset, block.data() + kMetadataSize,
                      metadata.original_entry_bytes.begin());
    return metadata;
}

std::expected<Region, Error> Reader::read_region()
{
    std::array<std::uint8_t, kRegionRecordSize> record{};
    if (const Error error = read_bytes(record.data(), record.size()); error != Error::kNone) {
        return std::unexpected(error);
    }
    const RegionHeader header{
        .base_address = le::load_le64(record.data()),
        .size = le::load_le64(record.data() + kRegionSizeOffset),
        .protection = le::load_le32(record.data() + kRegionProtectionOffset),
        .type = le::load_le32(record.data() + kRegionTypeOffset),
        .content = record[kRegionContentFlagOffset],
    };
    if (header.content != kContentAbsent && header.content != kContentPresent) {
        return std::unexpected(Error::kBadContent);
    }
    Region region{.header = header};
    if (header.content == kContentPresent && header.size > 0) {
        region.content.resize(static_cast<std::size_t>(header.size));
        if (const Error error = read_bytes(region.content.data(), region.content.size());
            error != Error::kNone) {
            return std::unexpected(error);
        }
    }
    return region;
}

} // namespace sheller::snapshot
