// Little-endian scalar access for the wire formats the project defines
// (snapshot v1, TLV events). The byte layouts are little-endian by spec,
// independent of the host byte order.

#ifndef SHELLER_BYTE_ORDER_H
#define SHELLER_BYTE_ORDER_H

#include <cstddef>
#include <cstdint>

namespace sheller::le {

constexpr void store_le16(std::uint8_t* dst, std::uint16_t value)
{
    dst[0] = static_cast<std::uint8_t>(value);
    dst[1] = static_cast<std::uint8_t>(value >> 8);
}

constexpr void store_le32(std::uint8_t* dst, std::uint32_t value)
{
    store_le16(dst, static_cast<std::uint16_t>(value));
    store_le16(dst + 2, static_cast<std::uint16_t>(value >> 16));
}

constexpr void store_le64(std::uint8_t* dst, std::uint64_t value)
{
    store_le32(dst, static_cast<std::uint32_t>(value));
    store_le32(dst + 4, static_cast<std::uint32_t>(value >> 32));
}

constexpr std::uint16_t load_le16(const std::uint8_t* src)
{
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(src[0]) |
                                      static_cast<std::uint16_t>(src[1] << 8));
}

constexpr std::uint32_t load_le32(const std::uint8_t* src)
{
    return static_cast<std::uint32_t>(load_le16(src)) |
           (static_cast<std::uint32_t>(load_le16(src + 2)) << 16);
}

constexpr std::uint64_t load_le64(const std::uint8_t* src)
{
    return static_cast<std::uint64_t>(load_le32(src)) |
           (static_cast<std::uint64_t>(load_le32(src + 4)) << 32);
}

} // namespace sheller::le

#endif // SHELLER_CAPTURE_BYTE_ORDER_H
