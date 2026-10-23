#include "exception_layout.h"

#include <cstring>

namespace sheller::engine::exceptions {
namespace {

// LE scalar stores over the synthesized buffers; the guest is little-endian
// and the structures travel in guest memory, not host struct instances.
void store64(std::uint8_t* dst, const std::uint64_t value)
{
    for (std::size_t i = 0; i < 8; ++i) {
        dst[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

void store32(std::uint8_t* dst, const std::uint32_t value)
{
    for (std::size_t i = 0; i < 4; ++i) {
        dst[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

void store16(std::uint8_t* dst, const std::uint16_t value)
{
    for (std::size_t i = 0; i < 2; ++i) {
        dst[i] = static_cast<std::uint8_t>(value >> (8 * i));
    }
}

} // namespace

// Layout pins: the offsets are part of the contract with the real
// dispatcher; anything below explodes at compile time.
static_assert(kContextXsaveAreaOffset + 0x200 == 0x300, "XSAVE area must end at the vector slots");
static_assert(kContextGprOffsets.back() + 8 == kContextRipOffset, "R15 must precede Rip");
static_assert(kRecordInformationOffset + kRecordMaxParameters * 8 == kExceptionRecordSize,
              "ExceptionInformation must end the record");
static_assert(kRecordMaxParameters == 15, "EXCEPTION_MAXIMUM_PARAMETERS is 15");

void write_context(std::uint8_t* context, const RegisterSnapshot& snapshot)
{
    std::memset(context, 0, kContextSize);
    store32(context + kContextFlagsOffset, kContextFull);
    store32(context + kContextEFlagsOffset, snapshot.eflags);
    store16(context + kContextSegCsOffset, snapshot.cs);
    store16(context + kContextSegDsOffset, snapshot.ds);
    store16(context + kContextSegEsOffset, snapshot.es);
    store16(context + kContextSegFsOffset, snapshot.fs);
    store16(context + kContextSegGsOffset, snapshot.gs);
    store16(context + kContextSegSsOffset, snapshot.ss);
    for (std::size_t i = 0; i < snapshot.gpr.size(); ++i) {
        store64(context + kContextGprOffsets[i], snapshot.gpr[i]);
    }
    store64(context + kContextRipOffset, snapshot.rip);
}

void write_record(std::uint8_t* record, const std::uint32_t code, const std::uint64_t address,
                  const std::uint64_t* information, const std::size_t information_count)
{
    std::memset(record, 0, kExceptionRecordSize);
    store32(record + kRecordCodeOffset, code);
    store64(record + kRecordAddressOffset, address);
    store32(record + kRecordNumberParametersOffset, static_cast<std::uint32_t>(information_count));
    for (std::size_t i = 0; i < information_count && i < kRecordMaxParameters; ++i) {
        store64(record + kRecordInformationOffset + 8 * i, information[i]);
    }
}

// Layout pins for the x86 twins.
static_assert(kContextEipOffset32 == kContextEbpOffset32 + 4,
              "Ebp must precede Eip in the CONTEXT32 memory order");
static_assert(kRecordInformationOffset32 + kRecordMaxParameters * 4 == kExceptionRecordSize32,
              "ExceptionInformation must end the x86 record");

void write_context_x86(std::uint8_t* context, const RegisterSnapshot& snapshot)
{
    std::memset(context, 0, kContextSize32);
    store32(context + kContextFlagsOffset32, kContextFull32);
    store32(context + kContextEFlagsOffset32, snapshot.eflags);
    store16(context + kContextSegCsOffset32, snapshot.cs);
    store16(context + kContextSegDsOffset32, snapshot.ds);
    store16(context + kContextSegEsOffset32, snapshot.es);
    store16(context + kContextSegFsOffset32, snapshot.fs);
    store16(context + kContextSegGsOffset32, snapshot.gs);
    store16(context + kContextSegSsOffset32, snapshot.ss);
    // 8 GPR slots, 4 bytes each, truncated from the u64 snapshot slots
    for (std::size_t i = 0; i < kContextGprOffsets32.size(); ++i) {
        store32(context + kContextGprOffsets32[i], static_cast<std::uint32_t>(snapshot.gpr[i]));
    }
    store32(context + kContextEipOffset32, static_cast<std::uint32_t>(snapshot.rip));
}

void write_record_x86(std::uint8_t* record, const std::uint32_t code, const std::uint64_t address,
                      const std::uint64_t* information, const std::size_t information_count)
{
    std::memset(record, 0, kExceptionRecordSize32);
    store32(record + kRecordCodeOffset32, code);
    store32(record + kRecordAddressOffset32, static_cast<std::uint32_t>(address));
    store32(record + kRecordNumberParametersOffset32,
            static_cast<std::uint32_t>(information_count));
    for (std::size_t i = 0; i < information_count && i < kRecordMaxParameters; ++i) {
        store32(record + kRecordInformationOffset32 + 4 * i,
                static_cast<std::uint32_t>(information[i]));
    }
}

} // namespace sheller::engine::exceptions
