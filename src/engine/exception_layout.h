// Win64 CONTEXT / EXCEPTION_RECORD layout constants for the synthesized
// exception dispatch: the engine plays the kernel role and
// builds the two structures the real ntdll dispatcher consumes. Windows
// headers may not appear in engine modules (portability boundary), so the offsets are pinned here
// from winnt.h (WDK, x64) and locked by static_asserts - layout drift explodes at compile time, not
// in front of a live dispatcher.

#ifndef SHELLER_ENGINE_EXCEPTION_LAYOUT_H
#define SHELLER_ENGINE_EXCEPTION_LAYOUT_H

#include <array>
#include <cstddef>
#include <cstdint>

namespace sheller::engine::exceptions {

// -- CONTEXT (x64, DECLSPEC_ALIGN(16)), winnt.h ------------------------------

inline constexpr std::size_t kContextSize = 0x4D0;
inline constexpr std::uint32_t kContextAmd64 = 0x100000;
// CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS: everything the
// integer-part dispatch and its handlers inspect.
inline constexpr std::uint32_t kContextFull = kContextAmd64 | 0x7;

// User-dispatch stack frame (read off the captured ntdll's
// KiUserExceptionDispatcher prologue: `mov rcx,rsp; add rcx,0x4f0; mov
// rdx,rsp` - it loads both pointers from RSP itself, whatever the kernel
// left in rcx/rdx): RSP points at the CONTEXT and the EXCEPTION_RECORD sits
// at RSP + 0x4F0. Not a winnt.h constant; pinned from the prologue pattern.
inline constexpr std::size_t kUserDispatchRecordDisplacement = 0x4F0;

inline constexpr std::size_t kContextFlagsOffset = 0x30;
inline constexpr std::size_t kContextMxCsrOffset = 0x34;
inline constexpr std::size_t kContextSegCsOffset = 0x38;
inline constexpr std::size_t kContextSegDsOffset = 0x3A;
inline constexpr std::size_t kContextSegEsOffset = 0x3C;
inline constexpr std::size_t kContextSegFsOffset = 0x3E;
inline constexpr std::size_t kContextSegGsOffset = 0x40;
inline constexpr std::size_t kContextSegSsOffset = 0x42;
inline constexpr std::size_t kContextEFlagsOffset = 0x44;
inline constexpr std::size_t kContextRaxOffset = 0x78;
inline constexpr std::size_t kContextRcxOffset = 0x80;
inline constexpr std::size_t kContextRdxOffset = 0x88;
inline constexpr std::size_t kContextRbxOffset = 0x90;
inline constexpr std::size_t kContextRspOffset = 0x98;
inline constexpr std::size_t kContextRbpOffset = 0xA0;
inline constexpr std::size_t kContextRsiOffset = 0xA8;
inline constexpr std::size_t kContextRdiOffset = 0xB0;
inline constexpr std::size_t kContextRipOffset = 0xF8;
inline constexpr std::size_t kContextXsaveAreaOffset = 0x100; // 512 bytes, zero-filled

// GPR slots in CONTEXT order, index-matched to the engine's kGprRegisters
// array (Intel order RAX=0..R15=15).
inline constexpr std::array<std::size_t, 16> kContextGprOffsets{kContextRaxOffset,
                                                                kContextRcxOffset,
                                                                kContextRdxOffset,
                                                                kContextRbxOffset,
                                                                kContextRspOffset,
                                                                kContextRbpOffset,
                                                                kContextRsiOffset,
                                                                kContextRdiOffset,
                                                                0xB8,
                                                                0xC0,
                                                                0xC8,
                                                                0xD0,
                                                                0xD8,
                                                                0xE0,
                                                                0xE8,
                                                                0xF0}; // R8..R15

// -- EXCEPTION_RECORD (x64), winnt.h ------------------------------------------

inline constexpr std::size_t kExceptionRecordSize = 0x98;
inline constexpr std::size_t kRecordCodeOffset = 0x00;
inline constexpr std::size_t kRecordFlagsOffset = 0x04;
inline constexpr std::size_t kRecordInnerOffset = 0x08; // nested record pointer
inline constexpr std::size_t kRecordAddressOffset = 0x10;
inline constexpr std::size_t kRecordNumberParametersOffset = 0x18;
inline constexpr std::size_t kRecordInformationOffset = 0x20;
inline constexpr std::size_t kRecordMaxParameters = 15;

// The kernel's interrupt machine frame {rip, cs, eflags, rsp, ss} follows
// the EXCEPTION_RECORD 16-aligned: KiUserExceptionDispatcher's own unwind
// (v2, UWOP_PUSH_MACHFRAME) restores the faulting rip/rsp from here.
inline constexpr std::size_t kUserDispatchMachineFrame =
    (kUserDispatchRecordDisplacement + kExceptionRecordSize + 0xF) & ~std::size_t{0xF};

// -- CONTEXT (x86, CONTEXT_i386), winnt.h -------------------------------------
// Offsets pinned from the WDK x86 shapes; the wow64 dispatcher consumes the
// same bytes a 32-bit kernel would leave.

inline constexpr std::size_t kContextSize32 = 0x2CC;
inline constexpr std::uint32_t kContextI386 = 0x10000;
inline constexpr std::uint32_t kContextFull32 = kContextI386 | 0x7;

inline constexpr std::size_t kContextFlagsOffset32 = 0x00;
inline constexpr std::size_t kContextSegGsOffset32 = 0x8C;
inline constexpr std::size_t kContextSegFsOffset32 = 0x90;
inline constexpr std::size_t kContextSegEsOffset32 = 0x94;
inline constexpr std::size_t kContextSegDsOffset32 = 0x98;
inline constexpr std::size_t kContextEdiOffset32 = 0x9C;
inline constexpr std::size_t kContextEsiOffset32 = 0xA0;
inline constexpr std::size_t kContextEbxOffset32 = 0xA4;
inline constexpr std::size_t kContextEdxOffset32 = 0xA8;
inline constexpr std::size_t kContextEcxOffset32 = 0xAC;
inline constexpr std::size_t kContextEaxOffset32 = 0xB0;
inline constexpr std::size_t kContextEbpOffset32 = 0xB4;
inline constexpr std::size_t kContextEipOffset32 = 0xB8;
inline constexpr std::size_t kContextSegCsOffset32 = 0xBC;
inline constexpr std::size_t kContextEFlagsOffset32 = 0xC0;
inline constexpr std::size_t kContextEspOffset32 = 0xC4;
inline constexpr std::size_t kContextSegSsOffset32 = 0xC8;

// GPR slots in CONTEXT32 order, index-matched to the engine's Intel-order
// EAX=0..EDI=7 register table.
inline constexpr std::array<std::size_t, 8> kContextGprOffsets32{
    kContextEaxOffset32, kContextEcxOffset32, kContextEdxOffset32, kContextEbxOffset32,
    kContextEspOffset32, kContextEbpOffset32, kContextEsiOffset32, kContextEdiOffset32};

// -- EXCEPTION_RECORD (x86), winnt.h ------------------------------------------

inline constexpr std::size_t kExceptionRecordSize32 = 0x50;
inline constexpr std::size_t kRecordCodeOffset32 = 0x00;
inline constexpr std::size_t kRecordFlagsOffset32 = 0x04;
inline constexpr std::size_t kRecordInnerOffset32 = 0x08;
inline constexpr std::size_t kRecordAddressOffset32 = 0x0C;
inline constexpr std::size_t kRecordNumberParametersOffset32 = 0x10;
inline constexpr std::size_t kRecordInformationOffset32 = 0x14;

// x86 user-dispatch stack shape (32-bit kernel): at KiUserExceptionDispatcher
// entry [esp] is the EXCEPTION_RECORD pointer and [esp+4] the CONTEXT pointer.
inline constexpr std::size_t kUserDispatchStackSlots32 = 8; // frame under the structs

// Exception codes accepted by the dispatch (winnt.h).
inline constexpr std::uint32_t kStatusBreakpoint = 0x80000003;
inline constexpr std::uint32_t kStatusAccessViolation = 0xC0000005;
// __fastfail's reported code: int 0x29 never dispatches, but the crash keeps
// the real Windows spelling.
inline constexpr std::uint32_t kStatusStackBufferOverrun = 0xC0000409;

// The real-CPU #UD: an instruction the engine cannot decode or execute is
// surfaced to the guest as a fault its own SEH decides on.
inline constexpr std::uint32_t kStatusIllegalInstruction = 0xC000001D;

// ACCESS_VIOLATION information array: [0] access kind, [1] faulting address.
inline constexpr std::uint64_t kAccessRead = 0;
inline constexpr std::uint64_t kAccessWrite = 1;
inline constexpr std::uint64_t kAccessExecute = 8;

// -- register snapshot --------------------------------------------------------

// The guest facts one dispatch needs, read at the exception point in the
// engine's register spelling; the writer maps them into the Win64 layout.
struct RegisterSnapshot {
    std::array<std::uint64_t, 16> gpr{};
    std::uint64_t rip{};
    std::uint32_t eflags{};
    std::uint16_t cs{};
    std::uint16_t ds{};
    std::uint16_t es{};
    std::uint16_t fs{};
    std::uint16_t gs{};
    std::uint16_t ss{};
};

// Writes one CONTEXT (x64 shape): flag/integer/segment fields from the
// snapshot, the XSAVE area and debug registers zero-filled (the snapshot
// carries no debugger state).
void write_context(std::uint8_t* context, const RegisterSnapshot& snapshot);

// Writes one EXCEPTION_RECORD (x64 shape): code, address, and the
// information array up to the wire maximum (the C++ EH 0xE06D7363 record
// carries five entries; EXCEPTION_MAXIMUM_PARAMETERS is the hard bound).
void write_record(std::uint8_t* record, std::uint32_t code, std::uint64_t address,
                  const std::uint64_t* information, std::size_t information_count);

// x86 twins: same snapshot spelling, 32-bit structure shapes (4-byte GPR
// slots, Eip, u32 information entries).
void write_context_x86(std::uint8_t* context, const RegisterSnapshot& snapshot);
void write_record_x86(std::uint8_t* record, std::uint32_t code, std::uint64_t address,
                      const std::uint64_t* information, std::size_t information_count);

} // namespace sheller::engine::exceptions

#endif // SHELLER_ENGINE_EXCEPTION_LAYOUT_H
