#include "avx_shim.h"

#include <cstring>

namespace sheller::engine {
namespace {

// -- AVX data-move shim ---------------------------------------------------------
// The captured ntdll picks its memmove variant from CPU features baked in at
// capture time; on an AVX host that variant executes VEX.256 moves unicorn2's
// TCG cannot translate (QEMU TCG tops out at SSE). The guest code is left
// untouched: this hook interprets the handful of pure data moves the variant
// actually executes (all on ymm0) against the exposed YMM register file, and
// fails loudly on anything outside the subset - never silent corruption.

constexpr std::size_t kYmmBytes = 32;

struct VexPrefix {
    std::size_t length{};
    std::uint8_t opcode{};
    std::uint8_t vvvv{};
    std::uint8_t pp{};
    std::uint8_t map{};
    std::uint8_t r_ext{};
    std::uint8_t x_ext{};
    std::uint8_t b_ext{};
    bool l256{};
};

bool decode_vex(const std::uint8_t* code, const std::size_t max, VexPrefix& vex)
{
    if (max < 3) {
        return false;
    }
    if (code[0] == 0xC4) {
        if (max < 4) {
            return false;
        }
        vex.length = 3;
        vex.r_ext = ((code[1] >> 7) & 1) == 0;
        vex.x_ext = ((code[1] >> 6) & 1) == 0;
        vex.b_ext = ((code[1] >> 5) & 1) == 0;
        vex.map = code[1] & 0x1F;
        vex.vvvv = (~code[2] >> 3) & 0xF;
        vex.l256 = ((code[2] >> 2) & 1) != 0;
        vex.pp = code[2] & 0x3;
        vex.opcode = code[3];
        return true;
    }
    if (code[0] == 0xC5) {
        vex.length = 2;
        vex.r_ext = ((code[1] >> 7) & 1) == 0;
        vex.x_ext = false;
        vex.b_ext = false;
        vex.map = 1;
        vex.vvvv = (~code[1] >> 3) & 0xF;
        vex.l256 = ((code[1] >> 2) & 1) != 0;
        vex.pp = code[1] & 0x3;
        vex.opcode = code[2];
        return true;
    }
    return false;
}

// AVX-shim memory decode: only reachable in x64 guests (the x86 CPUID
// answer masks AVX off), so the 64-bit GPR table is pinned here.
std::uint64_t read_gpr(uc_engine* const uc, const std::size_t index)
{
    std::uint64_t value = 0;
    if (index < kGprRegisters64.size()) {
        uc_reg_read(uc, kGprRegisters64[index], &value);
    }
    return value;
}

bool read_ymm(uc_engine* const uc, const std::size_t index, std::uint8_t (&out)[kYmmBytes])
{
    return uc_reg_read(uc, UC_X86_REG_YMM0 + static_cast<int>(index), out) == UC_ERR_OK;
}

bool write_ymm(uc_engine* const uc, const std::size_t index, const std::uint8_t (&in)[kYmmBytes])
{
    return uc_reg_write(uc, UC_X86_REG_YMM0 + static_cast<int>(index), in) == UC_ERR_OK;
}

struct VectorOperand {
    bool is_register{};
    std::size_t index{};     // ymm/xmm register number
    std::uint64_t address{}; // effective address when memory
};

// ModRM + SIB + displacement. RIP-relative (mod 0 / rm 5) does not occur in
// the subset and reads as unsupported.
bool decode_rm_operand(uc_engine* const uc, const std::uint8_t* code, const std::size_t max,
                       const VexPrefix& vex, std::size_t& cursor, VectorOperand& operand)
{
    if (cursor >= max) {
        return false;
    }
    const auto modrm = code[cursor++];
    const auto mod = modrm >> 6;
    const auto raw_rm = modrm & 7;
    operand.is_register = mod == 3;
    operand.index = raw_rm + vex.b_ext * 8;
    if (operand.is_register) {
        return true;
    }

    std::uint64_t address = 0;
    auto base_index = raw_rm + vex.b_ext * 8;
    auto base_present = true;
    auto index_present = false;
    std::uint64_t index_value = 0;
    std::uint64_t scale = 1;
    std::uint64_t displacement = 0;
    if (raw_rm == 4) {
        if (cursor >= max) {
            return false;
        }
        const auto sib = code[cursor++];
        const auto index_field = (sib >> 3) & 7;
        const auto base_field = sib & 7;
        scale = 1ULL << (sib >> 6);
        index_present = index_field != 4;
        index_value = read_gpr(uc, index_field + vex.x_ext * 8);
        base_index = base_field + vex.b_ext * 8;
        if (base_field == 5 && mod == 0) {
            base_present = false;
        }
    } else if (raw_rm == 5 && mod == 0) {
        base_present = false; // rip-relative: outside the subset
        return false;
    }
    if (base_present) {
        address = read_gpr(uc, base_index);
    }
    if (mod == 1) {
        if (cursor >= max) {
            return false;
        }
        displacement = static_cast<std::uint64_t>(static_cast<std::int8_t>(code[cursor++]));
    } else if (mod == 2 || (mod == 0 && raw_rm == 5)) {
        if (cursor + 4 > max) {
            return false;
        }
        // disp32 is SIGNED - negative displacements dominate real code
        // (stack frames, structure walks); assembling it unsigned points
        // every such operand 4GB past its true target.
        std::int32_t signed_displacement = 0;
        for (std::size_t i = 0; i < 4; ++i) {
            signed_displacement |= static_cast<std::int32_t>(code[cursor + i]) << (8 * i);
        }
        displacement = static_cast<std::uint64_t>(signed_displacement);
        cursor += 4;
    }
    if (index_present) {
        address += index_value * scale;
    }
    operand.address = address + displacement;
    return true;
}

bool rm_operand_is_register(const VectorOperand& operand)
{
    return operand.is_register;
}

} // namespace

bool on_insn_invalid_callback(uc_engine* const uc, void* const user_data)
{
    auto* state = static_cast<SyscallRunState*>(user_data);
    const auto rip = read_rip(uc);
    std::uint8_t code[16] = {};
    if (uc_mem_read(uc, rip, code, sizeof code) != UC_ERR_OK) {
        return false;
    }

    // Any instruction outside the shim's subset is a real-CPU #UD: surface
    // it to the guest as STATUS_ILLEGAL_INSTRUCTION and let its own SEH
    // decide (the guest sees a real Windows machine).
    const auto fail_as_ud = [&]() {
        state->exception = {.valid = true,
                            .unhandled = false,
                            .code = exceptions::kStatusIllegalInstruction,
                            .pc = rip,
                            .information = {},
                            .information_count = 0};
        uc_emu_stop(uc);
        return false;
    };
    // A shim data-movement access that hits unmapped or protected memory is
    // a page fault on the real CPU (#PF → STATUS_ACCESS_VIOLATION with the
    // access type and fault address), never #UD: hand it to the guest's own
    // dispatch exactly like the invalid-memory hook would.
    const auto fail_as_pf = [&](const std::uint64_t fault_address, const bool is_write) {
        state->exception = {
            .valid = true,
            .unhandled = false,
            .code = exceptions::kStatusAccessViolation,
            .pc = rip,
            .information = {is_write ? exceptions::kAccessWrite : exceptions::kAccessRead,
                            fault_address},
            .information_count = 2};
        uc_emu_stop(uc);
        return false;
    };

    VexPrefix vex{};
    if (!decode_vex(code, sizeof code, vex)) {
        return fail_as_ud();
    }

    std::size_t cursor = vex.length + 1; // prefix + opcode
    std::uint8_t ymm[kYmmBytes] = {};
    auto handled = false;

    // vzeroupper: zero the upper lanes of every vector register.
    if (vex.map == 1 && vex.opcode == 0x77 && vex.pp == 0) {
        handled = true;
        for (std::size_t i = 0; i < 16 && handled; ++i) {
            if (!read_ymm(uc, i, ymm)) {
                handled = false;
                break;
            }
            std::memset(ymm + 16, 0, 16);
            handled = write_ymm(uc, i, ymm);
        }
        cursor = vex.length + 1;
    }
    // Everything else in the subset is VEX.256.66 data movement. The VEX reg
    // field is one operand (store source / load destination / insert target);
    // the rm field is the other (memory or a ymm register).
    else if (vex.map == 1 && vex.pp == 1 && vex.l256 &&
             (vex.opcode == 0x74 || vex.opcode == 0x75 || vex.opcode == 0x76)) {
        // vpcmpeq{b,w,d} ymm1, ymm2, ymm/m256: per-lane equality mask
        // (the memchr/compare loops inside real ntdll string code).
        const std::size_t element_size = vex.opcode == 0x74 ? 1 : vex.opcode == 0x75 ? 2 : 4;
        const auto reg_index = static_cast<std::size_t>((code[cursor] >> 3) & 7) + vex.r_ext * 8;
        VectorOperand operand{};
        if (!decode_rm_operand(uc, code, sizeof code, vex, cursor, operand)) {
            return fail_as_ud();
        }
        std::uint8_t src1[kYmmBytes] = {};
        std::uint8_t src2[kYmmBytes] = {};
        handled = read_ymm(uc, vex.vvvv, src1);
        if (handled) {
            if (rm_operand_is_register(operand)) {
                handled = read_ymm(uc, operand.index, src2);
            } else if (uc_mem_read(uc, operand.address, src2, kYmmBytes) != UC_ERR_OK) {
                return fail_as_pf(operand.address, false);
            } else {
                handled = true;
            }
        }
        if (handled) {
            std::uint8_t dst[kYmmBytes] = {};
            for (std::size_t lane = 0; lane < kYmmBytes; lane += element_size) {
                const bool equal = std::memcmp(src1 + lane, src2 + lane, element_size) == 0;
                std::memset(dst + lane, equal ? 0xFF : 0x00, element_size);
            }
            handled = write_ymm(uc, reg_index, dst);
        }
    } else if (vex.map == 1 && vex.pp == 1 && vex.l256 && vex.opcode == 0xD7) {
        // vpmovmskb r32, ymm: gather each byte's sign bit into a 32-bit
        // mask (register-form only, mod=11; memory form does not exist).
        const auto modrm = code[cursor++];
        if ((modrm >> 6) != 3) {
            return fail_as_ud();
        }
        std::uint8_t src[kYmmBytes] = {};
        handled = read_ymm(uc, static_cast<std::size_t>(modrm & 0x7) + vex.b_ext * 8, src);
        if (handled) {
            std::uint32_t mask = 0;
            for (std::size_t i = 0; i < kYmmBytes; ++i) {
                mask |= static_cast<std::uint32_t>(src[i] >> 7) << i;
            }
            const auto dst_index = static_cast<std::size_t>((modrm >> 3) & 0x7) + vex.r_ext * 8;
            uc_reg_write(uc, kGprRegisters64.at(dst_index), &mask);
        }
    } else if (vex.l256) {
        const auto reg_index = static_cast<std::size_t>((code[cursor] >> 3) & 7) + vex.r_ext * 8;
        VectorOperand operand{};
        if (!decode_rm_operand(uc, code, sizeof code, vex, cursor, operand)) {
            return fail_as_ud();
        }
        if (vex.map == 1 && (vex.opcode == 0x11 || vex.opcode == 0x29 || vex.opcode == 0x7F)) {
            // vmovups/vmovaps/vmovdqa/vmovdqu: store ymm[reg] to rm.
            handled = read_ymm(uc, reg_index, ymm);
            if (handled) {
                if (rm_operand_is_register(operand)) {
                    handled = write_ymm(uc, operand.index, ymm);
                } else {
                    const auto write_err = uc_mem_write(uc, operand.address, ymm, kYmmBytes);
                    handled = write_err == UC_ERR_OK;
                    if (!handled) {
                        // A store into unmapped/protected memory is a page
                        // fault on the real CPU, not #UD: surface it as
                        // STATUS_ACCESS_VIOLATION with the faulting address
                        // and let the guest's own dispatch decide.
                        state->exception = {
                            .valid = true,
                            .unhandled = false,
                            .code = exceptions::kStatusAccessViolation,
                            .pc = rip,
                            .information = {exceptions::kAccessWrite, operand.address},
                            .information_count = 2};
                        uc_emu_stop(uc);
                        return false;
                    }
                }
            }
        } else if (vex.map == 1 &&
                   (vex.opcode == 0x10 || vex.opcode == 0x28 || vex.opcode == 0x6F)) {
            // vmovups/vmovaps/vmovdqa/vmovdqu: load rm into ymm[reg].
            handled = rm_operand_is_register(operand);
            if (handled) {
                handled = read_ymm(uc, operand.index, ymm) && write_ymm(uc, reg_index, ymm);
            } else {
                if (uc_mem_read(uc, operand.address, ymm, kYmmBytes) != UC_ERR_OK) {
                    return fail_as_pf(operand.address, false);
                }
                handled = write_ymm(uc, reg_index, ymm);
            }
        } else if (vex.map == 3 && vex.opcode == 0x18 && vex.pp == 1 && cursor < sizeof code) {
            // vinsertf128 dst, src1, src2(mem128/xmm), imm8 (0F3A 18).
            const auto imm = code[cursor++];
            std::uint8_t src1[kYmmBytes] = {};
            std::uint8_t insert[kYmmBytes] = {};
            handled = read_ymm(uc, vex.vvvv, src1);
            if (handled) {
                if (rm_operand_is_register(operand)) {
                    handled = read_ymm(uc, operand.index, insert);
                } else if (uc_mem_read(uc, operand.address, insert, 16) != UC_ERR_OK) {
                    return fail_as_pf(operand.address, false);
                } else {
                    handled = true;
                }
            }
            if (handled) {
                std::uint8_t dst[kYmmBytes] = {};
                if ((imm & 1) != 0) {
                    std::memcpy(dst, src1, 16); // low = src1 low
                    std::memcpy(dst + 16, insert, 16);
                } else {
                    std::memcpy(dst, insert, 16); // low = inserted xmm
                    std::memcpy(dst + 16, src1 + 16, 16);
                }
                handled = write_ymm(uc, reg_index, dst);
            }
        } else if (vex.map == 3 && vex.opcode == 0x19 && vex.pp == 1 && cursor < sizeof code) {
            // vextractf128 dst(mem128/xmm), src, imm8 (0F3A 19).
            const auto imm = code[cursor++];
            std::uint8_t src[kYmmBytes] = {};
            handled = read_ymm(uc, reg_index, src);
            if (handled) {
                const std::uint8_t* half = (imm & 1) != 0 ? src + 16 : src;
                if (operand.is_register) {
                    // xmm destination: the low 128 bits of the ymm register.
                    std::uint8_t dst[kYmmBytes] = {};
                    handled = read_ymm(uc, operand.index, dst);
                    if (handled) {
                        std::memcpy(dst, half, 16);
                        handled = write_ymm(uc, operand.index, dst);
                    }
                } else if (uc_mem_write(uc, operand.address, half, 16) != UC_ERR_OK) {
                    return fail_as_pf(operand.address, true);
                } else {
                    handled = true;
                }
            }
        }
    }

    if (!handled) {
        return fail_as_ud(); // outside the subset: guest-visible #UD
    }
    // The hook runs at translation time, so resuming inside the current
    // translation block would hit its cached bad instruction again: stop the
    // emulation and let the run loop re-enter at the advanced RIP.
    state->avx_resume = true;
    const std::uint64_t next = rip + cursor;
    uc_reg_write(uc, UC_X86_REG_RIP, &next);
    uc_emu_stop(uc);
    return true;
}

} // namespace sheller::engine
