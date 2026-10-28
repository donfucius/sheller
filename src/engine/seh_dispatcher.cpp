// Engine-side SEH dispatch. See seh_dispatcher.h for the contract.
//
// Dispatch model: the engine walks frames itself (x64: .pdata binary search
// + virtual unwind; x86: TEB FS:[0] chain), interprets scope tables and
// handler dispositions, and stages each handler/filter/VEH callback as a
// real guest-code call that returns through the engine trampoline (int3
// page consumed by the INTR hook). No ntdll code participates.

#include "seh_dispatcher.h"

#include "diag_trace.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string_view>

// One record per trace line, delivered through the host's log facade. [seh-diag] is
// the marker a reader filters on, the switch is the SHELLER_SEH_TRACE the traces have
// always had (cached in diag_trace.h with the other site switches), and the format is
// std::format's, so a mismatched argument is a compile error rather than a stack read.
//
// The switch is tested before the arguments are evaluated, and the expansion is one
// statement again. Several of these calls pass a result rather than a value - read_gpr
// walks a register read through the emulator - so an argument list evaluated on a call
// nobody will print is work paid for a record nobody asked for; and the do/while is what
// lets the macro stand alone after an if/else without deciding which branch the else
// belongs to.
#define SEH_TRACE(...)                                                                             \
    do {                                                                                           \
        if (::sheller::engine::diag::seh_on()) {                                                   \
            ::sheller::engine::diag::emit(::sheller::log::level::kDebug,                           \
                                          ::sheller::engine::diag::seh_on(),                       \
                                          "[seh-diag] " __VA_ARGS__);                              \
        }                                                                                          \
    } while (false)

namespace sheller::engine::seh {

namespace {

// -- winnt dispositions (winnt.h; this layer builds on Linux too) -------------

constexpr std::uint64_t kExceptionContinueSearch = 0;
constexpr std::uint64_t kExceptionContinueExecution = 0xFFFFFFFFFFFFFFFFULL; // -1
constexpr std::uint64_t kExceptionExecuteHandler = 1;
constexpr std::uint64_t kExceptionNestedException = 0xFFFFFFFFFFFFFFFEULL; // -2
// VEH handlers return the __except-filter spellings: 0 = continue the walk,
// -1 = resume through the (possibly rewritten) CONTEXT.
constexpr std::uint32_t kVehContinueSearch = 0;
constexpr std::uint32_t kVehContinueExecution = 0xFFFFFFFF; // -1
constexpr std::uint32_t kExceptionUnwindingFlag = 0x2;      // EXCEPTION_UNWINDING

constexpr std::size_t kMaxLayers = 8;  // nested dispatch bound
constexpr std::size_t kMaxFrames = 64; // per-layer walk depth bound

// -- guest register IO (mode-shaped; Intel order RAX=0..R15) -------------------

constexpr std::array<uc_x86_reg, 16> kGpr64{
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_RSP, UC_X86_REG_RBP,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R8,  UC_X86_REG_R9,  UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15};

constexpr std::array<uc_x86_reg, 8> kGpr32{UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX,
                                           UC_X86_REG_EBX, UC_X86_REG_ESP, UC_X86_REG_EBP,
                                           UC_X86_REG_ESI, UC_X86_REG_EDI};

std::uint64_t read_gpr(uc_engine* uc, bool x86, std::size_t index)
{
    std::uint64_t value = 0;
    if (x86) {
        std::uint32_t v32 = 0;
        uc_reg_read(uc, kGpr32.at(index), &v32);
        value = v32;
    } else {
        uc_reg_read(uc, kGpr64.at(index), &value);
    }
    return value;
}

void write_gpr(uc_engine* uc, bool x86, std::size_t index, std::uint64_t value)
{
    if (x86) {
        const auto v32 = static_cast<std::uint32_t>(value);
        uc_reg_write(uc, kGpr32.at(index), &v32);
    } else {
        uc_reg_write(uc, kGpr64.at(index), &value);
    }
}

std::uint64_t read_rip(uc_engine* uc, bool x86)
{
    std::uint64_t rip = 0;
    if (x86) {
        std::uint32_t v32 = 0;
        uc_reg_read(uc, UC_X86_REG_EIP, &v32);
        rip = v32;
    } else {
        uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    }
    return rip;
}

void write_rip(uc_engine* uc, bool x86, std::uint64_t rip)
{
    if (x86) {
        const auto v32 = static_cast<std::uint32_t>(rip);
        uc_reg_write(uc, UC_X86_REG_EIP, &v32);
    } else {
        uc_reg_write(uc, UC_X86_REG_RIP, &rip);
    }
}

template <typename T> bool read_guest(uc_engine* uc, std::uint64_t address, T& out)
{
    return uc_mem_read(uc, address, &out, sizeof out) == UC_ERR_OK;
}

template <typename T> bool write_guest(uc_engine* uc, std::uint64_t address, const T& value)
{
    return uc_mem_write(uc, address, &value, sizeof value) == UC_ERR_OK;
}

// -- module attribution --------------------------------------------------------

struct ModuleSpan {
    std::uint64_t base{};
    std::uint64_t size{};
};

bool module_for(const mem_region::MemRegionMap& map, std::uint64_t pc, ModuleSpan& out)
{
    for (std::size_t i = 0; i < map.module_count(); ++i) {
        const auto& module = map.module(i);
        if (module.synthesized) {
            continue; // synthesized unknown images stay outside EH frame attribution
        }
        if (pc >= module.base && pc < module.base + module.size) {
            out = {module.base, module.size};
            return true;
        }
    }
    return false;
}

// -- PE exception directory + RUNTIME_FUNCTION lookup --------------------------

struct Directory {
    std::uint32_t rva{};
    std::uint32_t size{};
};

bool read_directory(uc_engine* uc, std::uint64_t base, std::uint32_t index, Directory& out)
{
    std::uint32_t e_lfanew = 0;
    if (!read_guest(uc, base + 0x3C, e_lfanew)) {
        return false;
    }
    std::array<std::uint8_t, 4> signature{};
    if (uc_mem_read(uc, base + e_lfanew, signature.data(), signature.size()) != UC_ERR_OK ||
        std::memcmp(signature.data(), "PE\0\0", 4) != 0) {
        return false;
    }
    std::uint16_t magic = 0;
    if (!read_guest(uc, base + e_lfanew + 0x18, magic)) {
        return false;
    }
    const std::uint64_t dirs =
        magic == 0x20B ? base + e_lfanew + 0x18 + 0x70 : base + e_lfanew + 0x18 + 0x60;
    const std::uint64_t entry = dirs + static_cast<std::uint64_t>(index) * 8;
    std::uint32_t rva = 0;
    std::uint32_t size = 0;
    if (!read_guest(uc, entry, rva) || !read_guest(uc, entry + 4, size) || rva == 0) {
        return false;
    }
    out = {rva, size};
    return true;
}

struct RuntimeFunction {
    std::uint32_t begin{};
    std::uint32_t end{};
    std::uint32_t unwind_rva{};
};

bool find_runtime_function(uc_engine* uc, std::uint64_t module_base, std::uint32_t rva,
                           RuntimeFunction& out, std::uint64_t& entry_va)
{
    Directory dir{};
    if (!read_directory(uc, module_base, 3, dir)) {
        return false;
    }
    const auto count = dir.size / sizeof(RuntimeFunction);
    std::uint64_t low = 0;
    std::uint64_t high = count;
    while (low < high) {
        const auto mid = low + (high - low) / 2;
        RuntimeFunction rf{};
        if (!read_guest(uc, module_base + dir.rva + mid * sizeof(RuntimeFunction), rf)) {
            return false;
        }
        if (rva < rf.begin) {
            high = mid;
        } else if (rva >= rf.end) {
            low = mid + 1;
        } else {
            out = rf;
            entry_va = module_base + dir.rva + mid * sizeof(RuntimeFunction);
            return true;
        }
    }
    return false;
}

// -- UNWIND_INFO parsing + prolog accounting -----------------------------------

struct UnwindInfo {
    std::uint32_t flags{};
    std::uint32_t count_of_codes{};
    std::uint32_t frame_register{};     // nonvolatile reg used as frame pointer (0 = none)
    std::uint32_t frame_offset_units{}; // its distance from entry rsp, scaled by 16
    std::uint64_t info_va{};
    std::uint64_t handler_rva{};  // language handler RVA (0 = none)
    std::uint64_t handler_data{}; // guest VA of the handler data (scope table)
    bool chained{};
};

bool parse_unwind_info(uc_engine* uc, std::uint64_t info_va, UnwindInfo& out)
{
    std::array<std::uint8_t, 4> header{};
    if (uc_mem_read(uc, info_va, header.data(), header.size()) != UC_ERR_OK) {
        return false;
    }
    out.info_va = info_va;
    out.flags = (header[0] >> 3) & 0x1F;
    out.count_of_codes = header[2];
    // UNWIND_INFO byte 3: FrameRegister : 4, FrameOffset : 4 (scaled by 16)
    out.frame_register = header[3] & 0xF;
    out.frame_offset_units = (header[3] >> 4) & 0xF;
    out.chained = (out.flags & 0x4) != 0;
    const bool has_handler = (out.flags & (0x1 | 0x2)) != 0;
    if (!has_handler) {
        return true;
    }
    const std::uint64_t handler_pos =
        info_va + 4 + (out.count_of_codes + out.count_of_codes % 2) * 2;
    std::uint32_t handler = 0;
    if (!read_guest(uc, handler_pos, handler)) {
        return false;
    }
    out.handler_rva = handler;
    out.handler_data = handler_pos + 4;
    return true;
}

// Sums the prolog's rsp effects for unwind codes that have already executed
// at `rip_offset` bytes into the function. Full UNWIND_OP set: saving-only
// ops advance the cursor, push/alloc ops advance both cursor and total.

// -- VEH list-head discovery -----------------------------------------------------

const mem_region::ModuleRecord* ntdll_module(const mem_region::MemRegionMap& map)
{
    for (std::size_t i = 0; i < map.module_count(); ++i) {
        const auto& module = map.module(i);
        if (std::string_view(module.name.data()) == "ntdll.dll") {
            return &module;
        }
    }
    return nullptr;
}

bool exec_section(const mem_region::MemRegionMap& map, std::uint64_t va)
{
    // IMAGE_SCN_MEM_EXECUTE (winnt.h)
    constexpr std::uint32_t kScnMemExecute = 0x20000000;
    const auto attribution = map.query(va);
    return attribution.has_value() &&
           attribution->kind == mem_region::AttributionKind::kImageSection &&
           !map.module(attribution->module_index).synthesized &&
           (attribution->characteristics & kScnMemExecute) != 0;
}

// A real VEH handler is sample or runtime code; ntdll-resident "handlers" are
// the misdecode signature - the key search decoding a data qword into one of
// ntdll's own executable addresses (KiUserExceptionDispatcher above all), and
// a callback staged there reads kernel-entry stack args and returns to garbage.
bool inside_ntdll(const mem_region::MemRegionMap& map, std::uint64_t va)
{
    const auto* ntdll = ntdll_module(map);
    return ntdll != nullptr && va >= ntdll->base && va < ntdll->base + ntdll->size;
}

// Resolves the handler of one VEH registration node. x64 nodes hold the plain
// pointer at +0x10 (older builds) or the encoded pointer at +0x20 (Win10+);
// wow64 nodes always carry the raw handler at +8. Returns false when the node
// holds no executable handler - the walk then advances past it.
bool veh_node_handler(uc_engine* uc, SehDispatchState& seh, const mem_region::MemRegionMap& map,
                      bool x86, std::uint64_t node, std::uint64_t& handler);

// The VEH list heads (LdrpVectorHandlerList and its tail-insert twin) are not
// exported, and code-pattern scans of the registration stub rotate with every
// ntdll build (recent stubs are a bare jmp; the list loads are computed
// through registers). Discover a live head by data shape instead: a non-empty
// doubly-linked list inside the ntdll image, in a non-executable section,
// whose first node back-links to the head AND resolves to an executable
// handler - the list-shaped lookalikes scattered through the image's data
// fail that resolution. Empty lists are self-pointed and skipped; the first
// match in address order wins (the head-insert list sits below the
// tail-insert list in the builds observed). A failed scan disables VEH
// traversal for the run - the fidelity mode covers those samples.
std::uint64_t find_veh_head(uc_engine* uc, SehDispatchState& seh,
                            const mem_region::MemRegionMap& map, bool x86)
{
    const std::uint64_t pointer = x86 ? 4 : 8;
    const auto* ntdll = ntdll_module(map);
    if (ntdll == nullptr) {
        return 0;
    }
    const auto span =
        static_cast<std::size_t>((std::min)(ntdll->size, static_cast<std::uint64_t>(0x800000ULL)));
    std::vector<std::uint8_t> image(span);
    if (uc_mem_read(uc, ntdll->base, image.data(), image.size()) != UC_ERR_OK) {
        return 0;
    }
    auto slot_at = [&](std::size_t offset) {
        std::uint64_t value = 0;
        std::memcpy(&value, image.data() + offset, static_cast<std::size_t>(pointer));
        return value;
    };
    for (std::size_t off = 0; off + 2 * pointer <= span; off += pointer) {
        const auto candidate = ntdll->base + off;
        const auto flink = slot_at(off);
        const auto blink = slot_at(off + static_cast<std::size_t>(pointer));
        if (flink == 0 || flink == candidate || blink == candidate) {
            continue; // empty list (self-pointed) or not a list head
        }
        std::uint64_t back = 0;
        if (!read_guest(uc, flink + pointer, back) || back != candidate) {
            continue; // not a consistent (head, first node) pair
        }
        // The head lives in the image's data, never in a code section.
        if (exec_section(map, candidate)) {
            continue;
        }
        // The decisive gate: the first node must resolve to an executable
        // handler (plain, or encoded with a recoverable key).
        std::uint64_t handler = 0;
        if (!veh_node_handler(uc, seh, map, x86, flink, handler)) {
            continue;
        }
        SEH_TRACE("veh head={:x} node={:x} handler={:x}", candidate, flink, handler);
        return candidate;
    }
    return 0;
}

// -- VEH node handler resolution -------------------------------------------------

// Win10+ ntdll stores the VEH handler encoded: E = ror64(H ^ D, D & 63) with
// a per-process 32-bit key D at a build-specific data RVA (0 = identity).
// The engine recovers D from one observed pair without any code-pattern
// knowledge: H is a user-mode VA (< 2^48) and D is zero-extended 32-bit, so
// the true rotation r must satisfy rol64(E, r) >> 48 == 0 - that pins r
// essentially uniquely - and D then must decode E into an executable module
// section. Cached per run; keyless builds (D == 0 / plain node+0x10) resolve
// without it.
std::uint64_t veh_decode_key(uc_engine* uc, [[maybe_unused]] SehDispatchState& seh,
                             const mem_region::MemRegionMap& map, std::uint64_t encoded)
{
    const auto* ntdll = ntdll_module(map);
    if (ntdll == nullptr) {
        return 0;
    }
    const auto span =
        static_cast<std::size_t>((std::min)(ntdll->size, static_cast<std::uint64_t>(0x800000ULL)));
    std::vector<std::uint8_t> image(span);
    if (uc_mem_read(uc, ntdll->base, image.data(), image.size()) != UC_ERR_OK) {
        return 0;
    }
    // The rotation is pinned by the canonical user-space shape of H.
    for (std::uint64_t r = 0; r < 64; ++r) {
        const auto rotated = (r == 0) ? encoded : (encoded << r) | (encoded >> (64 - r));
        if ((rotated >> 48) != 0) {
            continue;
        }
        std::uint64_t fallback = 0;
        for (std::size_t off = 0; off + 8 <= span; off += 4) {
            std::uint32_t key32 = 0;
            std::memcpy(&key32, image.data() + off, sizeof key32);
            if ((key32 & 63) != r) {
                continue; // the key carries its own rotation
            }
            const auto key = static_cast<std::uint64_t>(key32);
            const auto handler = rotated ^ key;
            if (inside_ntdll(map, handler)) {
                continue; // a key that decodes into ntdll itself is a misdecode
            }
            const auto attribution = map.query(handler);
            if (!attribution.has_value() ||
                attribution->kind != mem_region::AttributionKind::kImageSection) {
                continue;
            }
            if (!exec_section(map, handler)) {
                continue;
            }
            // Prefer the writable data sections the key global lives in.
            constexpr std::uint32_t kScnMemWrite = 0x80000000;
            if ((attribution->characteristics & kScnMemWrite) != 0) {
                return key;
            }
            if (fallback == 0) {
                fallback = key;
            }
        }
        if (fallback != 0) {
            return fallback;
        }
    }
    return 0;
}

// Resolves the handler of one VEH registration node. x64 requires the modern
// encoded form: a nonzero node+0x20 whose shape (readable non-exec refcount
// block at +0x10, zeroed flags at +0x18) holds before the decode key is
// derived - list-shaped lookalikes get rejected here instead of poisoning
// the cached key, and a failed derivation is not cached either so a later
// true node still derives it fresh. wow64 nodes carry the raw handler at +8.
// Returns false when the node holds no executable handler - the walk then
// advances past it.
bool veh_node_handler(uc_engine* uc, SehDispatchState& seh, const mem_region::MemRegionMap& map,
                      bool x86, std::uint64_t node, std::uint64_t& handler)
{
    // Registration nodes come from RtlAddVectoredExceptionHandler's dynamic
    // allocation, never from ntdll's own image. A "node" inside the ntdll
    // image is a data lookalike, and whatever its fields decode to is poison:
    // the staged callback reads kernel-entry stack args and returns through
    // garbage (the observed misdecode staged ntdll's own dispatcher entry).
    if (inside_ntdll(map, node)) {
        return false;
    }
    if (x86) {
        std::uint32_t raw = 0;
        if (!read_guest(uc, node + 8, raw) || raw == 0 || !exec_section(map, raw)) {
            return false;
        }
        handler = raw;
        return true;
    }
    std::uint64_t encoded = 0;
    if (!read_guest(uc, node + 0x20, encoded) || encoded == 0) {
        return false;
    }
    std::uint64_t refcount = 0;
    std::uint32_t flags = 1;
    if (!read_guest(uc, node + 0x10, refcount) || refcount == 0 || exec_section(map, refcount) ||
        !read_guest(uc, node + 0x18, flags) || flags != 0) {
        SEH_TRACE("veh node={:x} shape enc={:x} ref={:x} flags={:x}", node, encoded, refcount,
                  flags);
        return false;
    }
    if (seh.veh_key_state == 0) {
        const auto key = veh_decode_key(uc, seh, map, encoded);
        if (key == 0) {
            return false; // not cached: a later node derives it fresh
        }
        seh.veh_decode_key = key;
        seh.veh_key_state = 1;
        SEH_TRACE("veh key={:x}", key);
    }
    const auto rotation = seh.veh_decode_key & 63;
    const auto rotated =
        rotation == 0 ? encoded : (encoded << rotation) | (encoded >> (64 - rotation));
    handler = rotated ^ seh.veh_decode_key;
    return handler != 0 && exec_section(map, handler) && !inside_ntdll(map, handler);
}

} // namespace

namespace {

// -- C++ frame-handler discrimination -------------------------------------------

// FuncInfo magic numbers (vcruntime source): the first DWORD of a C++ frame's
// handler data. The magic travels with every C++ exception ABI revision; a
// scope-table's Count can never reach these values.
constexpr std::array<std::uint32_t, 4> kFuncInfoMagics{0x19930520, 0x19930521, 0x19930522,
                                                       0x19930523};
constexpr std::string_view kCxxHandlerPrefix = "__CxxFrameHandler";

// x64 DISPATCHER_CONTEXT (winnt.h): ControlPc, ImageBase, FunctionEntry,
// EstablisherFrame, TargetIp, ContextRecord, LanguageHandler, HandlerData,
// HistoryTable, ScopeIndex+Fill0.
constexpr std::size_t kDcTargetIpOffset = 0x20;
constexpr std::size_t kDcScopeIndexOffset = 0x48;

// MSVC-linked images reference language handlers through a local jump thunk
// (the unwind RVA can only address inside the owning module, and
// __CxxFrameHandler* / __C_specific_handler live in the CRT DLLs): a
// `jmp [rip+disp32]` IAT slot load, or a plain `jmp rel32` chain. Follow up
// to four hops to the final VA.
std::uint64_t follow_jump_chain(uc_engine* uc, std::uint64_t va)
{
    for (std::size_t hop = 0; hop < 4; ++hop) {
        std::array<std::uint8_t, 8> code{};
        if (!read_guest(uc, va, code)) {
            return va;
        }
        if (code[0] == 0xFF && code[1] == 0x25) {
            // jmp [rip+disp32]: the IAT slot holds the resolved handler VA
            std::uint32_t disp = 0;
            std::memcpy(&disp, code.data() + 2, sizeof disp);
            std::uint64_t resolved = 0;
            if (!read_guest(uc, va + 6 + disp, resolved)) {
                return va;
            }
            return resolved;
        }
        if (code[0] == 0xE9) {
            std::int32_t rel = 0;
            std::memcpy(&rel, code.data() + 1, sizeof rel);
            va = va + 5 + static_cast<std::uint64_t>(rel);
            continue;
        }
        return va; // not a thunk: the VA is the handler itself (static CRT, ntdll)
    }
    return va;
}

// The export name of a guest VA, resolved against every mapped module's
// export directory (guest-memory PE walk; bounded, best effort).
bool export_name_for(uc_engine* uc, const mem_region::MemRegionMap& map, std::uint64_t va,
                     char* out, const std::size_t cap)
{
    for (std::size_t i = 0; i < map.module_count(); ++i) {
        const auto& module = map.module(i);
        if (module.synthesized) {
            continue; // synthesized unknown images carry no export tables to name
        }
        Directory dir{};
        if (!read_directory(uc, module.base, 0, dir)) {
            continue; // no exports (or not a PE image)
        }
        std::uint32_t names = 0;
        std::uint32_t addresses = 0;
        std::uint32_t name_table = 0;
        std::uint32_t ordinals = 0;
        if (!read_guest(uc, module.base + dir.rva + 0x18, names) ||
            !read_guest(uc, module.base + dir.rva + 0x1C, addresses) ||
            !read_guest(uc, module.base + dir.rva + 0x20, name_table) ||
            !read_guest(uc, module.base + dir.rva + 0x24, ordinals) || names == 0) {
            continue;
        }
        const auto bounded = (std::min)(names, dir.size / 4);
        for (std::uint32_t n = 0; n < bounded; ++n) {
            std::uint32_t name_rva = 0;
            if (!read_guest(uc, module.base + name_table + 4 * n, name_rva) || name_rva == 0) {
                continue;
            }
            std::array<char, 40> name{};
            if (uc_mem_read(uc, module.base + name_rva, name.data(), name.size() - 1) !=
                UC_ERR_OK) {
                continue;
            }
            if (std::string_view(name.data()).starts_with(kCxxHandlerPrefix)) {
                std::uint16_t ordinal = 0;
                std::uint32_t function_rva = 0;
                if (!read_guest(uc, module.base + ordinals + 2 * n, ordinal) ||
                    !read_guest(uc, module.base + addresses + 4 * ordinal, function_rva)) {
                    continue;
                }
                // forwarded exports resolve to other modules' names: the VA
                // match, not the name, is the test
                if (module.base + function_rva != va) {
                    continue;
                }
                std::snprintf(out, cap, "%s", name.data());
                return true;
            }
        }
    }
    return false;
}

} // namespace

// Test seam (seh_dispatcher.h): FuncInfo signature first - it covers /MT
// builds whose handler is a private static-CRT function - then thunk-follow
// plus export-name resolution for the /MD IAT-thunk shape. The scope-table
// semantics are the LAST resort and only on a shape-validated table: the
// first dword must be a sane entry count and the whole table must be
// readable. Anything else - notably the /MT CRT's private wrapper handlers,
// whose HandlerData first word is an RVA into their own metadata, not a
// count - runs as an opaque guest handler (the Cxx path stages the real
// function; it reads DispatcherContext.HandlerData and dispatches itself).
// Misreading a wrapper's metadata as a scope count both skipped the real
// handler and steered the walk into garbage.
HandlerKind classify_language_handler(uc_engine* uc, const mem_region::MemRegionMap& map,
                                      const std::uint64_t handler_va,
                                      const std::uint64_t handler_data)
{
    std::uint32_t magic = 0;
    if (read_guest(uc, handler_data, magic)) {
        for (const auto candidate : kFuncInfoMagics) {
            if (magic == candidate) {
                return HandlerKind::Cxx;
            }
        }
    }
    char name[40] = {};
    if (export_name_for(uc, map, follow_jump_chain(uc, handler_va), name, sizeof name) &&
        std::string_view(name).starts_with(kCxxHandlerPrefix)) {
        return HandlerKind::Cxx;
    }
    // Scope-table shape check: count sane, table extent readable. The bound
    // is generous (real tables carry single-digit counts); anything larger
    // is not a count.
    constexpr std::uint32_t kMaxScopeEntries = 4096;
    std::uint32_t count = 0;
    if (read_guest(uc, handler_data, count) && count >= 1 && count <= kMaxScopeEntries) {
        std::array<std::uint32_t, 4> last_scope{};
        if (read_guest(uc, handler_data + 4 + 16ull * (count - 1), last_scope)) {
            return HandlerKind::ScopeTable; // shape confirmed: interpret inline
        }
    }
    return HandlerKind::Cxx; // opaque: run the handler, it reads its own data
}

namespace {

// Opens the frame covering `pc` (module attribution, runtime function,
// unwind info with CHAININFO hop, language handler, scope table,
// establisher). `rsp_known` is the frame's rsp at the fault/call point.
bool open_frame(uc_engine* uc, const mem_region::MemRegionMap& map, bool x86,
                [[maybe_unused]] const SehDispatchState& seh, Frame& frame, std::uint64_t rsp_known)
{
    if (x86) {
        // x86 carries no function tables: the FS:[0] chain walk needs no
        // module attribution or unwind info - the chain record IS the frame.
        frame.establisher = rsp_known; // the chain record VA
        frame.opened = true;
        return true;
    }
    ModuleSpan module{};
    if (!module_for(map, frame.pc, module)) {
        return false;
    }
    frame.module_base = module.base;

    auto lookup_pc = frame.pc;
    RuntimeFunction rf{};
    std::uint64_t entry_va = 0;
    if (!find_runtime_function(uc, module.base, static_cast<std::uint32_t>(lookup_pc - module.base),
                               rf, entry_va)) {
        lookup_pc -= 1; // a call can be the function's last instruction
        if (!find_runtime_function(uc, module.base,
                                   static_cast<std::uint32_t>(lookup_pc - module.base), rf,
                                   entry_va)) {
            return false;
        }
    }
    frame.runtime_function = entry_va;
    frame.function_begin = module.base + rf.begin;

    auto info_va = module.base + rf.unwind_rva;
    UnwindInfo info{};
    if (!parse_unwind_info(uc, info_va, info)) {
        return false;
    }
    // rip_offset and the prolog total come from the frame's OWN unwind info:
    // a funclet frame (chained info) has its own prolog, and the chained hop
    // below only re-homes the language-handler fields. The establisher
    // semantics (x64) ride on this own-frame total: the faulting frame's is
    // its live rsp (rsp_known); a CALLER frame arrives pre-seeded with its
    // entry rsp (return slot + 8) and must subtract its own prolog total to
    // get the post-prolog frame the __except body and unwind resume expect.
    // The previous unconditional `= rsp_known` clobbered caller guesses with
    // the fault rsp, so an accepting caller frame resumed its handler body
    // on the callee's stack area and derailed (rsp=0 cascade).
    const auto rip_offset =
        static_cast<std::uint32_t>((std::min)(lookup_pc, frame.pc) - frame.function_begin);
    frame.rip_offset = rip_offset;
    frame.info_va = info_va;
    frame.count_of_codes = info.count_of_codes;
    if (!prolog_total(uc, info_va, info.count_of_codes, rip_offset, frame.total)) {
        return false;
    }
    while (info.chained) {
        RuntimeFunction parent{};
        if (!read_guest(uc, info.handler_data, parent)) {
            return false;
        }
        frame.function_begin = module.base + parent.begin;
        info_va = module.base + parent.unwind_rva;
        if (!parse_unwind_info(uc, info_va, info)) {
            return false;
        }
    }
    frame.language_handler = info.handler_rva == 0 ? 0 : module.base + info.handler_rva;
    frame.handler_data = info.handler_data;
    SEH_TRACE("open pc={:x} mod={:x} est={:x} handler={:x} data={:x} total={}", frame.pc,
              module.base, frame.establisher, frame.language_handler, frame.handler_data,
              frame.total);

    if (frame.establisher == 0) {
        frame.establisher = rsp_known; // the faulting frame's live rsp
    }
    // caller frames arrive pre-seeded with the rsp at the call site (return
    // slot + 8), which IS the post-prolog establisher the walk dispatches
    // with: the prolog total is already behind that rsp, and subtracting it
    // again landed handlers inside their caller's frame (the C++ cleanup
    // funclets then read their object pointers from wrong slots - native
    // cdb: caller establisher = fault establisher + callee frame size + 8,
    // with no caller-prolog term).
    // the chain hop re-homed `info` on the parent for funclet frames: its
    // flags govern the handler protocol of the frame the walk dispatches to
    frame.search_handler = (info.flags & 0x1) != 0; // UNW_FLAG_EHANDLER
    frame.cxx_handler = frame.language_handler != 0 &&
                        classify_language_handler(uc, map, frame.language_handler,
                                                  frame.handler_data) == HandlerKind::Cxx;
    frame.opened = true;
    return true;
}

// -- per-frame guest structs + callback staging --------------------------------

// Per-layer scratch blocks: EXCEPTION_RECORD, CONTEXT, DISPATCHER_CONTEXT
// and the VEH EXCEPTION_POINTERS at fixed offsets so nested layers never
// overlap.
std::uint64_t layer_block(const SehDispatchState& seh, std::size_t layer)
{
    return seh.scratch + 0x1000 + layer * 0x800;
}

// The callback stack of one layer: engine-mapped memory, growing down from
// +0x8000 + layer * 0x2000 inside the trampoline mapping (rebuild maps
// 0x21000 bytes for trampoline + scratch + stacks). The guest stack is not
// used: a captured snapshot's committed stack need not extend below the
// faulting rsp, and a staging write into unmapped memory would silently
// zero the handler's return address.
std::uint64_t callback_stack_top(const SehDispatchState& seh, std::size_t layer)
{
    return seh.trampoline + 0x8000 + layer * 0x2000;
}

void write_frame_guest_structs(uc_engine* uc, SehDispatchState& seh, bool x86, std::size_t layer,
                               Frame& frame, bool unwinding)
{
    const std::uint64_t block = layer_block(seh, layer);
    frame.record_va = block;
    frame.context_va = block + 0x100;
    frame.dispatcher_va = block + 0x600;

    if (x86) {
        std::array<std::uint8_t, exceptions::kExceptionRecordSize32> record{};
        exceptions::write_record_x86(record.data(), frame.code, seh.pc, seh.information.data(),
                                     seh.information_count);
        if (unwinding) {
            std::uint32_t flags = 0;
            std::memcpy(&flags, record.data() + exceptions::kRecordFlagsOffset32, sizeof flags);
            flags |= kExceptionUnwindingFlag;
            std::memcpy(record.data() + exceptions::kRecordFlagsOffset32, &flags, sizeof flags);
        }
        uc_mem_write(uc, frame.record_va, record.data(), record.size());
        std::array<std::uint8_t, exceptions::kContextSize32> context{};
        exceptions::write_context_x86(context.data(), seh.snapshot);
        uc_mem_write(uc, frame.context_va, context.data(), context.size());
        return;
    }
    std::array<std::uint8_t, exceptions::kExceptionRecordSize> record{};
    exceptions::write_record(record.data(), frame.code, seh.pc, seh.information.data(),
                             seh.information_count);
    if (unwinding) {
        std::uint32_t flags = 0;
        std::memcpy(&flags, record.data() + exceptions::kRecordFlagsOffset, sizeof flags);
        flags |= kExceptionUnwindingFlag;
        std::memcpy(record.data() + exceptions::kRecordFlagsOffset, &flags, sizeof flags);
    }
    uc_mem_write(uc, frame.record_va, record.data(), record.size());
    std::array<std::uint8_t, exceptions::kContextSize> context{};
    exceptions::write_context(context.data(), seh.snapshot);
    uc_mem_write(uc, frame.context_va, context.data(), context.size());
    // DISPATCHER_CONTEXT (x64, winnt.h): ControlPc, ImageBase, FunctionEntry,
    // EstablisherFrame, TargetIp, ContextRecord, LanguageHandler, HandlerData,
    // HistoryTable, ScopeIndex+Fill0. The C++ frame handler dereferences
    // FunctionEntry and ImageBase and hands its funclet target back through
    // TargetIp, so every slot must match the guest ABI (the unwind pass also
    // delivers the accept target through TargetIp, RtlUnwindEx semantics).
    std::uint64_t target_ip = 0;
    if (unwinding) {
        target_ip = seh.layers.at(layer).accept_jump_target;
    }
    std::array<std::uint64_t, 10> dc{
        frame.pc,  frame.module_base, frame.runtime_function, frame.establisher,
        target_ip, frame.context_va,  frame.language_handler, frame.handler_data,
        0,         frame.target_state};
    // element count != byte count: the pre-C++ DC write shipped only the
    // first 8 bytes and nothing ever read the rest (no engine-mode consumer)
    uc_mem_write(uc, frame.dispatcher_va, dc.data(), sizeof dc);
}

// Stages one guest callback: the machine jumps into `callback` with the
// language calling convention delivered and the return address pinned to
// the trampoline page. `staged` is the frame the callback belongs to: the
// guest structs (ExceptionRecord / Context / DISPATCHER_CONTEXT) are
// written from it, so the callback's establisher pairing - what it receives
// in rdx and what the DC names - is per-unwound-frame by construction.
void stage_callback(uc_engine* uc, SehDispatchState& seh, bool x86, std::size_t layer,
                    Frame& staged, std::uint64_t callback, std::uint64_t establisher)
{
    write_frame_guest_structs(uc, seh, x86, layer, staged,
                              seh.layers.at(layer).phase == Layer::Phase::Unwind);
    // pairing invariant: the struct frame and the establisher handed to the
    // callback must be the same frame. The C++ unwind misattribution of the
    // /Od corpus (the accepting frame's DC staged for a deeper frame's
    // funclet pass) tripped exactly here - trace-gated, off the hot path.
    if (diag::seh_on() && staged.establisher != establisher) {
        SEH_TRACE("establisher pairing violation: frame pc={:x} est={:x} callback est={:x}",
                  staged.pc, staged.establisher, establisher);
    }

    if (x86) {
        // x86 frame-based handlers are __cdecl: at entry [esp] holds the
        // return address (the trampoline) and the four arguments follow -
        // record, establisher, context, dispatcher. The handler's plain ret
        // lands on the trampoline.
        const auto sp =
            static_cast<std::uint32_t>((callback_stack_top(seh, layer) - 0x10) & ~0x3ULL);
        write_guest(uc, sp, static_cast<std::uint32_t>(seh.trampoline));
        write_guest(uc, sp + 4, static_cast<std::uint32_t>(staged.record_va));
        write_guest(uc, sp + 8, static_cast<std::uint32_t>(establisher));
        write_guest(uc, sp + 12, static_cast<std::uint32_t>(staged.context_va));
        write_guest(uc, sp + 16, static_cast<std::uint32_t>(staged.dispatcher_va));
        write_gpr(uc, true, 4, sp);
    } else {
        const std::uint64_t sp = ((callback_stack_top(seh, layer) - 8) & ~0xFULL) - 8;
        write_guest(uc, sp, seh.trampoline);
        write_gpr(uc, false, 1, staged.record_va);     // rcx = ExceptionRecord
        write_gpr(uc, false, 2, establisher);          // rdx = EstablisherFrame
        write_gpr(uc, false, 3, staged.context_va);    // r8 = ContextRecord
        write_gpr(uc, false, 9, staged.dispatcher_va); // r9 = DispatcherContext
        write_gpr(uc, false, 4, sp);                   // rsp
    }
    write_rip(uc, x86, callback);
    SEH_TRACE("staged callback={:x} layer={} sp={:x}", callback, layer, read_gpr(uc, x86, 4));
    seh.awaiting_callback = true;
    seh.callback_done = false;
    seh.callback_layer = layer;
}

// Applies the CONTEXT a callback wrote back (winnt semantics: every
// continue-execution disposition resumes through the guest CONTEXT - the
// VEH verdict lands in NtContinue, the walk's in RtlUnwindEx/NtContinue -
// so handler rewrites of the CONTEXT win over the fault snapshot).
// Segments and debug state stay engine-pinned: their CONTEXT slots are
// meaningless in the emulation.
// Applies one frame's recovered nonvolatile state to the machine (GPRs and
// XMMs): unwind callbacks and the final resume run against the frame's own
// registers - the RtlUnwindEx per-frame virtual-unwind semantics the funclets
// and finally bodies rely on. x64 only.
void apply_frame_registers(uc_engine* uc, const Frame& frame)
{
    NonvolatileFrame nv{};
    if (!nonvolatile_frame(uc, frame.info_va, frame.count_of_codes, frame.rip_offset,
                           frame.establisher, frame.total, nv)) {
        return;
    }
    for (std::size_t i = 0; i < nv.gpr_valid.size(); ++i) {
        if (nv.gpr_valid.at(i)) {
            write_gpr(uc, false, i, nv.gpr.at(i));
        }
    }
    for (std::size_t i = 0; i < nv.xmm_valid.size(); ++i) {
        if (nv.xmm_valid.at(i)) {
            static_cast<void>(
                uc_reg_write(uc, UC_X86_REG_XMM0 + static_cast<int>(i), nv.xmm.data() + i * 16));
        }
    }
}

StepResult apply_guest_context(uc_engine* uc, SehDispatchState& seh, bool x86)
{
    const auto context_va = seh.layers.back().frames.back().context_va;
    if (x86) {
        std::uint32_t eip = 0;
        std::uint32_t eflags = 0;
        if (!read_guest(uc, context_va + exceptions::kContextEipOffset32, eip) ||
            !read_guest(uc, context_va + exceptions::kContextEFlagsOffset32, eflags)) {
            return {Step::EngineError, 0};
        }
        static constexpr std::array<std::size_t, 8> kCtxToGpr{
            exceptions::kContextEaxOffset32, exceptions::kContextEcxOffset32,
            exceptions::kContextEdxOffset32, exceptions::kContextEbxOffset32,
            exceptions::kContextEspOffset32, exceptions::kContextEbpOffset32,
            exceptions::kContextEsiOffset32, exceptions::kContextEdiOffset32};
        for (std::size_t i = 0; i < 8; ++i) {
            std::uint32_t value = 0;
            if (!read_guest(uc, context_va + kCtxToGpr.at(i), value)) {
                return {Step::EngineError, 0};
            }
            write_gpr(uc, true, i, value);
        }
        uc_reg_write(uc, UC_X86_REG_EFLAGS, &eflags);
        write_rip(uc, true, eip);
        seh.layers.pop_back();
        if (seh.layers.empty()) {
            seh.active = false;
        }
        return {Step::ResumeHandled, eip};
    }
    std::uint64_t rip = 0;
    std::uint64_t eflags = 0;
    if (!read_guest(uc, context_va + exceptions::kContextRipOffset, rip) ||
        !read_guest(uc, context_va + exceptions::kContextEFlagsOffset, eflags)) {
        return {Step::EngineError, 0};
    }
    for (std::size_t i = 0; i < 16; ++i) {
        std::uint64_t value = 0;
        if (!read_guest(uc, context_va + exceptions::kContextGprOffsets.at(i), value)) {
            return {Step::EngineError, 0};
        }
        write_gpr(uc, false, i, value);
    }
    const auto flags = static_cast<std::uint64_t>(static_cast<std::uint32_t>(eflags));
    uc_reg_write(uc, UC_X86_REG_RFLAGS, &flags);
    write_rip(uc, false, rip);
    seh.layers.pop_back();
    if (seh.layers.empty()) {
        seh.active = false;
    }
    return {Step::ResumeHandled, rip};
}

StepResult finish_unhandled(SehDispatchState& seh)
{
    SEH_TRACE("unhandled layers={}", seh.layers.size());
    seh.layers.clear();
    seh.active = false;
    return {Step::Unhandled, 0};
}

} // namespace

// -- public state helpers --------------------------------------------------------

// Trace-only per-instruction hook body: while a staged callback is in
// flight, log {rip, rdx, rsp} - the funclet entries the real handler drives
// and the establisher each one receives.
void seh_callback_code_hook(uc_engine* uc, std::uint64_t address, std::uint32_t, void* user_data)
{
    auto* state = static_cast<SehDispatchState*>(user_data);
    if (!state->awaiting_callback) {
        return;
    }
    std::uint64_t rdx = 0;
    std::uint64_t rsp = 0;
    uc_reg_read(uc, UC_X86_REG_RDX, &rdx);
    uc_reg_read(uc, UC_X86_REG_RSP, &rsp);
    // The hook this writes from is installed only under the same switch (see
    // begin_dispatch), so the flag here is a name, not a second gate.
    diag::emit(sheller::log::level::kDebug, diag::seh_on(), "[seh-cb] rip={:x} rdx={:x} rsp={:x}",
               address, rdx, rsp);
}

void begin_dispatch(SehDispatchState& seh, uc_engine* uc, bool x86, std::uint32_t code,
                    std::uint64_t pc, std::uint64_t fault_address, const std::uint64_t* information,
                    std::uint32_t information_count)
{
    SEH_TRACE("begin code={:x} pc={:x} rsp={:x}", code, pc, read_gpr(uc, x86, 4));
    if (diag::seh_on() && !x86) {
        uc_hook hook = 0;
        static_cast<void>(uc_hook_add(uc, &hook, UC_HOOK_CODE,
                                      reinterpret_cast<void*>(seh_callback_code_hook), &seh, 1, 0));
    }
    seh.active = true;
    seh.code = code;
    seh.pc = pc;
    seh.fault_address = fault_address;
    seh.information_count = information_count;
    for (std::uint32_t i = 0; i < information_count && i < seh.information.size(); ++i) {
        seh.information.at(i) = information[i];
    }
    const auto gpr_count = x86 ? kGpr32.size() : kGpr64.size();
    for (std::size_t i = 0; i < gpr_count; ++i) {
        seh.snapshot.gpr.at(i) = read_gpr(uc, x86, i);
    }
    seh.snapshot.rip = read_rip(uc, x86);
    std::uint64_t eflags = 0;
    uc_reg_read(uc, x86 ? UC_X86_REG_EFLAGS : UC_X86_REG_RFLAGS, &eflags);
    seh.snapshot.eflags = static_cast<std::uint32_t>(eflags);
    seh.layers.push_back(Layer{});
}

bool in_flight(const SehDispatchState& seh)
{
    return seh.active;
}

void retire_dispatch(SehDispatchState& seh)
{
    // The staged search callback handed control to the real unwind machinery
    // (ntdll!RtlUnwindEx as guest code) and will never return through the
    // trampoline: the dispatch ends here and the guest protocol owns the
    // resume - the unwind callbacks, the catch funclet and the continuation
    // transfer all run as guest code from this point.
    seh.awaiting_callback = false;
    seh.callback_done = false;
    if (!seh.layers.empty()) {
        seh.layers.pop_back();
    }
    if (seh.layers.empty()) {
        seh.active = false;
    }
}

void restore_snapshot(uc_engine* uc, const SehDispatchState& seh, bool x86)
{
    // The re-delivery path synthesizes its dispatch frame from the live
    // machine state, so the fault context must be back in the registers
    // first: the staged callback left the engine-stack rsp in place.
    const auto gpr_count = x86 ? kGpr32.size() : kGpr64.size();
    for (std::size_t i = 0; i < gpr_count; ++i) {
        write_gpr(uc, x86, i, seh.snapshot.gpr.at(i));
    }
    write_rip(uc, x86, seh.snapshot.rip);
    const std::uint64_t eflags = seh.snapshot.eflags;
    uc_reg_write(uc, x86 ? UC_X86_REG_EFLAGS : UC_X86_REG_RFLAGS, &eflags);
}

bool prolog_total(uc_engine* uc, std::uint64_t info_va, std::uint32_t count_of_codes,
                  std::uint32_t rip_offset, std::uint64_t& total)
{
    total = 0;
    std::uint64_t cursor = info_va + 4;
    // CountOfCodes counts SLOTS: an opcode with an operand consumes the
    // operand's slot(s) too (ALLOC_LARGE info=1 and the *_FAR family use
    // two). Unexecuted codes (code_offset > rip_offset) skip their effects
    // but still burn their slots.
    std::uint32_t slot = 0;
    while (slot < count_of_codes) {
        std::uint16_t code = 0;
        if (!read_guest(uc, cursor, code)) {
            return false;
        }
        cursor += 2;
        ++slot;
        const auto code_offset = static_cast<std::uint32_t>(code & 0xFF);
        const auto op = static_cast<std::uint32_t>((code >> 8) & 0xF);
        const auto op_info = static_cast<std::uint32_t>((code >> 12) & 0xF);
        const bool executed = code_offset <= rip_offset;
        std::uint64_t effect = 0;
        std::uint32_t operand_slots = 0;
        switch (op) {
        case 0: // UWOP_PUSH_NONVOL
            effect = 8;
            break;
        case 1: // UWOP_ALLOC_LARGE: operand u16 (info=0) or u32 (info=1)
        {
            std::uint16_t lo = 0;
            if (!read_guest(uc, cursor, lo)) {
                return false;
            }
            cursor += 2;
            operand_slots = 1;
            if (op_info != 0) {
                std::uint16_t hi = 0;
                if (!read_guest(uc, cursor, hi)) {
                    return false;
                }
                cursor += 2;
                operand_slots = 2;
                effect = (static_cast<std::uint64_t>(hi) << 16) | lo;
            } else {
                effect = static_cast<std::uint64_t>(lo) * 8;
            }
            break;
        }
        case 2: // UWOP_ALLOC_SMALL
            effect = (op_info + 1) * 8;
            break;
        case 3: // UWOP_SET_FPREG
            break;
        case 4: // UWOP_SAVE_NONVOL: operand u16 slot
        case 8: // UWOP_SAVE_XMM128: operand u16 slot
            cursor += 2;
            operand_slots = 1;
            break;
        case 5: // UWOP_SAVE_NONVOL_FAR: operand u32 = 2 slots
        case 9: // UWOP_SAVE_XMM128_FAR: operand u32 = 2 slots
            cursor += 4;
            operand_slots = 2;
            break;
        case 6: // UWOP_EPILOGUE
        case 7: // UWOP_SPARE_CODE
            cursor += 2;
            operand_slots = 1;
            break;
        case 10: // UWOP_PUSH_MACHFRAME
            effect = op_info != 0 ? 0x30 : 0x28;
            break;
        default:
            break;
        }
        slot += operand_slots;
        if (executed) {
            total += effect;
        }
    }
    return true;
}

// Test seam (seh_dispatcher.h): recovers the callee-saved state the executed
// prolog codes saved into the frame - the engine-side parity of RtlUnwindEx's
// virtual unwind. PUSH_NONVOL slots sit at [establisher + total - done] (the
// running entry-rsp distance), the SAVE_* family stores absolute
// [establisher + offset] slots; SET_FPREG re-establishes the frame pointer
// register at entry_rsp - offset*16. Read failures skip that register: a
// partially committed stack must not abort the restore.
bool nonvolatile_frame(uc_engine* uc, std::uint64_t info_va, std::uint32_t count_of_codes,
                       std::uint32_t rip_offset, std::uint64_t establisher, std::uint64_t total,
                       NonvolatileFrame& out)
{
    UnwindInfo info{};
    if (!parse_unwind_info(uc, info_va, info)) {
        return false;
    }
    out = {};
    std::uint64_t cursor = info_va + 4;
    std::uint32_t slot = 0;
    std::uint64_t done = 0; // entry-rsp distance of the last executed push
    while (slot < count_of_codes) {
        std::uint16_t code = 0;
        if (!read_guest(uc, cursor, code)) {
            return false;
        }
        cursor += 2;
        ++slot;
        const auto code_offset = static_cast<std::uint32_t>(code & 0xFF);
        const auto op = static_cast<std::uint32_t>((code >> 8) & 0xF);
        const auto op_info = static_cast<std::uint32_t>((code >> 12) & 0xF);
        const bool executed = code_offset <= rip_offset;
        std::uint64_t effect = 0;
        std::uint32_t operand_slots = 0;
        switch (op) {
        case 0: // UWOP_PUSH_NONVOL: the pushed register sits just below
        {
            effect = 8;
            if (executed && op_info < out.gpr.size()) {
                out.gpr_valid.at(op_info) =
                    read_guest(uc, establisher + total - done - effect, out.gpr.at(op_info));
            }
            break;
        }
        case 1: // UWOP_ALLOC_LARGE: operand u16 (info=0) or u32 (info=1)
        {
            std::uint16_t lo = 0;
            if (!read_guest(uc, cursor, lo)) {
                return false;
            }
            cursor += 2;
            operand_slots = 1;
            if (op_info != 0) {
                std::uint16_t hi = 0;
                if (!read_guest(uc, cursor, hi)) {
                    return false;
                }
                cursor += 2;
                operand_slots = 2;
                effect = (static_cast<std::uint64_t>(hi) << 16) | lo;
            } else {
                effect = static_cast<std::uint64_t>(lo) * 8;
            }
            break;
        }
        case 2: // UWOP_ALLOC_SMALL
            effect = (op_info + 1) * 8;
            break;
        case 3: // UWOP_SET_FPREG: frame pointer = entry rsp - offset * 16
            if (executed && info.frame_register < out.gpr.size()) {
                out.gpr_valid.at(info.frame_register) =
                    read_guest(uc, establisher + total - info.frame_offset_units * 16ULL,
                               out.gpr.at(info.frame_register));
            }
            break;
        case 4: // UWOP_SAVE_NONVOL: operand u16 slot
        case 8: // UWOP_SAVE_XMM128: operand u16 slot
        {
            std::uint16_t where = 0;
            if (!read_guest(uc, cursor, where)) {
                return false;
            }
            cursor += 2;
            operand_slots = 1;
            if (executed) {
                if (op == 4) {
                    if (op_info < out.gpr.size()) {
                        out.gpr_valid.at(op_info) =
                            read_guest(uc, establisher + where * 8ULL, out.gpr.at(op_info));
                    }
                } else if (op_info < out.xmm_valid.size()) {
                    out.xmm_valid.at(op_info) =
                        uc_mem_read(uc, establisher + where * 16ULL, out.xmm.data() + op_info * 16,
                                    16) == UC_ERR_OK;
                }
            }
            break;
        }
        case 5: // UWOP_SAVE_NONVOL_FAR: operand u32 = 2 slots
        case 9: // UWOP_SAVE_XMM128_FAR: operand u32 = 2 slots
        {
            std::uint32_t where = 0;
            if (!read_guest(uc, cursor, where)) {
                return false;
            }
            cursor += 4;
            operand_slots = 2;
            if (executed) {
                if (op == 5) {
                    if (op_info < out.gpr.size()) {
                        out.gpr_valid.at(op_info) =
                            read_guest(uc, establisher + where, out.gpr.at(op_info));
                    }
                } else if (op_info < out.xmm_valid.size()) {
                    out.xmm_valid.at(op_info) =
                        uc_mem_read(uc, establisher + where, out.xmm.data() + op_info * 16, 16) ==
                        UC_ERR_OK;
                }
            }
            break;
        }
        case 6: // UWOP_EPILOGUE
        case 7: // UWOP_SPARE_CODE
            cursor += 2;
            operand_slots = 1;
            break;
        case 10: // UWOP_PUSH_MACHFRAME
            effect = op_info != 0 ? 0x30 : 0x28;
            break;
        default:
            break;
        }
        slot += operand_slots;
        if (executed) {
            done += effect;
        }
    }
    return true;
}

std::uint32_t fault_code(const SehDispatchState& seh)
{
    return seh.code;
}

std::uint64_t fault_pc(const SehDispatchState& seh)
{
    return seh.pc;
}

// -- the state machine ------------------------------------------------------------

StepResult step(uc_engine* uc, SehDispatchState& seh, bool x86, std::uint64_t teb,
                const mem_region::MemRegionMap& map)
{
    if (diag::seh_on()) {
        // The enclosing test is this block's switch, so the emits below pass true for
        // it: one record per line, as each of these was its own stderr line before.
        diag::emit(sheller::log::level::kDebug, diag::seh_on(),
                   "[seh-step] layers={} done={} await={} rax={:x}", seh.layers.size(),
                   static_cast<int>(seh.callback_done), static_cast<int>(seh.awaiting_callback),
                   seh.callback_rax);
        for (std::size_t L = 0; L < seh.layers.size(); ++L) {
            const auto& ly = seh.layers.at(L);
            diag::emit(sheller::log::level::kDebug, diag::seh_on(),
                       "[seh-step]   L{} phase={} veh={:x}/{} frames={}", L,
                       static_cast<int>(ly.phase), ly.veh_head, static_cast<int>(ly.veh_scanned),
                       ly.frames.size());
            for (std::size_t fi = 0; fi < ly.frames.size(); ++fi) {
                const auto& f = ly.frames.at(fi);
                diag::emit(sheller::log::level::kDebug, diag::seh_on(),
                           "[seh-step]     F{} pc={:x} cur={} opened={} lh={:x}", fi, f.pc,
                           f.scope_cursor, static_cast<int>(f.opened), f.language_handler);
            }
        }
    }
    if (seh.layers.empty() || seh.layers.size() > kMaxLayers) {
        return finish_unhandled(seh);
    }
    const auto layer = seh.layers.size() - 1;
    auto& top = seh.layers.at(layer);
    auto& frames = top.frames;

    // A staged callback returned through the trampoline: consume the verdict
    // and let the phase logic continue below.
    if (seh.callback_done) {
        seh.callback_done = false;
        const auto verdict = seh.callback_rax;
        SEH_TRACE("verdict={:x} phase={} layer={}", verdict, static_cast<int>(top.phase), layer);
        if (top.phase == Layer::Phase::Veh) {
            if (verdict == kVehContinueExecution) {
                return apply_guest_context(uc, seh, x86);
            }
            // ContinueSearch: advance the VEH list (node was stashed)
        } else if (top.phase == Layer::Phase::Dispatch) {
            if (x86) {
                // x86 handlers return the EXCEPTION_DISPOSITION enum in EAX
                // (0 = ContinueExecution with a possibly rewritten CONTEXT,
                // 1 = ContinueSearch, 2 = NestedException) - not the x64
                // negative NT-style values.
                if (verdict == 0) {
                    return apply_guest_context(uc, seh, true);
                }
                // any other disposition: advance the chain
                std::uint32_t next = 0;
                if (!read_guest(uc, frames.back().establisher, next) || next == 0xFFFFFFFF) {
                    return finish_unhandled(seh);
                }
                frames.back().establisher = next;
            } else {
                auto& frame = frames.back();
                if (verdict == kExceptionContinueExecution) {
                    return apply_guest_context(uc, seh, false);
                }
                if (verdict == kExceptionExecuteHandler) {
                    if (frame.cxx_handler) {
                        // C++ protocol: the real handler wrote its funclet
                        // target into DISPATCHER_CONTEXT.TargetIp (+ the
                        // ScopeIndex it wants echoed back on the unwind
                        // re-call). Capture both - the shared per-layer
                        // scratch block is about to be reused by the unwind
                        // stagings.
                        std::uint64_t target_ip = 0;
                        std::uint32_t scope_index = 0;
                        if (!read_guest(uc, frame.dispatcher_va + kDcTargetIpOffset, target_ip) ||
                            !read_guest(uc, frame.dispatcher_va + kDcScopeIndexOffset,
                                        scope_index) ||
                            target_ip == 0) {
                            return finish_unhandled(seh);
                        }
                        frame.target_state = scope_index;
                        top.accept_jump_target = target_ip;
                        top.accept_establisher = frame.establisher;
                        top.accept_frame = frames.size() - 1;
                    }
                    top.unwind_cursor = 0;
                    top.phase = Layer::Phase::Unwind;
                } else {
                    // ContinueSearch / NestedException
                    if (frame.cxx_handler) {
                        // no scope cursor to advance: the walk moves to the
                        // caller frame
                        const std::uint64_t ret_va = frame.establisher + frame.total;
                        std::uint64_t ret = 0;
                        if (!read_guest(uc, ret_va, ret) || ret == 0) {
                            return finish_unhandled(seh);
                        }
                        frames.push_back(
                            Frame{.pc = ret, .code = seh.code, .establisher = ret_va + 8});
                    } else {
                        frame.scope_cursor += 1;
                    }
                }
            }
        } else if (top.phase == Layer::Phase::Unwind) {
            // one frame's unwind callback just returned: a C++ handler ran
            // every destructor of its frame within that single call - the
            // scan moves on; a finally body is one scope and the same frame
            // keeps scanning (its cursor advanced before the staging).
            if (!x86 && top.unwind_cursor < top.accept_frame &&
                frames.at(top.unwind_cursor).cxx_handler) {
                top.unwind_cursor += 1;
            }
        }
    }

    switch (top.phase) {
    case Layer::Phase::Veh: {
        if (!top.veh_scanned) {
            top.veh_scanned = true;
            top.veh_head = find_veh_head(uc, seh, map, x86);
        }
        if (top.veh_head != 0) {
            std::uint64_t node = 0;
            if (top.veh_node == 0) {
                static_cast<void>(read_guest(uc, top.veh_head, node));
            } else {
                static_cast<void>(read_guest(uc, top.veh_node, node));
            }
            if (node != 0 && node != top.veh_head) {
                std::uint64_t handler = 0;
                if (veh_node_handler(uc, seh, map, x86, node, handler)) {
                    // VEH callback: rcx/[esp] = EXCEPTION_POINTERS
                    const auto pointers = layer_block(seh, layer) + 0x700;
                    frames.push_back(Frame{.pc = seh.pc, .code = seh.code});
                    auto& veh_frame = frames.back();
                    write_frame_guest_structs(uc, seh, x86, layer, veh_frame, false);
                    write_guest(uc, pointers, veh_frame.record_va);
                    write_guest(uc, pointers + (x86 ? 4 : 8), veh_frame.context_va);
                    top.veh_node = node;
                    if (x86) {
                        // cdecl: return address first, then the
                        // EXCEPTION_POINTERS argument
                        const auto sp = static_cast<std::uint32_t>(
                            (callback_stack_top(seh, layer) - 0x10) & ~0x3ULL);
                        write_guest(uc, sp, static_cast<std::uint32_t>(seh.trampoline));
                        write_guest(uc, sp + 4, static_cast<std::uint32_t>(pointers));
                        write_gpr(uc, true, 4, sp);
                    } else {
                        const std::uint64_t sp =
                            ((callback_stack_top(seh, layer) - 8) & ~0xFULL) - 8;
                        write_guest(uc, sp, seh.trampoline);
                        write_gpr(uc, false, 1, pointers);
                        write_gpr(uc, false, 4, sp);
                    }
                    write_rip(uc, x86, handler);
                    seh.awaiting_callback = true;
                    seh.callback_done = false;
                    seh.callback_layer = layer;
                    return {Step::RunCallback, handler};
                }
                // no resolvable handler on this node: advance the walk
                top.veh_node = node;
            }
        }
        top.phase = Layer::Phase::Dispatch;
        frames.push_back(Frame{.pc = seh.pc, .code = seh.code});
        return step(uc, seh, x86, teb, map);
    }
    case Layer::Phase::Dispatch: {
        if (frames.empty() || frames.size() >= kMaxFrames) {
            return finish_unhandled(seh);
        }
        auto& frame = frames.back();
        if (!frame.opened) {
            std::uint32_t chain_head32 = 0;
            if (x86) {
                read_guest(uc, teb, chain_head32); // FS:[0]: ExceptionList head
                if (chain_head32 == 0xFFFFFFFF) {
                    return finish_unhandled(seh);
                }
            }
            const std::uint64_t chain_head = x86 ? chain_head32 : seh.snapshot.gpr.at(4);
            if (!open_frame(uc, map, x86, seh, frame, chain_head)) {
                return finish_unhandled(seh);
            }
            if (x86) {
                std::uint32_t handler32 = 0;
                if (!read_guest(uc, frame.establisher + 4, handler32) || handler32 == 0) {
                    return finish_unhandled(seh);
                }
                diag::emit(sheller::log::level::kDebug, diag::seh_on(),
                           "[seh-diag] x86 stage handler={:x} chain={:x} esp={:x}", handler32,
                           static_cast<unsigned>(frame.establisher), seh.snapshot.gpr.at(4));
                stage_callback(uc, seh, true, layer, frame, handler32, frame.establisher);
                return {Step::RunCallback, handler32};
            }
            if (frame.language_handler == 0) {
                // no handler in this frame: advance to the caller
                const std::uint64_t ret_va = frame.establisher + frame.total;
                std::uint64_t ret = 0;
                if (!read_guest(uc, ret_va, ret) || ret == 0) {
                    return finish_unhandled(seh);
                }
                frames.push_back(Frame{.pc = ret, .code = seh.code, .establisher = ret_va + 8});
                return step(uc, seh, x86, teb, map);
            }
        }
        if (x86) {
            std::uint32_t handler32 = 0;
            if (!read_guest(uc, frame.establisher + 4, handler32) || handler32 == 0) {
                return finish_unhandled(seh);
            }
            stage_callback(uc, seh, true, layer, frame, handler32, frame.establisher);
            return {Step::RunCallback, handler32};
        }
        // C++ frames: the real handler consumes the FuncInfo; the engine
        // never interprets handler_data. ScopeIndex starts clean (the
        // handler recomputes its state from ControlPc). UHANDLER-only frames
        // (the /EHa pure-cleanup shape) take no search call - ntdll parity:
        // their UNWINDING call happens in the unwind pass.
        if (frame.cxx_handler && !frame.search_handler) {
            const std::uint64_t ret_va = frame.establisher + frame.total;
            std::uint64_t ret = 0;
            if (!read_guest(uc, ret_va, ret) || ret == 0) {
                return finish_unhandled(seh);
            }
            frames.push_back(Frame{.pc = ret, .code = seh.code, .establisher = ret_va + 8});
            return step(uc, seh, x86, teb, map);
        }
        if (frame.cxx_handler) {
            stage_callback(uc, seh, false, layer, frame, frame.language_handler, frame.establisher);
            return {Step::RunCallback, frame.language_handler};
        }
        // scope iteration (x64 __C_specific_handler semantics)
        std::uint32_t count = 0;
        if (!read_guest(uc, frame.handler_data, count)) {
            count = 0;
        }
        frame.unwind_scope_cursor = count; // reverse __finally scan seed
        // The block keeps its own test: reading the scope table off the guest stack
        // is work nobody should pay for a record nobody asked for.
        if (diag::seh_on()) {
            diag::emit(sheller::log::level::kDebug, diag::seh_on(),
                       "[seh-diag] scopes data={:x} count={} site={:x}", frame.handler_data, count,
                       static_cast<unsigned>(frame.pc - frame.module_base));
            for (std::uint32_t si = 0; si < count && si < 6; ++si) {
                std::array<std::uint32_t, 4> sc{};
                if (read_guest(uc, frame.handler_data + 4 + 16 * si, sc)) {
                    diag::emit(sheller::log::level::kDebug, diag::seh_on(),
                               "[seh-diag]   scope[{}] {:x} {:x} {:x} {:x}", si, sc[0], sc[1],
                               sc[2], sc[3]);
                }
            }
        }
        while (frame.scope_cursor < count) {
            // EXCEPTION_SCOPE_TABLE: {u32 Count} then records - the first
            // record sits at HandlerData+4, not +8.
            const std::uint64_t scope_va =
                frame.handler_data + 4 + 16 * static_cast<std::uint64_t>(frame.scope_cursor);
            std::array<std::uint32_t, 4> scope{};
            if (!read_guest(uc, scope_va, scope)) {
                return finish_unhandled(seh);
            }
            const auto site = static_cast<std::uint32_t>(frame.pc - frame.module_base);
            const bool covering = (site >= scope[0] && site < scope[1]) ||
                                  (site - 1 >= scope[0] && site - 1 < scope[1]);
            if (!covering || scope[3] == 0) {
                // not covered, or __finally form (runs on unwind only)
                frame.scope_cursor += 1;
                continue;
            }
            if (scope[2] == 1) {
                // Constant EXCEPTION_EXECUTE_HANDLER filter: MSVC emits 1 in
                // HandlerAddress for __except(1) - accept without a call.
                top.accept_jump_target = frame.module_base + scope[3];
                top.accept_establisher = frame.establisher;
                top.accept_frame = frames.size() - 1;
                top.phase = Layer::Phase::Unwind;
                return step(uc, seh, x86, teb, map);
            }
            // __except: Handler = filter, JumpTarget = handler body. The
            // establisher must be captured NOW - the constant-filter fast
            // path above does it, and the Unwind phase resumes the handler
            // body at rsp = accept_establisher; leaving it unset made every
            // function-filtered accept resume with rsp=0 (the body's first
            // call faulted instantly).
            const std::uint64_t filter = frame.module_base + scope[2];
            top.accept_jump_target = frame.module_base + scope[3];
            top.accept_establisher = frame.establisher;
            top.accept_frame = frames.size() - 1;
            SEH_TRACE("stage filter={:x} scope={} jt={:x} est={:x}", filter, frame.scope_cursor,
                      top.accept_jump_target, frame.establisher);
            stage_callback(uc, seh, false, layer, frame, filter, frame.establisher);
            return {Step::RunCallback, filter};
        }
        // scopes exhausted without an accept: advance to the caller frame
        const std::uint64_t ret_va = frame.establisher + frame.total;
        std::uint64_t ret = 0;
        if (!read_guest(uc, ret_va, ret) || ret == 0) {
            return finish_unhandled(seh);
        }
        frames.push_back(Frame{.pc = ret, .code = seh.code, .establisher = ret_va + 8});
        return step(uc, seh, x86, teb, map);
    }
    case Layer::Phase::Unwind: {
        if (x86) {
            // x86 keeps the direct resume: the FS:[0] chain model has no
            // per-frame UNWINDING scheduling of its own here (the chain
            // handlers saw the EH_UNWINDING record during the walk).
            const std::uint64_t rip = top.accept_jump_target;
            write_gpr(uc, true, 4, top.accept_establisher);
            write_rip(uc, true, rip);
            seh.layers.pop_back();
            if (seh.layers.empty()) {
                seh.active = false;
            }
            return {Step::ResumeHandled, rip};
        }
        // RtlUnwindEx parity: frames deeper than the accepting frame run
        // their UNWINDING callbacks innermost-first - a C++ handler re-called
        // with the EH_UNWINDING record runs its frame's destructors itself, a
        // scope-table frame runs each covering __finally body - each against
        // its own recovered nonvolatile state. Then the accept target resumes
        // with the accepting frame's registers. The /MD C++ accept path never
        // reaches this pass (its handler drives the real RtlUnwindEx as guest
        // code, hook-retired in intercept.cpp); the pass serves the SEH
        // scope-table accepts and a C++ handler verdict that names its own
        // resume target without driving RtlUnwindEx.
        while (top.unwind_cursor < top.accept_frame) {
            auto& f = frames.at(top.unwind_cursor);
            if (f.cxx_handler && f.language_handler != 0) {
                apply_frame_registers(uc, f);
                stage_callback(uc, seh, false, layer, f, f.language_handler, f.establisher);
                return {Step::RunCallback, f.language_handler};
            }
            if (!f.cxx_handler && f.handler_data != 0 && top.unwind_cursor < top.accept_frame) {
                // the reverse finally scan: seeded during the frame's search
                // visit (unwind_scope_cursor = scope count), consumed here
                while (f.unwind_scope_cursor > 0) {
                    f.unwind_scope_cursor -= 1;
                    const std::uint64_t scope_va =
                        f.handler_data + 4 + 16 * static_cast<std::uint64_t>(f.unwind_scope_cursor);
                    std::array<std::uint32_t, 4> scope{};
                    if (!read_guest(uc, scope_va, scope)) {
                        break;
                    }
                    const auto site = static_cast<std::uint32_t>(f.pc - f.module_base);
                    const bool covering = (site >= scope[0] && site < scope[1]) ||
                                          (site - 1 >= scope[0] && site - 1 < scope[1]);
                    if (covering && scope[3] == 0 && scope[2] != 0) {
                        // __finally form (JumpTarget == 0, body =
                        // HandlerAddress): stage the body as a real guest
                        // call; its plain ret lands on the trampoline.
                        apply_frame_registers(uc, f);
                        const std::uint64_t body = f.module_base + scope[2];
                        stage_callback(uc, seh, false, layer, f, body, f.establisher);
                        return {Step::RunCallback, body};
                    }
                }
            }
            top.unwind_cursor += 1;
        }
        SEH_TRACE("unwind-done jt={:x} est={:x} frames={}", top.accept_jump_target,
                  top.accept_establisher, top.accept_frame);
        // every unwind callback ran: restore the accepting frame's registers
        // and resume at the target (SEH scope JumpTarget or the C++ funclet)
        apply_frame_registers(uc, frames.at(top.accept_frame));
        const std::uint64_t rip = top.accept_jump_target;
        write_gpr(uc, x86, 4, top.accept_establisher);
        write_rip(uc, x86, rip);
        seh.layers.pop_back();
        if (seh.layers.empty()) {
            seh.active = false;
        }
        return {Step::ResumeHandled, rip};
    }
    }
    return finish_unhandled(seh);
}

} // namespace sheller::engine::seh
