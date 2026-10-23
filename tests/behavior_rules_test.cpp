// Behavior rules unit tests: synthesis is a pure function of the
// fact/event order, so every signal of the layer-2 list is
// driven here from synthetic fact sequences - no unicorn, no snapshot.

#include "behavior_rules.h"

#include <gtest/gtest.h>

#include "render_test_util.hpp"

#include <string>

namespace {

using namespace sheller::behavior;
using sheller::EventTypeId;
using Kind = sheller::EventTypeId;
using AntiDebug = sheller::AntiDebugSubtype;
using ExceptionDisposition = sheller::ExceptionDisposition;

BehaviorRulesParams make_params();

// One recorded judgment event, decoded back from the wire payload the rules
// emitted - the tests keep their old field spellings while the production
// type is now the event stream.
struct Judgment {
    EventTypeId kind{};
    std::uint64_t pc{};
    std::uint64_t address{};
    std::uint64_t aux{};
    std::uint32_t subtype{};
    std::string api{};
};

// Rules with a recording emitter: every emit call decodes its judgment
// payload into the list, exactly as a host would.
class RulesHarness : public BehaviorRules {
  public:
    explicit RulesHarness(BehaviorRulesParams params = make_params())
        : BehaviorRules(std::move(params))
    {
        set_event_emitter([this](const EventTypeId type, const sheller::EventPreamble& preamble,
                                 const std::span<const std::uint8_t> fields) {
            const auto decoded = sheller::read_judgment(fields);
            if (!decoded.has_value()) {
                return;
            }
            judgments_.push_back(Judgment{type, preamble.pc, decoded->fields.address,
                                          decoded->fields.aux, decoded->fields.subtype,
                                          std::string{decoded->fields.api}});
        });
    }

    const std::vector<Judgment>& signals() const
    {
        return judgments_;
    }

  private:
    std::vector<Judgment> judgments_;
};

constexpr std::uint64_t kTeb = 0x423444a000;
constexpr std::uint64_t kPeb = 0x423435b000;
constexpr std::uint64_t kImage = 0x7ff600000000;
constexpr std::uint64_t kImageSize = 0x10000;
constexpr std::uint64_t kNtdll = 0x7ff800000000;
constexpr std::uint64_t kNtdllSize = 0x200000;
constexpr std::uint64_t kQueryNumber = 0x19;

BehaviorRulesParams make_params()
{
    BehaviorRulesParams params;
    params.teb_address = kTeb;
    params.peb_address = kPeb;
    params.sample_image_base = kImage;
    params.sample_image_size = kImageSize;
    params.ntdll_base = kNtdll;
    params.query_process_number = kQueryNumber;
    mem_region::ModuleRecord ntdll;
    ntdll.base = kNtdll;
    ntdll.size = kNtdllSize;
    params.modules.push_back(ntdll);
    mem_region::ModuleRecord sample;
    sample.base = kImage;
    sample.size = kImageSize;
    params.modules.push_back(sample);
    params.syscall_entries = {kNtdll + 0x1000, kNtdll + 0x1010};
    BehaviorRulesParams::ExportSlot slot;
    slot.slot_va = kNtdll + 0x18000;
    const std::string annotation = "ntdll.dll!NtCreateFile";
    std::copy(annotation.begin(), annotation.end(), slot.annotation.begin());
    params.export_slots.push_back(slot);
    params.function_entries.push_back(slot); // function entry at the same spot
    return params;
}

engine::BehaviorFact mem_read(const std::uint64_t pc, const std::uint64_t addr,
                              const std::uint32_t size, const std::uint64_t value)
{
    engine::BehaviorFact fact;
    fact.kind = engine::BehaviorFact::Kind::kMemRead;
    fact.pc = pc;
    fact.addr = addr;
    fact.size = size;
    fact.aux = value;
    return fact;
}

engine::BehaviorFact code_fact(const std::uint64_t rip, const std::vector<std::uint8_t>& bytes)
{
    engine::BehaviorFact fact;
    fact.kind = engine::BehaviorFact::Kind::kCode;
    fact.pc = rip;
    fact.length = static_cast<std::uint8_t>(bytes.size());
    std::copy(bytes.begin(), bytes.end(), fact.bytes.begin());
    return fact;
}

engine::BehaviorFact protect_fact(const std::uint64_t base, const std::uint64_t size,
                                  const std::uint32_t protection)
{
    engine::BehaviorFact fact;
    fact.kind = engine::BehaviorFact::Kind::kProtect;
    fact.pc = kImage + 0x100;
    fact.addr = base;
    fact.aux = size;
    fact.size = protection;
    return fact;
}

engine::BehaviorFact write_fact(const std::uint64_t pc, const std::uint64_t addr)
{
    engine::BehaviorFact fact;
    fact.kind = engine::BehaviorFact::Kind::kMemWrite;
    fact.pc = pc;
    fact.addr = addr;
    fact.size = 1;
    return fact;
}

sheller::EventPreamble preamble(const std::uint64_t pc)
{
    return {.seq = 0, .tid = 0, .pc = pc};
}

bool has_kind(const RulesHarness& rules, const Kind kind)
{
    for (const auto& signal : rules.signals()) {
        if (signal.kind == kind) {
            return true;
        }
    }
    return false;
}

std::size_t signal_count(const RulesHarness& rules, const Kind kind)
{
    std::size_t count = 0;
    for (const auto& signal : rules.signals()) {
        if (signal.kind == kind) {
            ++count;
        }
    }
    return count;
}

TEST(BehaviorRules, PebWalkChainFires)
{
    RulesHarness rules(make_params());
    rules.on_fact(mem_read(kImage + 0x500, kTeb + 0x60, 8, kPeb));
    rules.on_fact(mem_read(kImage + 0x510, kPeb + 0x18, 8, kPeb + 0x1000));
    EXPECT_TRUE(has_kind(rules, Kind::kPebWalk));
}

TEST(BehaviorRules, BeingDebuggedNeedsSamplePc)
{
    RulesHarness rules(make_params());
    rules.on_fact(mem_read(kImage + 0x500, kPeb + 0x2, 1, 0));
    ASSERT_TRUE(has_kind(rules, Kind::kAntiDebug));
    EXPECT_EQ(rules.signals()[0].subtype, static_cast<std::uint32_t>(AntiDebug::kBeingDebugged));

    RulesHarness system_reader(make_params());
    system_reader.on_fact(mem_read(kNtdll + 0x5000, kPeb + 0x2, 1, 0));
    EXPECT_FALSE(has_kind(system_reader, Kind::kAntiDebug)); // infrastructure pc
}

TEST(BehaviorRules, KusdAccessFiresFromSamplePc)
{
    RulesHarness rules(make_params());
    // TickCount field read (the Silver Fox sleep-stub shape)
    rules.on_fact(mem_read(kImage + 0x500, 0x7FFE0324, 4, 0x1234));
    ASSERT_TRUE(has_kind(rules, Kind::kKusdAccess));
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kKusdAccess) {
            EXPECT_EQ(signal.address, 0x7FFE0324ULL);
            EXPECT_EQ(signal.aux, 0x1234ULL);
        }
    }
}

TEST(BehaviorRules, KusdAccessFiresFromRuntimePc)
{
    // shellcode readers live outside every module: no image gate here (the
    // loader-module filter sits engine-side)
    RulesHarness rules(make_params());
    rules.on_fact(mem_read(0x7f000000cb6f, 0x7FFE0320, 4, 0x5678));
    ASSERT_TRUE(has_kind(rules, Kind::kKusdAccess));
}

TEST(BehaviorRules, KusdAccessEmitsEveryRead)
{
    RulesHarness rules(make_params());
    rules.on_fact(mem_read(kImage + 0x500, 0x7FFE0324, 4, 0x1234));
    rules.on_fact(mem_read(kImage + 0x500, 0x7FFE0324, 4, 0x1235)); // same site
    rules.on_fact(mem_read(kImage + 0x500, 0x7FFE0004, 4, 0x1236)); // same site, other field
    // Every read is its own event now: no first-hit folding.
    EXPECT_EQ(signal_count(rules, Kind::kKusdAccess), 3);

    rules.on_fact(mem_read(kImage + 0x900, 0x7FFE0324, 4, 0x1237)); // a second reader site
    EXPECT_EQ(signal_count(rules, Kind::kKusdAccess), 4);
}

TEST(BehaviorRules, NonKusdReadIsSilent)
{
    RulesHarness rules(make_params());
    rules.on_fact(mem_read(kImage + 0x500, 0x7FFD0000, 4, 0x42)); // neighbor page
    rules.on_fact(mem_read(kImage + 0x500, 0x7FFE1000, 4, 0x42)); // past the shared page
    EXPECT_EQ(signal_count(rules, Kind::kKusdAccess), 0);
}

TEST(BehaviorRules, ExportWalkResolvesAnnotation)
{
    RulesHarness rules(make_params());
    rules.on_fact(mem_read(kImage + 0x500, kNtdll + 0x18000, 8, kNtdll + 0x9000));
    ASSERT_TRUE(has_kind(rules, Kind::kExportWalk));
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kExportWalk) {
            EXPECT_EQ(std::string(signal.api.data()), "ntdll.dll!NtCreateFile");
        }
    }
}

TEST(BehaviorRules, HeaderReadIsExportWalkWithoutAnnotation)
{
    RulesHarness rules(make_params());
    rules.on_fact(mem_read(kImage + 0x500, kNtdll + 0x40, 4, 0x00905A4D));
    ASSERT_TRUE(has_kind(rules, Kind::kExportWalk));
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kExportWalk) {
            EXPECT_TRUE(signal.api.empty());
        }
    }
}

TEST(BehaviorRules, GetPcCallPop)
{
    RulesHarness rules(make_params());
    rules.on_fact(code_fact(kImage + 0x800, {0xE8, 0x00, 0x00, 0x00, 0x00}));
    rules.on_fact(code_fact(kImage + 0x805, {0x59}));
    ASSERT_TRUE(has_kind(rules, Kind::kGetPc));
    // same pc pair again: each call/pop pair is its own event
    rules.on_fact(code_fact(kImage + 0x800, {0xE8, 0x00, 0x00, 0x00, 0x00}));
    rules.on_fact(code_fact(kImage + 0x805, {0x59}));
    EXPECT_EQ(signal_count(rules, Kind::kGetPc), 2U);
}

TEST(BehaviorRules, GetPcFnstenvSlotRead)
{
    RulesHarness rules(make_params());
    rules.on_fact(code_fact(kImage + 0x900, {0xD9, 0x34, 0x24}));       // fnstenv [esp]
    rules.on_fact(code_fact(kImage + 0x903, {0x8B, 0x44, 0x24, 0x0C})); // mov eax,[esp+0Ch]
    EXPECT_TRUE(has_kind(rules, Kind::kGetPc));
}

TEST(BehaviorRules, GetPcTebSelfReadNeedsSamplePc)
{
    RulesHarness rules(make_params());
    rules.on_fact(mem_read(kImage + 0x600, kTeb + 0x30, 8, kTeb));
    ASSERT_TRUE(has_kind(rules, Kind::kGetPc));

    RulesHarness system_reader(make_params());
    system_reader.on_fact(mem_read(kNtdll + 0x6000, kTeb + 0x30, 8, kTeb));
    EXPECT_FALSE(has_kind(system_reader, Kind::kGetPc));
}

TEST(BehaviorRules, RwxProtectAndWriteThenExecuteSequence)
{
    RulesHarness rules(make_params());
    rules.on_fact(protect_fact(kImage + 0x8000, 0x1000, 0x40)); // PAGE_EXECUTE_READWRITE
    EXPECT_TRUE(has_kind(rules, Kind::kRwxAlloc));

    RulesHarness sequence(make_params());
    sequence.on_fact(protect_fact(kImage + 0x9000, 0x1000, 0x04)); // plain write first
    EXPECT_FALSE(has_kind(sequence, Kind::kRwxAlloc));
    sequence.on_fact(protect_fact(kImage + 0x9000, 0x1000, 0x20)); // then execute-read
    EXPECT_TRUE(has_kind(sequence, Kind::kRwxAlloc));
}

TEST(BehaviorRules, SmcWriteThenExecuteCross)
{
    RulesHarness rules(make_params());
    const std::uint64_t page = kImage + 0xA000;
    rules.on_fact(write_fact(kImage + 0x700, page));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(page + 0x10), {});
    ASSERT_TRUE(has_kind(rules, Kind::kSmcExecute));
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kSmcExecute) {
            EXPECT_EQ(signal.aux, kImage + 0x700); // the page's first write pc
        }
    }
}

TEST(BehaviorRules, RdtscBurstWindow)
{
    auto params = make_params();
    params.rdtsc_window_blocks = 10;
    params.rdtsc_burst_threshold = 3;
    RulesHarness rules(params);
    for (auto i = 0; i < 3; ++i) {
        rules.on_event(sheller::EventTypeId::kRdtsc, preamble(kImage + 0x100 + i), {});
    }
    for (auto i = 0; i < 10; ++i) {
        rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kImage + 0x200 + i), {});
    }
    ASSERT_TRUE(has_kind(rules, Kind::kAntiDebug));
    bool burst = false;
    for (const auto& signal : rules.signals()) {
        if (signal.subtype == static_cast<std::uint32_t>(AntiDebug::kRdtscBurst)) {
            burst = true;
        }
    }
    EXPECT_TRUE(burst);
}

TEST(BehaviorRules, CpuidHypervisorLeafOnly)
{
    RulesHarness rules(make_params());
    rules.on_fact(engine::BehaviorFact{.kind = engine::BehaviorFact::Kind::kCpuidLeaf,
                                       .pc = 0,
                                       .addr = 0,
                                       .aux = 0x40000000,
                                       .size = 0,
                                       .length = 0,
                                       .bytes = {}});
    ASSERT_TRUE(has_kind(rules, Kind::kAntiDebug));
    EXPECT_EQ(rules.signals()[0].subtype, static_cast<std::uint32_t>(AntiDebug::kCpuidHypervisor));

    RulesHarness ordinary(make_params());
    ordinary.on_fact(engine::BehaviorFact{.kind = engine::BehaviorFact::Kind::kCpuidLeaf,
                                          .pc = 0,
                                          .addr = 0,
                                          .aux = 1,
                                          .size = 0,
                                          .length = 0,
                                          .bytes = {}});
    EXPECT_FALSE(has_kind(ordinary, Kind::kAntiDebug));
}

// The engine's function-form kSyscall event payload (apicall-param-
// reporting): {u32 number, u8 flags(raw), u32 status, u64 caller} + four
// u64 raw-register records (rcx/rdx/r8/r9). arg1..arg3 ride records 0..2;
// the stack return address lives in the head.
std::vector<std::uint8_t> syscall_payload(const std::uint32_t number, const std::uint32_t arg1,
                                          const std::uint32_t arg2, const std::uint32_t arg3)
{
    std::vector<std::uint8_t> fields(sheller::kSyscallFixedBytes + 4 * 11);
    const sheller::SyscallFields head{
        .number = number, .flags = sheller::kEventFlagRaw, .status = 0, .caller_retaddr = 0};
    if (!sheller::encode_syscall_head(fields, head).has_value()) {
        return {};
    }
    std::size_t cursor = sheller::kSyscallFixedBytes;
    for (const std::uint64_t reg :
         {static_cast<std::uint64_t>(arg1), static_cast<std::uint64_t>(arg2),
          static_cast<std::uint64_t>(arg3), std::uint64_t{0}}) {
        std::vector<std::uint8_t> value(8);
        sheller::le::store_le64(value.data(), reg);
        if (!sheller::append_param_record(fields, cursor, sheller::ParamKind::kU64, value)
                 .appended) {
            return {};
        }
    }
    fields.resize(cursor);
    return fields;
}

TEST(BehaviorRules, DirectSyscallOutsideStubs)
{
    RulesHarness rules(make_params());
    rules.on_event(sheller::EventTypeId::kSyscall, preamble(kImage + 0x900),
                   syscall_payload(0xBEEF, 0, 0, 0));
    EXPECT_TRUE(has_kind(rules, Kind::kDirectSyscall));
    EXPECT_FALSE(has_kind(rules, Kind::kIndirectSyscall));
}

// A sample-issued probe query: a hand-rolled syscall inside the sample
// image. The class travels in arg2 of the payload (NtQueryInformation-
// Process's ProcessInformationClass), not arg1 (ProcessHandle).
TEST(BehaviorRules, DirectSyscallProbeClassFires)
{
    RulesHarness rules(make_params());
    rules.on_event(sheller::EventTypeId::kSyscall, preamble(kImage + 0x900),
                   syscall_payload(kQueryNumber, 0xFFFFFFFF, 7, 0));
    ASSERT_TRUE(has_kind(rules, Kind::kAntiDebug));
    bool query_seen = false;
    for (const auto& signal : rules.signals()) {
        if (signal.subtype == static_cast<std::uint32_t>(AntiDebug::kQueryInformationProcess)) {
            query_seen = true;
            EXPECT_EQ(signal.aux, 7U); // the query class rides aux
        }
    }
    EXPECT_TRUE(query_seen);
}

// The WER crash-reporting shape: a probe-class query whose syscall
// instruction executes in a system module. Under the direct-issuance
// semantics that is the system's behavior, not the sample's - the exact
// false positive a crash under emulation used to produce on every sample.
TEST(BehaviorRules, SystemIssuedProbeQueryStaysSilent)
{
    RulesHarness rules(make_params());
    rules.on_event(sheller::EventTypeId::kSyscall, preamble(kNtdll + 0x1000),
                   syscall_payload(kQueryNumber, 0xFFFFFFFF, 7, 0));
    EXPECT_FALSE(has_kind(rules, Kind::kAntiDebug));
    // Non-probe classes stay silent wherever they execute.
    rules.on_event(sheller::EventTypeId::kSyscall, preamble(kImage + 0x900),
                   syscall_payload(kQueryNumber, 0xFFFFFFFF, 0, 0));
    EXPECT_FALSE(has_kind(rules, Kind::kAntiDebug));
    // A short payload cannot carry the class; no fire either.
    rules.on_event(sheller::EventTypeId::kSyscall, preamble(kImage + 0x900),
                   std::vector<std::uint8_t>{static_cast<std::uint8_t>(kQueryNumber & 0xFF), 0x00,
                                             0x00, 0x00});
    EXPECT_FALSE(has_kind(rules, Kind::kAntiDebug));
}

// The sample calls a probe API through its import: the block-exec right
// after a sample-side block is the callee's entry block, and it lands on
// the resolved probe API entry. The pair is read from the block stream -
// the narrowed xfer edges never fire for sample->system calls.
TEST(BehaviorRules, ProbeApiDirectCallFires)
{
    auto params = make_params();
    constexpr std::uint64_t kProbeEntry = kNtdll + 0x2000;
    params.probe_api_entries = {kProbeEntry};
    BehaviorRulesParams::ExportSlot slot;
    slot.slot_va = kProbeEntry;
    const std::string annotation = "ntdll.dll!NtQueryInformationProcess";
    std::copy(annotation.begin(), annotation.end(), slot.annotation.begin());
    params.function_entries.push_back(slot);

    RulesHarness rules(std::move(params));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kImage + 0x900),
                   std::vector<std::uint8_t>(8, 0));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kProbeEntry),
                   std::vector<std::uint8_t>(8, 0));

    ASSERT_TRUE(has_kind(rules, Kind::kAntiDebug));
    bool probe_seen = false;
    for (const auto& signal : rules.signals()) {
        if (signal.subtype == static_cast<std::uint32_t>(AntiDebug::kProbeApiCall)) {
            probe_seen = true;
            EXPECT_EQ(signal.aux, kProbeEntry);
            EXPECT_NE(std::string_view(signal.api.data()).find("NtQueryInformationProcess"),
                      std::string_view::npos);
        }
    }
    EXPECT_TRUE(probe_seen);
}

// Probes reached through system machinery are system behavior: the previous
// block is system-side (WER crash reporting), or an unrelated system block
// sits between the sample's block and the probe entry. Both stay silent.
TEST(BehaviorRules, ProbeApiInternalUseStaysSilent)
{
    {
        auto params = make_params();
        params.probe_api_entries = {kNtdll + 0x2000};
        RulesHarness rules(std::move(params));
        // the previous block is system-side (ntdll itself)
        rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kNtdll + 0x1800),
                       std::vector<std::uint8_t>(8, 0));
        rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kNtdll + 0x2000),
                       std::vector<std::uint8_t>(8, 0));
        EXPECT_FALSE(has_kind(rules, Kind::kAntiDebug));
    }
    {
        auto params = make_params();
        params.probe_api_entries = {kNtdll + 0x2000};
        RulesHarness rules(std::move(params));
        rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kImage + 0x900),
                       std::vector<std::uint8_t>(8, 0));
        // the sample's call landed elsewhere; the later probe entry is not
        // the callee of that transfer
        rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kNtdll + 0x1800),
                       std::vector<std::uint8_t>(8, 0));
        rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kNtdll + 0x2000),
                       std::vector<std::uint8_t>(8, 0));
        EXPECT_FALSE(has_kind(rules, Kind::kAntiDebug));
    }
}

// A payload unpacked into a sample-issued allocation calls the probe
// directly: the allocation's RWX protect fact opens a sample-side execution
// window, so the payload block arms the entry check exactly like a
// sample-image block - registering the allocation must not silence the
// payload's own probe.
TEST(BehaviorRules, ProbeApiFromRuntimeRegionFires)
{
    auto params = make_params();
    constexpr std::uint64_t kProbeEntry = kNtdll + 0x2000;
    constexpr std::uint64_t kPayloadBase = 0x7F0000000000ULL;
    params.probe_api_entries = {kProbeEntry};
    RulesHarness rules(std::move(params));
    rules.on_fact(protect_fact(kPayloadBase, 0x10000, engine::kPageExecuteReadwrite));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kPayloadBase + 0x8000),
                   std::vector<std::uint8_t>(8, 0));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kProbeEntry),
                   std::vector<std::uint8_t>(8, 0));

    ASSERT_TRUE(has_kind(rules, Kind::kAntiDebug));
    bool probe_seen = false;
    for (const auto& signal : rules.signals()) {
        if (signal.subtype == static_cast<std::uint32_t>(AntiDebug::kProbeApiCall)) {
            probe_seen = true;
        }
    }
    EXPECT_TRUE(probe_seen);
}

// The registration API entered straight from a sample-issued payload region
// is the sample installing its own handler - the same territory rule as the
// probe list.
TEST(BehaviorRules, ExceptionHandlerInstallFromRuntimeRegionFires)
{
    auto params = make_params();
    constexpr std::uint64_t kExceptionHandlerEntry = kNtdll + 0x3000;
    constexpr std::uint64_t kPayloadBase = 0x7F0000000000ULL;
    params.exception_handler_api_entries = {kExceptionHandlerEntry};
    RulesHarness rules(std::move(params));
    rules.on_fact(protect_fact(kPayloadBase, 0x10000, engine::kPageExecuteReadwrite));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kPayloadBase + 0x4000),
                   std::vector<std::uint8_t>(8, 0));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kExceptionHandlerEntry),
                   std::vector<std::uint8_t>(8, 0));
    EXPECT_TRUE(has_kind(rules, Kind::kExceptionHandlerInstall));
}

// Blocks outside the sample image and outside any sample-side execution
// window (snapshot-captured private regions and the like) do not arm: their
// signal semantics predate registration and are unchanged.
TEST(BehaviorRules, ProbeApiFromSnapshotRegionStaysSilent)
{
    auto params = make_params();
    constexpr std::uint64_t kProbeEntry = kNtdll + 0x2000;
    params.probe_api_entries = {kProbeEntry};
    RulesHarness rules(std::move(params));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kNtdll + 0x1000),
                   std::vector<std::uint8_t>(8, 0));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kProbeEntry),
                   std::vector<std::uint8_t>(8, 0));
    EXPECT_FALSE(has_kind(rules, Kind::kAntiDebug));
}

// The engine's kException event payload: {u32 status code, u32 chance} LE
// (chance 0 = first-chance delivery, 1 = last-chance unhandled raise).
std::vector<std::uint8_t> exception_payload(const std::uint32_t code, const std::uint32_t chance)
{
    std::vector<std::uint8_t> fields(8, 0);
    fields[0] = static_cast<std::uint8_t>(code & 0xFF);
    fields[1] = static_cast<std::uint8_t>((code >> 8) & 0xFF);
    fields[2] = static_cast<std::uint8_t>((code >> 16) & 0xFF);
    fields[3] = static_cast<std::uint8_t>((code >> 24) & 0xFF);
    fields[4] = static_cast<std::uint8_t>(chance & 0xFF);
    return fields;
}

TEST(BehaviorRules, ExceptionEventProducesSignal)
{
    RulesHarness rules(make_params());
    rules.on_event(sheller::EventTypeId::kException, preamble(kImage + 0x700),
                   exception_payload(0xC0000005, 0));
    ASSERT_TRUE(has_kind(rules, Kind::kExceptionDisposition));
    bool seen = false;
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kExceptionDisposition) {
            seen = true;
            EXPECT_EQ(signal.pc, kImage + 0x700);
            EXPECT_EQ(signal.aux, 0xC0000005U); // the status code rides aux
            EXPECT_EQ(signal.subtype,
                      static_cast<std::uint32_t>(ExceptionDisposition::kFirstChance));
        }
    }
    EXPECT_TRUE(seen);
    // An exception raised inside a system module reports the same way:
    // exceptions belong to the sample's run, no image attribution applies.
    rules.on_event(sheller::EventTypeId::kException, preamble(kNtdll + 0x200),
                   exception_payload(0xC000001D, 0));
    bool illegal_seen = false;
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kExceptionDisposition && signal.aux == 0xC000001DU) {
            illegal_seen = true;
        }
    }
    EXPECT_TRUE(illegal_seen);
}

TEST(BehaviorRules, LastChanceExceptionCarriesUnhandledSubtype)
{
    RulesHarness rules(make_params());
    rules.on_event(sheller::EventTypeId::kException, preamble(kImage + 0x700),
                   exception_payload(0xC0000005, 0));
    rules.on_event(sheller::EventTypeId::kException, preamble(kNtdll + 0x400),
                   exception_payload(0xC0000005, 1));
    std::size_t first_chance = 0, unhandled = 0;
    for (const auto& signal : rules.signals()) {
        if (signal.kind != Kind::kExceptionDisposition) {
            continue;
        }
        if (signal.subtype == static_cast<std::uint32_t>(ExceptionDisposition::kFirstChance)) {
            ++first_chance;
        }
        if (signal.subtype == static_cast<std::uint32_t>(ExceptionDisposition::kUnhandled)) {
            ++unhandled;
            EXPECT_EQ(signal.aux, 0xC0000005U);
        }
    }
    // the absorbed first-chance and the fatal last-chance both surface:
    // SEH control flow shows up as first-chance only, a crash adds unhandled
    EXPECT_EQ(first_chance, 1U);
    EXPECT_EQ(unhandled, 1U);
}

TEST(BehaviorRules, ExceptionEmitsEveryHit)
{
    RulesHarness rules(make_params());
    rules.on_event(sheller::EventTypeId::kException, preamble(kImage + 0x700),
                   exception_payload(0xC0000005, 0));
    rules.on_event(sheller::EventTypeId::kException, preamble(kImage + 0x700),
                   exception_payload(0xC0000005, 0)); // same site/code: its own event
    EXPECT_EQ(signal_count(rules, Kind::kExceptionDisposition), 2U);
    // same site, different code: also its own event
    rules.on_event(sheller::EventTypeId::kException, preamble(kImage + 0x700),
                   exception_payload(0xC000001D, 0));
    EXPECT_EQ(signal_count(rules, Kind::kExceptionDisposition), 3U);
}

TEST(BehaviorRules, NoExceptionEventsKeepReportFreeOfExceptionSignals)
{
    RulesHarness rules(make_params());
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kImage + 0x100),
                   std::vector<std::uint8_t>(8, 0));
    EXPECT_EQ(signal_count(rules, Kind::kExceptionDisposition), 0U);
}

TEST(BehaviorRules, EmptyStreamAndDeterminism)
{
    RulesHarness silent(make_params());
    EXPECT_TRUE(silent.signals().empty());

    const auto run = [] {
        RulesHarness rules(make_params());
        rules.on_fact(mem_read(kImage + 0x500, kTeb + 0x60, 8, kPeb));
        rules.on_fact(mem_read(kImage + 0x510, kPeb + 0x18, 8, kPeb + 0x1000));
        rules.on_fact(protect_fact(kImage + 0x8000, 0x1000, 0x40));
        std::string stream;
        for (const auto& judgment : rules.signals()) {
            stream += sheller::event_type_name(judgment.kind);
            stream += ':' + std::to_string(judgment.pc);
            stream += ':' + std::to_string(judgment.address);
            stream += ':' + std::to_string(judgment.aux);
            stream += ':' + std::to_string(judgment.subtype);
            stream += ':' + judgment.api;
            stream += '\n';
        }
        return stream;
    };
    EXPECT_EQ(run(), run());
    EXPECT_FALSE(run().empty());
}

TEST(BehaviorRules, EveryHitEmitsPastTheOldCapacity)
{
    auto params = make_params();
    RulesHarness rules(params);
    // distinct pcs each fire a fresh getpc: the old 4096 cap is gone
    for (std::uint64_t i = 0; i < 4200; ++i) {
        rules.on_fact(code_fact(kImage + 0x800 + i * 2, {0xE8, 0x00, 0x00, 0x00, 0x00}));
        rules.on_fact(code_fact(kImage + 0x805 + i * 2, {0x59}));
    }
    EXPECT_EQ(rules.signals().size(), 4200U);
}

TEST(BehaviorRules, OepCandidateOnHandoffIntoWrittenRuntimePage)
{
    RulesHarness rules(make_params());
    // the unpacker writes a runtime page, then control crosses into it:
    // the first executed block on that page is the OEP candidate
    const std::uint64_t oep_page = 0x310000000 + 0x30000; // runtime region
    rules.on_fact(write_fact(oep_page + 0x40, oep_page));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(oep_page + 0x40), {});
    EXPECT_TRUE(has_kind(rules, Kind::kOepCandidate));

    // first candidate per page only
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(oep_page + 0x80), {});
    EXPECT_EQ(signal_count(rules, Kind::kOepCandidate), 1U);
}

TEST(BehaviorRules, NoOepCandidateWithoutPriorWrite)
{
    RulesHarness rules(make_params());
    // control crosses into a runtime page that was never written this run:
    // not an unpack handoff, just an execution into untracked memory
    const std::vector<std::uint8_t> xfer = {0x01, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
    rules.on_event(sheller::EventTypeId::kXfer, preamble(0x310000000 + 0x20000), xfer);
    EXPECT_FALSE(has_kind(rules, Kind::kOepCandidate));
}

TEST(BehaviorRules, NoOepCandidateForSampleImageSelfModification)
{
    // the stub rewriting its own image is plain SMC, not an OEP handoff:
    // the page sits inside the sample image range
    RulesHarness rules(make_params());
    const std::uint64_t page = kImage + 0xB000;
    rules.on_fact(write_fact(kImage + 0x700, page));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(page + 0x10), {});
    EXPECT_TRUE(has_kind(rules, Kind::kSmcExecute));
    EXPECT_FALSE(has_kind(rules, Kind::kOepCandidate));
}

// The function-form head carries the stack return address (caller_retaddr).
std::vector<std::uint8_t> syscall_payload_ret(const std::uint32_t number, const std::uint32_t arg1,
                                              const std::uint32_t arg2, const std::uint32_t arg3,
                                              const std::uint64_t return_address)
{
    auto fields = syscall_payload(number, arg1, arg2, arg3);
    if (fields.size() >= sheller::kSyscallCallerOffset + 8) {
        sheller::le::store_le64(fields.data() + sheller::kSyscallCallerOffset, return_address);
    }
    return fields;
}

TEST(BehaviorRules, IndirectSyscallNeedsSampleReturnAddress)
{
    RulesHarness rules(make_params());
    // the sample called into an ntdll stub: the syscall instruction sits in
    // the stub (kNtdll + 0x1000 is a recorded stub entry), the stack return
    // address points back into the sample image
    rules.on_event(sheller::EventTypeId::kSyscall, preamble(kNtdll + 0x1000),
                   syscall_payload_ret(0x55, 0, 0, 0, kImage + 0x900));
    ASSERT_TRUE(has_kind(rules, Kind::kIndirectSyscall));
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kIndirectSyscall) {
            EXPECT_EQ(signal.address, kImage + 0x900);
            EXPECT_FALSE(has_kind(rules, Kind::kDirectSyscall));
        }
    }
}

TEST(BehaviorRules, StubSyscallWithSystemReturnStaysSilent)
{
    RulesHarness rules(make_params());
    // kernelbase/CRT internals calling the same stub: the return address is
    // system-side, that flow is the system's own behavior
    rules.on_event(sheller::EventTypeId::kSyscall, preamble(kNtdll + 0x1000),
                   syscall_payload_ret(0x55, 0, 0, 0, kNtdll + 0x9000));
    EXPECT_FALSE(has_kind(rules, Kind::kIndirectSyscall));
    EXPECT_FALSE(has_kind(rules, Kind::kDirectSyscall));
}

TEST(BehaviorRules, WindowSyscallClassifiesDirect)
{
    RulesHarness rules(make_params());
    // the sample allocates RWX memory at a runtime address and executes
    // shellcode there: the syscall inside the window classifies as direct
    // with the window base riding aux
    const std::uint64_t window = 0x310000000 + 0x40000;
    rules.on_fact(protect_fact(window, 0x10000, 0x40)); // RWX allocation
    rules.on_event(sheller::EventTypeId::kSyscall, preamble(window + 0x40),
                   syscall_payload_ret(0x55, 0, 0, 0, window + 0x30));
    ASSERT_TRUE(has_kind(rules, Kind::kDirectSyscall));
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kDirectSyscall) {
            EXPECT_EQ(signal.aux, window); // the owning window base
        }
    }
    EXPECT_FALSE(has_kind(rules, Kind::kIndirectSyscall));
}

TEST(BehaviorRules, WriteThenExecutePageJoinsSyscallWindows)
{
    RulesHarness rules(make_params());
    // the W->X sequence window also classifies: page made writable, then
    // execute-enabled, shellcode syscalls from it
    const std::uint64_t page = 0x310000000 + 0x60000;
    rules.on_fact(protect_fact(page, 0x1000, 0x04)); // plain write first
    rules.on_fact(protect_fact(page, 0x1000, 0x20)); // then execute-read
    rules.on_event(sheller::EventTypeId::kSyscall, preamble(page + 0x10),
                   syscall_payload_ret(0x55, 0, 0, 0, 0));
    ASSERT_TRUE(has_kind(rules, Kind::kDirectSyscall));
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kDirectSyscall) {
            EXPECT_EQ(signal.aux, page);
        }
    }
}

// The kException payload extension: {u32 code, u32 disposition, u64 related
// pc} - related pc is the fault that selected the handler on a
// handler-dispatch report.
std::vector<std::uint8_t> exception_payload_related(const std::uint32_t code,
                                                    const std::uint32_t chance,
                                                    const std::uint64_t related_pc)
{
    auto fields = exception_payload(code, chance);
    fields.resize(16);
    for (std::size_t b = 0; b < 8; ++b) {
        fields[8 + b] = static_cast<std::uint8_t>((related_pc >> (8 * b)) & 0xFF);
    }
    return fields;
}

TEST(BehaviorRules, HandlerDispatchCarriesHandlerAttribution)
{
    RulesHarness rules(make_params());
    // the engine-side dispatcher staged the sample's handler at a mapped
    // export slot: the report names the handler, the fault pc rides address
    rules.on_event(sheller::EventTypeId::kException, preamble(kNtdll + 0x18000),
                   exception_payload_related(0xC0000005, 2, kImage + 0x700));
    ASSERT_TRUE(has_kind(rules, Kind::kExceptionDisposition));
    bool dispatch_seen = false;
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kExceptionDisposition &&
            signal.subtype == static_cast<std::uint32_t>(ExceptionDisposition::kHandlerDispatch)) {
            dispatch_seen = true;
            EXPECT_EQ(signal.pc, kNtdll + 0x18000);    // the handler entry
            EXPECT_EQ(signal.address, kImage + 0x700); // the fault pc
            EXPECT_EQ(signal.aux, 0xC0000005U);
            EXPECT_EQ(std::string(signal.api.data()), "ntdll.dll!NtCreateFile");
        }
    }
    EXPECT_TRUE(dispatch_seen);
}

TEST(BehaviorRules, HandlerDispatchWithoutAnnotationStillFires)
{
    RulesHarness rules(make_params());
    // a handler at an address with no export slot: the signal stays, the
    // api field just stays empty
    rules.on_event(sheller::EventTypeId::kException, preamble(kImage + 0x500),
                   exception_payload_related(0xC0000005, 2, kImage + 0x700));
    ASSERT_TRUE(has_kind(rules, Kind::kExceptionDisposition));
    for (const auto& signal : rules.signals()) {
        if (signal.subtype == static_cast<std::uint32_t>(ExceptionDisposition::kHandlerDispatch)) {
            EXPECT_TRUE(signal.api.empty());
        }
    }
}

TEST(BehaviorRules, ExceptionHandlerInstallFiresOnSampleSideEntry)
{
    auto params = make_params();
    constexpr std::uint64_t kVehEntry = kNtdll + 0x3000;
    params.exception_handler_api_entries = {kVehEntry};
    BehaviorRulesParams::ExportSlot slot;
    slot.slot_va = kVehEntry;
    const std::string annotation = "ntdll.dll!RtlAddVectoredExceptionHandler";
    std::copy(annotation.begin(), annotation.end(), slot.annotation.begin());
    params.function_entries.push_back(slot);

    RulesHarness rules(std::move(params));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kImage + 0x900),
                   std::vector<std::uint8_t>(8, 0));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kVehEntry),
                   std::vector<std::uint8_t>(8, 0));

    ASSERT_TRUE(has_kind(rules, Kind::kExceptionHandlerInstall));
    for (const auto& signal : rules.signals()) {
        if (signal.kind == Kind::kExceptionHandlerInstall) {
            EXPECT_EQ(std::string(signal.api.data()), "ntdll.dll!RtlAddVectoredExceptionHandler");
        }
    }
}

TEST(BehaviorRules, ExceptionHandlerInstallInternalUseStaysSilent)
{
    auto params = make_params();
    constexpr std::uint64_t kVehEntry = kNtdll + 0x3000;
    params.exception_handler_api_entries = {kVehEntry};
    RulesHarness rules(std::move(params));
    // the previous block is system-side (CRT startup registering its own
    // handler): the install is system behavior, not the sample's
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kNtdll + 0x1800),
                   std::vector<std::uint8_t>(8, 0));
    rules.on_event(sheller::EventTypeId::kBlockExec, preamble(kVehEntry),
                   std::vector<std::uint8_t>(8, 0));
    EXPECT_FALSE(has_kind(rules, Kind::kExceptionHandlerInstall));
}

} // namespace
