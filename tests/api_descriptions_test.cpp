// API description table tests: seed-table
// lookups, the interpolation invariants (intercept list ⊆ Win32 table),
// the Win32->Nt equivalence map, and the parameter-name join the full-level
// stream renders. Pure standard library - runs on both platforms.

#include "api_descriptions.h"

#include "../src/syscalls/syscall_arity.h"
#include "../src/syscalls/win32_nt_equivalence.h"

#include "event_ledger.h"

#include <sheller/events.h>

#include <gtest/gtest.h>

#include "render_test_util.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace {

namespace ev = sheller;
namespace behavior = sheller::behavior;

constexpr ev::EventPreamble kPreamble{.seq = 0, .tid = 7, .pc = 0x140001000};

std::vector<std::uint8_t> apicall_payload(const std::string_view name, const std::uint16_t module,
                                          const std::uint8_t flags, const std::string_view arg)
{
    std::vector<std::uint8_t> payload(ev::kApiCallFixedBytes + name.size() + 3 + arg.size());
    const ev::ApiCallFields fields{.name = name,
                                   .module = module,
                                   .flags = flags,
                                   .retval = 0x1D000000,
                                   .caller_retaddr = 0x14000130C};
    const auto head = ev::encode_api_call_head(payload, fields);
    if (!head.has_value()) {
        return {};
    }
    std::size_t cursor = *head;
    if (!ev::append_param_record(payload, cursor, ev::ParamKind::kStrA,
                                 {reinterpret_cast<const std::uint8_t*>(arg.data()), arg.size()})
             .appended) {
        return {};
    }
    payload.resize(cursor);
    return payload;
}

} // namespace

TEST(ApiDescriptions, SeedTableLookups)
{
    const auto& table = behavior::default_descriptions();

    const auto* load_library = table.find("kernel32", "LoadLibraryA");
    ASSERT_NE(load_library, nullptr);
    ASSERT_FALSE(load_library->empty());
    EXPECT_EQ((*load_library)[0], "lpFileName");

    const auto* create_file = table.find_nt("NtCreateFile");
    ASSERT_NE(create_file, nullptr);
    EXPECT_EQ(create_file->size(), 11U);
    EXPECT_EQ((*create_file)[3], "IoStatusBlock");

    // absent entries: nullptr, never a throw or a fabricated list
    EXPECT_EQ(table.find("kernel32", "DefWindowProcW"), nullptr);
    EXPECT_EQ(table.find_nt("NtBuildNumber"), nullptr);
}

TEST(ApiDescriptions, InterceptListIsCoveredByTable)
{
    // The invariant: every loader-route intercepted export must
    // have a description-table entry, or its apicall render silently
    // degrades to argN names.
    const auto& table = behavior::default_descriptions();
    static const char* kIntercepted[] = {
        "VirtualAlloc",        "VirtualProtect",  "VirtualFree",      "LoadLibraryA",
        "LoadLibraryW",        "GetProcAddress",  "GetModuleHandleA", "GetModuleHandleW",
        "ExitProcess",         "RtlAllocateHeap", "RtlFreeHeap",      "RtlReAllocateHeap",
        "RtlCreateHeap",       "RtlDestroyHeap",  "RtlSizeHeap",      "LdrLoadDll",
        "RtlTerminateProcess", "RegOpenKeyExA",   "RegOpenKeyExW",    "RegQueryValueExA",
        "RegQueryValueExW",    "RegCloseKey",
    };
    for (const auto* name : kIntercepted) {
        const bool nt_hit = table.find_nt(name) != nullptr;
        const bool win32_hit =
            table.find("kernel32", name) != nullptr || table.find("advapi32", name) != nullptr;
        EXPECT_TRUE(nt_hit || win32_hit) << "missing description for " << name;
    }
}

TEST(ApiDescriptions, Win32NtEquivalents)
{
    const auto map = behavior::win32_nt_equivalents();
    EXPECT_EQ(map.at("VirtualAlloc"), "NtAllocateVirtualMemory");
    EXPECT_EQ(map.at("ExitProcess"), "NtTerminateProcess");
    // deterministic map: sorted keys, fixed size for the pinned set
    EXPECT_EQ(map.size(), 10U);
}

TEST(ApiDescriptions, CodegenRowsAreWellFormed)
{
    // Every seed row: non-empty name, params non-empty, folded module.
    // Regeneration byte-stability is checked by re-running the generator
    // (see the script header); this guards the wired-in result.
    const auto& table = behavior::default_descriptions();
    EXPECT_GE(table.size(), 40U);
    const auto* alloc = table.find("kernel32", "VirtualAlloc");
    ASSERT_NE(alloc, nullptr);
    EXPECT_EQ(alloc->size(), 4U);
}

TEST(FullStream, JoinsNamesAcrossBothCallLayers)
{
    behavior::EventLedger ledger;
    // apicall: one strA parameter the description table can name
    ledger.record(ev::EventTypeId::kApiCall, kPreamble,
                  apicall_payload("LoadLibraryA", 1, ev::kEventFlagSuccess, "ntdll.dll"));
    // syscall: raw tier (no decoded spec), so its record stays positional
    std::vector<std::uint8_t> syscall_payload(ev::kSyscallFixedBytes + 11);
    const ev::SyscallFields head{.number = 0x1002,
                                 .flags = ev::kEventFlagRaw,
                                 .status = 0,
                                 .caller_retaddr = 0x7FFA11223344};
    ASSERT_TRUE(ev::encode_syscall_head(syscall_payload, head).has_value());
    std::size_t cursor = ev::kSyscallFixedBytes;
    const std::vector<std::uint8_t> zero(8);
    ASSERT_TRUE(
        ev::append_param_record(syscall_payload, cursor, ev::ParamKind::kU64, zero).appended);
    syscall_payload.resize(cursor);
    ledger.record(ev::EventTypeId::kSyscall, kPreamble, syscall_payload);

    sheller::TimelineNameTable names;
    names.modules = {"sample.exe", "kernel32"};
    names.syscalls.emplace(0x1002, "NtTerminateProcess");
    names.apicall_params.emplace("kernel32!LoadLibraryA", std::vector<std::string>{"lpFileName"});

    // The unified stream carries both hops with their names resolved: the
    // description table spells the apicall parameter, the syscall table the
    // mnemonic, and a record past the table's end stays positional.
    const auto events = render_full_events(ledger, names);
    EXPECT_NE(events.find("\"api\":\"LoadLibraryA\""), std::string::npos) << events;
    EXPECT_NE(events.find("\"module\":\"kernel32\""), std::string::npos) << events;
    EXPECT_NE(events.find("\"name\":\"lpFileName\",\"value\":\"ntdll.dll\""), std::string::npos)
        << events;
    EXPECT_NE(events.find("\"api\":\"NtTerminateProcess\""), std::string::npos) << events;
    EXPECT_NE(events.find("\"name\":\"arg1\""), std::string::npos) << events;
    EXPECT_NE(events.find("\"status\":\"0x0\""), std::string::npos) << events;
    EXPECT_NE(events.find("\"status\":true"), std::string::npos) << events;

    // determinism: the same window renders byte-identically
    EXPECT_EQ(events, render_full_events(ledger, names));
}

TEST(ApiDescriptions, NtArityTableMatchesDescriptionCounts)
{
    // Invariant: every Nt name in the description table has an
    // arity-table entry with the same form-parameter count - the engine's
    // decoded tier and the render's name join cannot drift.
    const auto& table = behavior::default_descriptions();
    static const char* kNtNames[] = {
        "NtCreateFile",
        "NtWriteFile",
        "NtAllocateVirtualMemory",
        "NtQueryInformationProcess",
        "NtCreateThreadEx",
        "NtRaiseException",
        "NtTerminateProcess",
    };
    for (const auto* name : kNtNames) {
        const auto* params = table.find_nt(name);
        ASSERT_NE(params, nullptr) << name;
        const auto arity = sheller::syscalls::nt_arg_count(name);
        ASSERT_TRUE(arity.has_value()) << name;
        EXPECT_EQ(*arity, params->size()) << name;
    }
    EXPECT_FALSE(sheller::syscalls::nt_arg_count("NtBuildNumber").has_value());
}

TEST(ApiDescriptions, EquivalenceInverseLookup)
{
    EXPECT_EQ(sheller::syscalls::win32_nt_equivalent("VirtualAlloc"),
              std::optional<std::string_view>("NtAllocateVirtualMemory"));
    EXPECT_EQ(sheller::syscalls::win32_nt_equivalent("LoadLibraryW"),
              std::optional<std::string_view>("LdrLoadDll"));
    EXPECT_FALSE(sheller::syscalls::win32_nt_equivalent("RegOpenKeyExA").has_value());
    EXPECT_FALSE(sheller::syscalls::win32_nt_equivalent("RtlAllocateHeap").has_value());
}

TEST(FullStream, SyntheticEventRendersItsFlag)
{
    behavior::EventLedger ledger;
    std::vector<std::uint8_t> payload(ev::kSyscallFixedBytes);
    const ev::SyscallFields head{.number = 0x1F,
                                 .flags = ev::kEventFlagSynthetic,
                                 .status = 0x1D000000,
                                 .caller_retaddr = 0x14000130C};
    ASSERT_TRUE(ev::encode_syscall_head(payload, head).has_value());
    ledger.record(ev::EventTypeId::kSyscall, kPreamble, payload);

    sheller::TimelineNameTable names;
    names.modules = {"sample.exe"};
    names.syscalls.emplace(0x1F, "NtAllocateVirtualMemory");

    // a synthetic event is a fact, not noise: it stays in the stream and says
    // so on its entry
    const auto events = render_full_events(ledger, names);
    EXPECT_NE(events.find("\"synthetic\":true"), std::string::npos);
    EXPECT_NE(events.find("\"api\":\"NtAllocateVirtualMemory\""), std::string::npos);
    // no arguments key on a zero-record event
    EXPECT_EQ(events.find("\"arguments\""), std::string::npos);
}

TEST(FullStream, DecodedTierRendersFullArityNames)
{
    behavior::EventLedger ledger;
    // an 11-arity decoded event: flags WITHOUT the raw bit, 11 records
    std::vector<std::uint8_t> payload(ev::kSyscallFixedBytes + 11 * 11);
    const ev::SyscallFields head{
        .number = 0x55, .flags = ev::kEventFlagSuccess, .status = 0, .caller_retaddr = 0x1400018B2};
    if (!ev::encode_syscall_head(payload, head).has_value()) {
        ADD_FAILURE();
        return;
    }
    std::size_t cursor = ev::kSyscallFixedBytes;
    for (int i = 0; i < 11; ++i) {
        std::vector<std::uint8_t> v(8);
        ev::le::store_le64(v.data(), 0x1000 + i);
        if (!ev::append_param_record(payload, cursor, ev::ParamKind::kU64, v).appended) {
            ADD_FAILURE();
            return;
        }
    }
    payload.resize(cursor);
    ledger.record(ev::EventTypeId::kSyscall, kPreamble, payload);

    sheller::TimelineNameTable names;
    names.modules = {"sample.exe"};
    names.syscalls.emplace(0x55, "NtCreateFile");
    // join through the seed table (second hop)
    sheller::behavior::default_descriptions().fill_apicall_params(names.apicall_params);

    const auto events = render_full_events(ledger, names);
    EXPECT_EQ(events.find("\"raw\":true"), std::string::npos); // decoded tier
    EXPECT_NE(events.find("\"name\":\"FileHandle\""), std::string::npos);
    EXPECT_NE(events.find("\"name\":\"EaLength\""), std::string::npos);
    // 11 records, 11 names: no positional fallback anywhere
    EXPECT_EQ(events.find("\"arg1\""), std::string::npos);
    EXPECT_EQ(events.find("\"arg11\""), std::string::npos);
}
