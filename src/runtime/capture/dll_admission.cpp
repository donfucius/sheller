// DLL-input admission, Windows side. See dll_admission.h for the contract.

#include "dll_admission.h"

#include "pe_headers.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#endif

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <cwctype>
#include <format>
#include <fstream>
#include <optional>
#include <set>
#include <span>

namespace sheller::capture {
namespace {

std::string folded(const std::string& name)
{
    std::string out;
    out.reserve(name.size());
    for (const char c : name) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return out;
}

std::wstring to_wide(const std::string& text)
{
    std::wstring out(text.size() + 1, L'\0');
    const int written =
        MultiByteToWideChar(CP_UTF8, 0, text.c_str(), -1, out.data(), static_cast<int>(out.size()));
    out.resize(written > 0 ? static_cast<std::size_t>(written - 1) : 0);
    return out;
}

// System-source proof: the module's loaded path must sit directly inside
// the system directory - no nested paths, no ".." hops, no file that merely
// shares a name with a system DLL. Case-insensitive throughout: the system
// directory's own spelling varies between API results.
bool under_system_directory(const std::wstring& path)
{
    wchar_t system_dir[MAX_PATH] = {};
    const auto length = GetSystemDirectoryW(system_dir, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
        return false;
    }
    auto lower = [](std::wstring text) {
        for (wchar_t& c : text) {
            c = static_cast<wchar_t>(towlower(c));
        }
        return text;
    };
    const std::wstring prefix = lower({system_dir, length});
    if (path.size() <= prefix.size() + 1) {
        return false;
    }
    const std::wstring lowered = lower(path);
    if (lowered.compare(0, prefix.size(), prefix) != 0 || path[prefix.size()] != L'\\') {
        return false;
    }
    const std::wstring rest = lowered.substr(prefix.size() + 1);
    return rest.find(L'\\') == std::wstring::npos && rest.find(L"..") == std::wstring::npos;
}

std::uint32_t rd32(const std::uint8_t* p)
{
    std::uint32_t v = 0;
    std::memcpy(&v, p, sizeof v);
    return v;
}

constexpr std::size_t kUnmapped = static_cast<std::size_t>(-1);

std::size_t rva_off(const std::span<const std::uint8_t> bytes, const std::int32_t lfanew,
                    const std::uint32_t rva)
{
    const std::uint16_t sections =
        *reinterpret_cast<const std::uint16_t*>(bytes.data() + lfanew + 6);
    const std::uint16_t opt_size =
        *reinterpret_cast<const std::uint16_t*>(bytes.data() + lfanew + 20);
    const std::uint32_t headers_size = rd32(bytes.data() + lfanew + 24 + 60);
    if (rva < headers_size) {
        return rva;
    }
    const std::size_t table = lfanew + 24 + opt_size;
    for (std::uint16_t i = 0; i < sections; ++i) {
        const std::size_t s = table + i * 40;
        if (s + 40 > bytes.size()) {
            return kUnmapped;
        }
        const std::uint32_t va = rd32(bytes.data() + s + 12);
        std::uint32_t span = rd32(bytes.data() + s + 8);
        const std::uint32_t raw = rd32(bytes.data() + s + 16);
        const std::uint32_t ptr = rd32(bytes.data() + s + 20);
        if (span == 0 || span > raw) {
            span = raw;
        }
        if (rva >= va && rva < va + span) {
            const std::size_t offset = ptr + (rva - va);
            return offset < bytes.size() ? offset : kUnmapped;
        }
    }
    return kUnmapped;
}

struct ExportTable {
    const std::uint8_t* data = nullptr;
    std::size_t size = 0;
    std::int32_t lfanew = 0;
    bool pe32plus = true;
    std::uint32_t dir_rva = 0;
    std::uint32_t dir_size = 0;
    std::uint32_t ordinal_base = 0;
    std::uint32_t function_count = 0;
    std::uint32_t name_count = 0;
    std::uint32_t functions_rva = 0;
    std::uint32_t names_rva = 0;
    std::uint32_t ordinals_rva = 0;
    bool valid = false;
};

ExportTable parse_exports(const std::span<const std::uint8_t> bytes)
{
    ExportTable table;
    if (bytes.size() < 0x40) {
        return table;
    }
    table.data = bytes.data();
    table.size = bytes.size();
    table.lfanew = static_cast<std::int32_t>(rd32(bytes.data() + 0x3C));
    if (table.lfanew < 0 || static_cast<std::size_t>(table.lfanew) + 24 > bytes.size()) {
        return table;
    }
    const std::uint16_t machine =
        *reinterpret_cast<const std::uint16_t*>(bytes.data() + table.lfanew + 4);
    table.pe32plus = machine == kMachineAmd64;
    if (!table.pe32plus && machine != kMachineI386) {
        return table;
    }
    const std::size_t dir_base = table.lfanew + 24 + (table.pe32plus ? 112 : 96);
    if (dir_base + 8 > bytes.size()) {
        return table;
    }
    table.dir_rva = rd32(bytes.data() + dir_base);
    table.dir_size = rd32(bytes.data() + dir_base + 4);
    if (table.dir_rva == 0) {
        return table;
    }
    const std::size_t dir = rva_off(bytes, table.lfanew, table.dir_rva);
    if (dir == kUnmapped || dir + 40 > bytes.size()) {
        return table;
    }
    table.ordinal_base = rd32(bytes.data() + dir + 16);
    table.function_count = rd32(bytes.data() + dir + 20);
    // IMAGE_EXPORT_DIRECTORY: NumberOfNames @+24, AddressOfFunctions @+28,
    // AddressOfNames @+32, AddressOfNameOrdinals @+36.
    table.name_count = rd32(bytes.data() + dir + 24);
    table.functions_rva = rd32(bytes.data() + dir + 28);
    table.names_rva = rd32(bytes.data() + dir + 32);
    table.ordinals_rva = rd32(bytes.data() + dir + 36);
    table.valid = table.function_count > 0 && table.functions_rva != 0;
    return table;
}

// Resolution outcome for one referenced symbol.
struct ExportHit {
    bool exported = false;
    bool forwarder = false;   // "DLL.Function" string
    std::string forwarded_to; // target DLL name when forwarder
};

ExportHit find_export(const ExportTable& table, const std::string& name,
                      const std::uint16_t ordinal, const bool by_ordinal)
{
    ExportHit hit;
    if (!table.valid) {
        return hit;
    }
    std::uint32_t function_rva = 0;
    if (by_ordinal) {
        if (ordinal < table.ordinal_base ||
            static_cast<std::uint32_t>(ordinal - table.ordinal_base) >= table.function_count) {
            return hit;
        }
        const std::size_t arr = rva_off({table.data, table.size}, table.lfanew,
                                        table.functions_rva + 4u * (ordinal - table.ordinal_base));
        if (arr == kUnmapped) {
            return hit;
        }
        function_rva = rd32(table.data + arr);
    } else {
        bool matched = false;
        for (std::uint32_t i = 0; i < table.name_count && i < 65536; ++i) {
            const std::size_t name_slot =
                rva_off({table.data, table.size}, table.lfanew, table.names_rva + 4u * i);
            if (name_slot == kUnmapped) {
                break;
            }
            const std::size_t candidate =
                rva_off({table.data, table.size}, table.lfanew, rd32(table.data + name_slot));
            if (candidate == kUnmapped) {
                continue;
            }
            const char* candidate_name = reinterpret_cast<const char*>(table.data + candidate);
            if (std::string_view{candidate_name} != name) {
                continue;
            }
            const std::size_t ord_slot =
                rva_off({table.data, table.size}, table.lfanew, table.ordinals_rva + 2u * i);
            if (ord_slot == kUnmapped) {
                return hit;
            }
            const auto ord_index = *reinterpret_cast<const std::uint16_t*>(table.data + ord_slot);
            const std::size_t arr = rva_off({table.data, table.size}, table.lfanew,
                                            table.functions_rva + 4u * ord_index);
            if (arr == kUnmapped) {
                return hit;
            }
            function_rva = rd32(table.data + arr);
            matched = true;
            break;
        }
        if (!matched) {
            return hit;
        }
    }
    if (function_rva == 0) {
        return hit;
    }
    if (function_rva >= table.dir_rva && function_rva < table.dir_rva + table.dir_size) {
        const std::size_t fwd = rva_off({table.data, table.size}, table.lfanew, function_rva);
        if (fwd == kUnmapped) {
            return hit;
        }
        const char* text = reinterpret_cast<const char*>(table.data + fwd);
        std::string forwarding{text};
        const auto dot = forwarding.find('.');
        if (dot == std::string::npos) {
            return hit; // malformed forwarder: treat as not exported
        }
        hit.exported = true;
        hit.forwarder = true;
        hit.forwarded_to = forwarding.substr(0, dot);
        return hit;
    }
    hit.exported = true;
    return hit;
}

std::string admission_error(const std::string& module, const char* reason)
{
    return std::format("dependency {}: {}", module, reason);
}

} // namespace

std::expected<RunnerPlan, std::string>
admit_dll_sample(const std::vector<std::uint8_t>& sample_bytes, const std::string& arrival_name)
{
    // The arrival name becomes the runner's path string and the emulated
    // Ldr entry's BaseDllName (bounded to 64 chars there) - enforce one
    // bound at the source. Non-ASCII is rejected honestly rather than
    // through a lossy widening the engine cannot round-trip.
    if (arrival_name.empty() || arrival_name.size() > 64 ||
        !std::all_of(arrival_name.begin(), arrival_name.end(),
                     [](const unsigned char c) { return c >= 0x20 && c < 0x7F && c != '\\'; })) {
        return std::unexpected("sample file name: empty, non-ASCII, or over 64 characters");
    }
    std::vector<PeImportThunk> imports;
    if (const auto error = parse_imports(sample_bytes.data(), sample_bytes.size(), imports);
        error != PeError::kNone) {
        return std::unexpected(std::string(pe_error_message(error)));
    }

    RunnerPlan plan;
    plan.arch = WrapArch::kX64;
    plan.arrival_name = arrival_name;
    plan.imports.push_back({"kernel32.dll", "LoadLibraryW", 0});
    plan.imports.push_back({"kernel32.dll", "ExitProcess", 0});

    // BFS over the dependency closure. Level 0 entries (the sample's direct
    // imports) each contribute one runner import; deeper levels are
    // verification-only - the loader resolves the chain through the same
    // system32 search when it initializes the runner's imports.
    struct QueueEntry {
        std::string module;
        bool direct;
    };
    std::vector<QueueEntry> queue;
    for (const auto& import : imports) {
        if (std::none_of(queue.begin(), queue.end(), [&](const QueueEntry& entry) {
                return folded(entry.module) == folded(import.module);
            })) {
            queue.push_back({import.module, true});
        }
    }

    std::set<std::string> processed{folded("kernel32.dll")}; // base pair covers it
    std::size_t cursor = 0;
    while (cursor < queue.size()) {
        const QueueEntry entry = queue[cursor++];
        const std::string key = folded(entry.module);
        if (key == folded(arrival_name)) {
            return std::unexpected(
                admission_error(entry.module, "dependency name collides with the sample"));
        }
        if (processed.count(key) != 0) {
            continue;
        }
        processed.insert(key);
        if (entry.module.empty() || entry.module.find('\\') != std::string::npos ||
            entry.module.find('/') != std::string::npos ||
            entry.module.find(':') != std::string::npos ||
            entry.module.find("..") != std::string::npos) {
            return std::unexpected(admission_error(entry.module, "path-shaped import name"));
        }

        // System verification. The data-file probe is the primary path: with
        // LOAD_LIBRARY_SEARCH_SYSTEM32 the loader's search set is exactly the
        // system directory (a same-named file in the sample's or current
        // directory is unreachable), and AS_DATAFILE means no code runs - so
        // probe success itself proves the system source. API-set virtual
        // names fail that probe (no backing file) and fall through to a real
        // system32-only load, where the module's path is checked into
        // System32 (GetModuleFileNameW works for real loads only - the
        // data-file probe returns an empty path by contract).
        std::vector<std::uint8_t> module_bytes;
        HMODULE map = LoadLibraryExW(to_wide(entry.module).c_str(), nullptr,
                                     LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_AS_DATAFILE);
        const bool via_datafile = map != nullptr;
        if (map == nullptr) {
            map = LoadLibraryExW(to_wide(entry.module).c_str(), nullptr,
                                 LOAD_LIBRARY_SEARCH_SYSTEM32);
        }
        if (map == nullptr) {
            return std::unexpected(admission_error(entry.module, "not a verifiable system module"));
        }
        wchar_t module_path[MAX_PATH * 2] = {};
        bool path_ok = true;
        if (!via_datafile) {
            path_ok = GetModuleFileNameW(map, module_path, MAX_PATH * 2) != 0 &&
                      under_system_directory(module_path);
        }
        FreeLibrary(map);
        if (!path_ok) {
            return std::unexpected(admission_error(
                entry.module, "resolves outside the system directory (private module)"));
        }
        if (via_datafile) {
            // Re-derive the verified file path for the byte reads below.
            wchar_t system_dir[MAX_PATH] = {};
            const auto length = GetSystemDirectoryW(system_dir, MAX_PATH);
            if (length == 0 || length >= MAX_PATH) {
                return std::unexpected(
                    admission_error(entry.module, "system directory unreadable"));
            }
            std::wstring wide{system_dir, length};
            wide += L'\\';
            wide += to_wide(entry.module);
            const int needed =
                WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
            std::string utf8(static_cast<std::size_t>(needed > 0 ? needed - 1 : 0), '\0');
            if (!utf8.empty()) {
                WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, utf8.data(),
                                    static_cast<int>(utf8.size() + 1), nullptr, nullptr);
            }
            std::ifstream in(utf8, std::ios::binary);
            module_bytes = std::vector<std::uint8_t>{std::istreambuf_iterator<char>(in),
                                                     std::istreambuf_iterator<char>()};
        } else {
            std::ifstream in(module_path, std::ios::binary);
            module_bytes = std::vector<std::uint8_t>{std::istreambuf_iterator<char>(in),
                                                     std::istreambuf_iterator<char>()};
        }
        if (module_bytes.empty()) {
            return std::unexpected(admission_error(entry.module, "system module unreadable"));
        }

        // The module's own imports join the closure (verification only).
        std::vector<PeImportThunk> module_imports;
        if (parse_imports(module_bytes.data(), module_bytes.size(), module_imports) ==
            PeError::kNone) {
            for (const auto& import : module_imports) {
                const std::string dep_key = folded(import.module);
                if (dep_key != folded("kernel32.dll") && dep_key != folded(arrival_name) &&
                    processed.count(dep_key) == 0 &&
                    std::none_of(queue.begin(), queue.end(), [&](const QueueEntry& pending) {
                        return folded(pending.module) == dep_key;
                    })) {
                    queue.push_back({import.module, false});
                }
            }
        }

        if (!entry.direct) {
            continue;
        }

        // Pick the first referenced symbol that resolves in this module's
        // export table; a forwarder adds its target DLL to the closure.
        const ExportTable exports = parse_exports(module_bytes);
        bool selected = false;
        for (const auto& import : imports) {
            if (folded(import.module) != key) {
                continue;
            }
            const ExportHit hit =
                find_export(exports, import.name, import.ordinal, import.name.empty());
            if (!hit.exported) {
                continue;
            }
            if (hit.forwarder) {
                const std::string target_key = folded(hit.forwarded_to);
                if (target_key != folded("kernel32.dll") && target_key != folded(arrival_name) &&
                    processed.count(target_key) == 0 &&
                    std::none_of(queue.begin(), queue.end(), [&](const QueueEntry& pending) {
                        return folded(pending.module) == target_key;
                    })) {
                    queue.push_back({hit.forwarded_to, false});
                }
            }
            plan.imports.push_back({entry.module, import.name, import.ordinal});
            if (plan.imports.size() > kMaxRunnerImports) {
                return std::unexpected("dependency closure exceeds the runner capacity");
            }
            selected = true;
            break;
        }
        if (!selected) {
            // Without an importable symbol the runner cannot preload this
            // dependency - out of contract, by name.
            return std::unexpected(
                admission_error(entry.module, "no importable export for the referenced symbol"));
        }
    }

    return plan;
}

} // namespace sheller::capture
