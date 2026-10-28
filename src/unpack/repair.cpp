#include "repair.h"

#include "exports_mapper.h"
#include "rebuild_probe.h"

#include <sheller/log.h>
#include <sheller/unpack.h>

#include <algorithm>
#include <charconv>
#include <cstring>
#include <fstream>
#include <string_view>

namespace sheller::unpack {

// -- PE header field offsets (layout offsets pinned as
// constexpr with provenance). "COFF" offsets are from the COFF header
// start (e_lfanew + 4); "optional" offsets are from the optional header
// start (e_lfanew + 4 + COFF). The data directory is an array of
// 8-byte {VirtualAddress, Size} entries indexed by kDataDirectory*:
// DataDirectory[0] = export dir, DataDirectory[1] = import dir. Values
// cross-checked against sizeof/offsetof over the SDK's IMAGE_DOS_HEADER,
// IMAGE_FILE_HEADER, IMAGE_OPTIONAL_HEADER64, IMAGE_SECTION_HEADER and
// IMAGE_IMPORT_DESCRIPTOR (MSVC will not constant-fold offsetof on these
// into constexpr initializers, hence the literals).
inline constexpr std::size_t kDosHeaderELfanewOffset = 0x3C;
inline constexpr std::size_t kPeSignatureSize = 4;
inline constexpr std::size_t kCoffHeaderSize = 20;
inline constexpr std::size_t kCoffNumberOfSectionsOffset = 2;
inline constexpr std::size_t kCoffSizeOfOptionalHeaderOffset = 16;
inline constexpr std::size_t kPeSectionHeaderSize = 40;
inline constexpr std::size_t kOptionalHeaderOffset = kPeSignatureSize + kCoffHeaderSize;
inline constexpr std::size_t kOptionalHeaderSizeOfImageOffset = 0x38;
inline constexpr std::size_t kOptionalHeaderAddressOfEntryPointOffset = 0x10;
inline constexpr std::size_t kOptionalHeaderDataDirectoryBase64 = 0x70; // PE32+
inline constexpr std::size_t kOptionalHeaderDataDirectoryBase32 = 0x60; // PE32
inline constexpr std::size_t kDataDirectoryEntrySize = 8;
inline constexpr std::size_t kDataDirectoryExport = 0; // DataDirectory[0]
inline constexpr std::size_t kDataDirectoryImport = 1; // DataDirectory[1]
inline constexpr std::size_t kSectionHeaderVirtualSizeOffset = 8;
inline constexpr std::size_t kSectionHeaderVirtualAddressOffset = 12;
inline constexpr std::size_t kSectionHeaderSizeOfRawDataOffset = 16;
inline constexpr std::size_t kSectionHeaderPointerToRawDataOffset = 20;
inline constexpr std::size_t kSectionHeaderCharacteristicsOffset = 36;
namespace {

constexpr std::size_t kMaxImageBytes = 64ULL * 1024 * 1024; // SizeOfImage sanity bound

std::string hex16(const std::uint64_t value)
{
    char buf[17] = {};
    std::snprintf(buf, sizeof buf, "%016llx", static_cast<unsigned long long>(value));
    return buf;
}

std::string read_file(const std::filesystem::path& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

std::vector<ManifestEntry> parse_manifest(const std::string& text)
{
    std::vector<ManifestEntry> entries;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t end = text.find('\n', pos);
        if (end == std::string::npos) {
            end = text.size();
        }
        std::string_view line(text.data() + pos, end - pos);
        pos = end + 1;
        if (!line.empty() && line.back() == '\r') {
            line.remove_suffix(1);
        }
        std::uint64_t fields[5] = {};
        std::size_t count = 0;
        std::size_t cursor = 0;
        while (cursor <= line.size() && count < 5) {
            const auto space = line.find(' ', cursor);
            const auto token = line.substr(
                cursor, space == std::string_view::npos ? std::string_view::npos : space - cursor);
            const auto [ptr, ec] =
                std::from_chars(token.data(), token.data() + token.size(), fields[count], 16);
            if (ec != std::errc{} || ptr != token.data() + token.size()) {
                count = 0; // not a manifest line
                break;
            }
            ++count;
            if (space == std::string_view::npos) {
                break;
            }
            cursor = space + 1;
        }
        if (count == 5) {
            entries.push_back({fields[0], fields[1], static_cast<std::uint32_t>(fields[2]),
                               static_cast<std::uint32_t>(fields[3]), fields[4]});
        }
    }
    return entries;
}

std::vector<AggregatedRegion> aggregate_regions(const std::vector<ManifestEntry>& entries)
{
    std::vector<ManifestEntry> sorted = entries;
    std::sort(sorted.begin(), sorted.end(),
              [](const ManifestEntry& a, const ManifestEntry& b) { return a.base < b.base; });
    std::vector<AggregatedRegion> out;
    for (const auto& entry : sorted) {
        if (!out.empty() && out.back().type == entry.type &&
            out.back().base + out.back().size == entry.base) {
            out.back().size += entry.size;
            continue;
        }
        out.push_back({entry.base, entry.size, entry.type});
    }
    return out;
}

std::optional<std::uint32_t> probe_size_of_image(const std::uint8_t* image, const std::size_t size)
{
    if (size < 0x98 || image[0] != 'M' || image[1] != 'Z') {
        return std::nullopt;
    }
    const auto e_lfanew = static_cast<std::size_t>(image[kDosHeaderELfanewOffset]) |
                          (static_cast<std::size_t>(image[0x3D]) << 8) |
                          (static_cast<std::size_t>(image[0x3E]) << 16) |
                          (static_cast<std::size_t>(image[0x3F]) << 24);
    if (e_lfanew + 0x58 > size || e_lfanew == 0) {
        return std::nullopt;
    }
    if (image[e_lfanew] != 'P' || image[e_lfanew + 1] != 'E' || image[e_lfanew + 2] != 0 ||
        image[e_lfanew + 3] != 0) {
        return std::nullopt;
    }
    // Optional header magic at +0x18, SizeOfImage at optional + 0x38:
    // e_lfanew + 4 (sig) + 20 (COFF) + 0x38 = e_lfanew + 0x50.
    const std::size_t offset =
        e_lfanew + kPeSignatureSize + kCoffHeaderSize + kOptionalHeaderSizeOfImageOffset;
    return static_cast<std::uint32_t>(image[offset]) |
           (static_cast<std::uint32_t>(image[offset + 1]) << 8) |
           (static_cast<std::uint32_t>(image[offset + 2]) << 16) |
           (static_cast<std::uint32_t>(image[offset + 3]) << 24);
}

IatAudit audit_imports(const std::uint8_t* image, const std::size_t size,
                       const ExportsMapper& mapper)
{
    IatAudit audit;
    const auto read_u32 = [&](const std::size_t rva) -> std::uint32_t {
        if (rva + 4 > size) {
            return 0;
        }
        return static_cast<std::uint32_t>(image[rva]) |
               (static_cast<std::uint32_t>(image[rva + 1]) << 8) |
               (static_cast<std::uint32_t>(image[rva + 2]) << 16) |
               (static_cast<std::uint32_t>(image[rva + 3]) << 24);
    };
    const auto read_u64 = [&](const std::size_t rva) -> std::uint64_t {
        if (rva + 8 > size) {
            return 0;
        }
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(image[rva + i]) << (i * 8);
        }
        return value;
    };
    if (size < 0x98) {
        return audit;
    }
    const auto e_lfanew = static_cast<std::size_t>(image[kDosHeaderELfanewOffset]) |
                          (static_cast<std::size_t>(image[0x3D]) << 8) |
                          (static_cast<std::size_t>(image[0x3E]) << 16) |
                          (static_cast<std::size_t>(image[0x3F]) << 24);
    const std::size_t import_dir = e_lfanew + kOptionalHeaderOffset +
                                   kOptionalHeaderDataDirectoryBase64 +
                                   kDataDirectoryImport * kDataDirectoryEntrySize;
    const std::size_t thunk_size = 8;
    if (import_dir + 8 > size) {
        return audit;
    }
    const auto import_rva = read_u32(import_dir);
    for (std::size_t descriptor = 0; import_rva != 0; ++descriptor) {
        const std::size_t desc = import_rva + descriptor * 20;
        if (desc + 20 > size) {
            break;
        }
        const auto name_rva = read_u32(desc + 12);
        const auto first_thunk = read_u32(desc + 16);
        if (name_rva == 0 && first_thunk == 0) {
            break; // null terminator descriptor
        }
        const auto original_thunk = read_u32(desc);
        for (std::size_t index = 0; index * thunk_size + thunk_size <= size; ++index) {
            if (original_thunk != 0 && read_u64(original_thunk + index * thunk_size) == 0) {
                break; // this descriptor's ILT ends before the adjacent IAT slice
            }
            const std::size_t thunk_rva = first_thunk + index * thunk_size;
            const auto bound_va = thunk_size == 4 ? read_u32(thunk_rva) : read_u64(thunk_rva);
            if (bound_va == 0) {
                break; // null terminator thunk
            }
            if (mapper.resolve(bound_va).has_value()) {
                ++audit.covered_count;
            } else {
                audit.uncovered.push_back({static_cast<std::uint32_t>(thunk_rva), bound_va});
            }
        }
    }
    return audit;
}

namespace {

// A thunk classified as name-record form must point at a plausible
// hint/name record: a hint word followed by printable ASCII and a NUL,
// inside the image. Small unresolvable values fail this and stay in the
// uncovered report.
auto looks_like_name_record(const std::vector<std::uint8_t>& image, const std::uint64_t rva)
{
    const auto size = image.size();
    if (rva + 3 > size) {
        return false;
    }
    auto i = static_cast<std::size_t>(rva) + 2;
    while (i < size && image[i] != 0) {
        if (image[i] < 0x20 || image[i] > 0x7e) {
            return false;
        }
        ++i;
    }
    return i > static_cast<std::size_t>(rva) + 2 && i < size;
}

// One reconstructed import: the thunk's RVA in the dump image plus the
// (module, function) the mapper attributed to its runtime value. An ordinal
// import keeps the ILT ordinal-flag form instead of a name.
struct ReconstructedImport {
    std::size_t thunk_rva{};
    std::string module;
    std::string function;
    bool by_ordinal{};
    std::uint16_t ordinal{};
};

// Scans the image for runs of consecutive thunks whose values are absolute
// runtime VAs the mapper resolves - the mark of a packer-resolved original
// IAT (the unpacking stub writes GetProcAddress results back over the
// payload's own thunk arrays, and zeroes the original descriptors, so the
// header's import directory cannot reach them). Runs shorter than three
// entries are ignored: one or two stray resolvable words are far more
// likely pointer data than an import array.
std::vector<std::vector<ReconstructedImport>>
find_resolved_iat_runs(std::vector<std::uint8_t>& image, const ExportsMapper& mapper)
{
    std::vector<std::vector<ReconstructedImport>> runs;
    const auto size = image.size();
    const auto read_u64 = [&](const std::size_t rva) {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 8 && rva + i < size; ++i) {
            value |= static_cast<std::uint64_t>(image[rva + i]) << (i * 8);
        }
        return value;
    };
    constexpr std::size_t kThunk = 8; // x64 dump images
    constexpr std::size_t kMinRun = 1;
    std::vector<ReconstructedImport> current;
    for (std::size_t rva = 0x1000; rva + kThunk <= size; rva += kThunk) {
        const auto value = read_u64(rva);
        const auto resolved = value >= size ? mapper.resolve(value) : std::nullopt;
        if (resolved.has_value()) {
            current.push_back({rva, resolved->module, resolved->function});
        } else {
            if (current.size() >= kMinRun) {
                runs.push_back(std::move(current));
            }
            current.clear();
        }
    }
    if (current.size() >= kMinRun) {
        runs.push_back(std::move(current));
    }
    return runs;
}

} // namespace

// First-chance reconstruction from the dump's own import directory. An
// unpacking stub that restores the payload's original import table leaves
// the ground truth in the image: DataDirectory[1] descriptors carry each
// dependency's real name and - through the OriginalFirstThunk - the ORIGINAL
// referenced symbol per slot, forwarders included. Rebuilding from those
// identities keeps every (DLL, name) pair resolvable: kernel32 exports
// EnterCriticalSection as a forwarder, so the pair survives even though the
// bound slot address landed in ntdll. The address-run reconstruction below
// stays as the fallback for images whose directory was wiped (the packed
// EXE corpus shape). Returns false when no usable directory exists.
bool reconstruct_from_original_directory(std::vector<std::uint8_t>& image,
                                         const ExportsMapper& mapper, IatAudit& audit,
                                         std::vector<std::vector<ReconstructedImport>>& groups)
{
    const auto size = image.size();
    const auto e_lfanew = static_cast<std::size_t>(image[kDosHeaderELfanewOffset]) |
                          (static_cast<std::size_t>(image[0x3D]) << 8) |
                          (static_cast<std::size_t>(image[0x3E]) << 16) |
                          (static_cast<std::size_t>(image[0x3F]) << 24);
    const std::size_t dir_entry = e_lfanew + kOptionalHeaderOffset +
                                  kOptionalHeaderDataDirectoryBase64 +
                                  kDataDirectoryImport * kDataDirectoryEntrySize;
    if (dir_entry + 8 > size) {
        return false;
    }
    const auto dir_rva = static_cast<std::size_t>(image[dir_entry]) |
                         (static_cast<std::size_t>(image[dir_entry + 1]) << 8) |
                         (static_cast<std::size_t>(image[dir_entry + 2]) << 16) |
                         (static_cast<std::size_t>(image[dir_entry + 3]) << 24);
    if (dir_rva == 0 || dir_rva + 20 > size) {
        return false;
    }
    const auto read_u64 = [&](const std::size_t rva) {
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 8 && rva + i < size; ++i) {
            value |= static_cast<std::uint64_t>(image[rva + i]) << (i * 8);
        }
        return value;
    };
    const auto read_u32 = [&](const std::size_t rva) {
        return static_cast<std::uint32_t>(image[rva]) |
               (static_cast<std::uint32_t>(image[rva + 1]) << 8) |
               (static_cast<std::uint32_t>(image[rva + 2]) << 16) |
               (static_cast<std::uint32_t>(image[rva + 3]) << 24);
    };
    constexpr std::size_t kThunk = 8;
    for (std::size_t d = 0; d < 64; ++d) {
        const std::size_t desc = dir_rva + d * 20;
        if (desc + 20 > size) {
            return false;
        }
        const auto name_rva = read_u32(desc + 12);
        const auto first_thunk = read_u32(desc + 16);
        if (name_rva == 0 && first_thunk == 0) {
            break; // terminator
        }
        if (name_rva == 0 || name_rva >= size || first_thunk == 0 || first_thunk + kThunk > size) {
            return false; // malformed: caller falls back
        }
        std::string module;
        for (std::size_t i = name_rva; i < size && image[i] != 0 && module.size() < 64; ++i) {
            module.push_back(static_cast<char>(image[i]));
        }
        if (module.empty()) {
            return false;
        }
        const auto int_rva = read_u32(desc); // OriginalFirstThunk: the original names
        std::vector<ReconstructedImport> imports;
        for (std::size_t t = 0; t < 512; ++t) {
            const std::uint64_t original = int_rva != 0 ? read_u64(int_rva + t * kThunk) : 0;
            if (original == 0) {
                break; // terminator
            }
            ReconstructedImport imp;
            imp.thunk_rva = first_thunk + t * kThunk;
            imp.module = module;
            if ((original >> 63) != 0) {
                imp.by_ordinal = true;
                imp.ordinal = static_cast<std::uint16_t>(original & 0xFFFF);
            } else {
                const auto hint_rva = static_cast<std::size_t>(original & 0x7FFFFFFFULL);
                if (hint_rva + 3 > size) {
                    return false;
                }
                for (std::size_t i = hint_rva + 2;
                     i < size && image[i] != 0 && imp.function.size() < 128; ++i) {
                    imp.function.push_back(static_cast<char>(image[i]));
                }
                if (imp.function.empty()) {
                    return false;
                }
            }
            // Sanity: the slot's bound runtime value should still resolve to
            // some known module; unresolvable slots mean this directory is
            // not a restored payload table - fall back.
            const auto bound = read_u64(imp.thunk_rva);
            if (bound < size || !mapper.resolve(bound).has_value()) {
                return false;
            }
            imports.push_back(std::move(imp));
        }
        if (imports.empty()) {
            return false;
        }
        audit.covered_count += imports.size();
        groups.push_back(std::move(imports));
    }
    return !groups.empty();
}

IatAudit reconstruct_imports(std::vector<std::uint8_t>& image, const ExportsMapper& mapper)
{
    IatAudit audit;
    std::vector<std::vector<ReconstructedImport>> runs;
    if (reconstruct_from_original_directory(image, mapper, audit, runs)) {
        return audit; // groups hold the original identities; shared rebuild below
    }
    audit = IatAudit{};
    // Do not replace a declared, partially unresolved IAT with only the
    // resolvable runs: that would erase evidence and turn partial into complete.
    if (!audit_imports(image.data(), image.size(), mapper).uncovered.empty()) {
        return audit;
    }
    runs = find_resolved_iat_runs(image, mapper);
    if (runs.empty()) {
        return audit;
    }

    // One descriptor per RESOLVED module within each run: forwarded
    // slots resolve into their final host DLL, and a (kernel32, Rtl*)
    // pair is unresolvable for the Windows loader - so the run splits
    // into consecutive sub-groups, each with its own descriptor and its
    // own fresh ILT in the blob. Slot positions never move (the code
    // references fixed IAT slots); the loader binds each descriptor's
    // slots from that descriptor's ILT, which terminates in the blob.
    struct Group {
        std::string module;
        std::vector<const ReconstructedImport*> imports;
    };
    std::vector<Group> groups;
    for (const auto& run : runs) {
        std::string current_module = run.front().module;
        std::vector<const ReconstructedImport*> current_imports{&run.front()};
        for (std::size_t i = 1; i < run.size(); ++i) {
            if (run[i].module != current_module) {
                groups.push_back({current_module, std::move(current_imports)});
                current_module = run[i].module;
                current_imports.clear();
            }
            current_imports.push_back(&run[i]);
        }
        groups.push_back({current_module, std::move(current_imports)});
    }

    // Build the reconstruction blob: hint/name records, then the DLL name
    // strings, then the descriptor array with its null terminator. The blob
    // becomes a new section appended past the current SizeOfImage - the
    // image's own tail is far too small for a full payload import set.
    const std::size_t section_alignment = 0x1000;
    const auto e_lfanew = static_cast<std::size_t>(image[kDosHeaderELfanewOffset]) |
                          (static_cast<std::size_t>(image[0x3D]) << 8) |
                          (static_cast<std::size_t>(image[0x3E]) << 16) |
                          (static_cast<std::size_t>(image[0x3F]) << 24);
    const auto read_u32_at = [&](const std::size_t rva) {
        return static_cast<std::uint32_t>(image[rva]) |
               (static_cast<std::uint32_t>(image[rva + 1]) << 8) |
               (static_cast<std::uint32_t>(image[rva + 2]) << 16) |
               (static_cast<std::uint32_t>(image[rva + 3]) << 24);
    };
    const std::size_t section_rva = (read_u32_at(e_lfanew + kPeSignatureSize + kCoffHeaderSize +
                                                 kOptionalHeaderSizeOfImageOffset) +
                                     section_alignment - 1) &
                                    ~(section_alignment - 1);
    std::vector<std::uint8_t> blob;
    std::size_t cursor = 0;
    const auto reserve = [&](const std::size_t bytes) {
        if (cursor + bytes > blob.size()) {
            blob.resize(cursor + bytes, 0);
        }
        const auto at = cursor;
        cursor += bytes;
        return at;
    };

    std::vector<std::uint32_t> name_rvas;
    for (const auto& group : groups) {
        for (const auto* imp : group.imports) {
            if (imp->by_ordinal) {
                // Ordinal imports have no hint/name record: the thunk value
                // is the ordinal-flagged ILT form, filled in at rewrite.
                name_rvas.push_back(0);
                continue;
            }
            const std::string& function = imp->function;
            const auto at = reserve(2 + function.size() + 1);
            blob[at] = 0;
            blob[at + 1] = 0; // Hint
            std::memcpy(blob.data() + at + 2, function.c_str(), function.size() + 1);
            name_rvas.push_back(static_cast<std::uint32_t>(section_rva + at));
        }
    }
    std::vector<std::uint32_t> dll_rvas;
    for (const auto& group : groups) {
        const auto at = reserve(group.module.size() + 1);
        std::memcpy(blob.data() + at, group.module.c_str(), group.module.size() + 1);
        dll_rvas.push_back(static_cast<std::uint32_t>(section_rva + at));
    }
    // Each descriptor reads its own terminated lookup table. Its IAT slice
    // remains adjacent to the next module's slice in the original image.
    cursor = (cursor + 7) & ~std::size_t{7};
    std::vector<std::size_t> ilt_offsets;
    for (const auto& group : groups) {
        ilt_offsets.push_back(reserve((group.imports.size() + 1) * 8));
    }
    const std::size_t desc_at = reserve((groups.size() + 1) * 20);
    const std::size_t blob_used = cursor;

    // Header fit: the new section header must land inside the header page
    // (the region before the first section's RVA). Compute first - nothing
    // in the original image is touched until every check passes.
    const std::uint16_t section_count =
        static_cast<std::uint16_t>(
            image[e_lfanew + kPeSignatureSize + kCoffNumberOfSectionsOffset]) |
        (static_cast<std::uint16_t>(
             image[e_lfanew + kPeSignatureSize + kCoffNumberOfSectionsOffset + 1])
         << 8);
    const std::uint16_t opt_size =
        static_cast<std::uint16_t>(
            image[e_lfanew + kPeSignatureSize + kCoffSizeOfOptionalHeaderOffset]) |
        (static_cast<std::uint16_t>(
             image[e_lfanew + kPeSignatureSize + kCoffSizeOfOptionalHeaderOffset + 1])
         << 8);
    const std::size_t new_header = e_lfanew + kOptionalHeaderOffset + opt_size +
                                   std::size_t(section_count) * kPeSectionHeaderSize;
    if (new_header + 40 > section_rva) {
        return audit; // header page full: nothing claimed, image untouched
    }

    // All checks passed - commit: rewrite the thunks to the new records.
    std::size_t name_index = 0;
    for (std::size_t g = 0; g < groups.size(); ++g) {
        std::size_t slot = ilt_offsets[g];
        for (const auto* imp : groups[g].imports) {
            const std::uint64_t value =
                imp->by_ordinal ? (0x8000000000000000ull | static_cast<std::uint64_t>(imp->ordinal))
                                : static_cast<std::uint64_t>(name_rvas[name_index]);
            std::memcpy(image.data() + imp->thunk_rva, &value, sizeof value);
            std::memcpy(blob.data() + slot, &value, sizeof value);
            slot += sizeof value;
            ++audit.covered_count;
            ++name_index;
        }
    }

    // Fill the descriptor array in the blob.
    const auto put32_blob = [&](const std::size_t at, const std::uint32_t value) {
        blob[at] = static_cast<std::uint8_t>(value);
        blob[at + 1] = static_cast<std::uint8_t>(value >> 8);
        blob[at + 2] = static_cast<std::uint8_t>(value >> 16);
        blob[at + 3] = static_cast<std::uint8_t>(value >> 24);
    };
    for (std::size_t g = 0; g < groups.size(); ++g) {
        const std::size_t desc = desc_at + g * 20;
        put32_blob(desc, static_cast<std::uint32_t>(section_rva + ilt_offsets[g]));
        put32_blob(desc + 4, 0);            // TimeDateStamp
        put32_blob(desc + 8, 0);            // ForwarderChain
        put32_blob(desc + 12, dll_rvas[g]); // Name
        put32_blob(desc + 16, static_cast<std::uint32_t>(groups[g].imports.front()->thunk_rva));
        // FirstThunk preserves the addresses referenced by the payload.
    }
    // The null terminator descriptor stays zero (blob was zero-initialized).

    // Append the blob as a new section and update the headers.
    image.resize(section_rva + blob.size(), 0);
    std::memcpy(image.data() + section_rva, blob.data(), blob.size());
    image[e_lfanew + 6] = static_cast<std::uint8_t>(section_count + 1);
    image[e_lfanew + 7] = static_cast<std::uint8_t>((section_count + 1) >> 8);
    const std::uint32_t new_size_of_image = static_cast<std::uint32_t>(
        section_rva + ((blob.size() + section_alignment - 1) & ~(section_alignment - 1)));
    image[e_lfanew + kPeSignatureSize + kCoffHeaderSize + kOptionalHeaderSizeOfImageOffset] =
        static_cast<std::uint8_t>(new_size_of_image);
    image[e_lfanew + 0x51] = static_cast<std::uint8_t>(new_size_of_image >> 8);
    image[e_lfanew + 0x52] = static_cast<std::uint8_t>(new_size_of_image >> 16);
    image[e_lfanew + 0x53] = static_cast<std::uint8_t>(new_size_of_image >> 24);
    const std::size_t header = new_header;
    const char sec_name[8] = {'.', 'i', 'd', 'a', 't', 'a', '2', 0};
    std::memcpy(image.data() + header, sec_name, 8);
    const auto put32_image = [&](const std::size_t at, const std::uint32_t value) {
        image[at] = static_cast<std::uint8_t>(value);
        image[at + 1] = static_cast<std::uint8_t>(value >> 8);
        image[at + 2] = static_cast<std::uint8_t>(value >> 16);
        image[at + 3] = static_cast<std::uint8_t>(value >> 24);
    };
    put32_image(header + 8, static_cast<std::uint32_t>(blob_used));    // VirtualSize
    put32_image(header + 12, static_cast<std::uint32_t>(section_rva)); // VirtualAddress
    put32_image(header + 16, static_cast<std::uint32_t>(blob.size())); // SizeOfRawData
    put32_image(header + 20, static_cast<std::uint32_t>(section_rva)); // PointerToRawData
    put32_image(header + 36, 0xC0000040);                              // INITIALIZED_DATA | READ

    // Repoint the header's import directory (DataDirectory[1]) at the
    // rebuilt table. The packer's own minimal table stays in memory
    // untouched - the dump keeps its memory truth.
    // DataDirectory[1]: the directory base sits at optional + 0x70 (PE32+)
    // / + 0x60 (PE32) - the optional-header size already includes it, so it
    // must not be added again. The merged image's header page comes from the
    // capture's sanitized snapshot (whose magic byte is not trustworthy), so
    // this x64-only pass uses the PE32+ offset unconditionally.
    const std::size_t dir_entry = e_lfanew + kOptionalHeaderOffset +
                                  kOptionalHeaderDataDirectoryBase64 +
                                  kDataDirectoryImport * kDataDirectoryEntrySize;
    put32_image(dir_entry, static_cast<std::uint32_t>(section_rva + desc_at));
    put32_image(dir_entry + 4, static_cast<std::uint32_t>(groups.size() * 20 + 20));
    return audit;
}

IatAudit synthesize_name_imports(std::vector<std::uint8_t>& image, const ExportsMapper& mapper)
{
    IatAudit audit;
    const auto size = image.size();
    if (size < 0x98) {
        return audit;
    }
    const auto e_lfanew = static_cast<std::size_t>(image[kDosHeaderELfanewOffset]) |
                          (static_cast<std::size_t>(image[0x3D]) << 8) |
                          (static_cast<std::size_t>(image[0x3E]) << 16) |
                          (static_cast<std::size_t>(image[0x3F]) << 24);
    // The merged dump's header page comes from the capture's sanitized
    // snapshot (its optional-header magic is not trustworthy), so this
    // x64-route pass uses the PE32+ layout unconditionally.
    const std::size_t import_dir = e_lfanew + kOptionalHeaderOffset +
                                   kOptionalHeaderDataDirectoryBase64 +
                                   kDataDirectoryImport * kDataDirectoryEntrySize;
    const std::size_t thunk_size = 8;
    if (import_dir + 8 > size) {
        return audit;
    }
    const auto read_u32 = [&](const std::size_t rva) -> std::uint32_t {
        if (rva + 4 > size) {
            return 0;
        }
        return static_cast<std::uint32_t>(image[rva]) |
               (static_cast<std::uint32_t>(image[rva + 1]) << 8) |
               (static_cast<std::uint32_t>(image[rva + 2]) << 16) |
               (static_cast<std::uint32_t>(image[rva + 3]) << 24);
    };
    const auto read_u64 = [&](const std::size_t rva) -> std::uint64_t {
        if (rva + 8 > size) {
            return 0;
        }
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(image[rva + i]) << (i * 8);
        }
        return value;
    };
    const auto write_thunk = [&](const std::size_t rva, const std::uint64_t value) {
        if (thunk_size == 4) {
            const auto v = static_cast<std::uint32_t>(value);
            std::memcpy(image.data() + rva, &v, sizeof v);
        } else {
            std::memcpy(image.data() + rva, &value, sizeof value);
        }
    };

    // The synthesis appends hint/name records past the last non-zero byte of
    // the image: the dump's tail is the payload's clean zero pages, and the
    // region is verified zero before each record so corruption can never be
    // introduced by a wrong placement guess.
    std::size_t cursor = size;
    while (cursor > 0 && image[cursor - 1] == 0) {
        --cursor;
    }
    cursor = (cursor + 1) & ~static_cast<std::size_t>(1);

    const auto import_rva = read_u32(import_dir);
    for (std::size_t descriptor = 0; import_rva != 0; ++descriptor) {
        const std::size_t desc = import_rva + descriptor * 20;
        if (desc + 20 > size) {
            break;
        }
        const auto name_rva = read_u32(desc + 12);
        const auto first_thunk = read_u32(desc + 16);
        if (name_rva == 0 && first_thunk == 0) {
            break; // null terminator descriptor
        }
        const auto original_thunk = read_u32(desc);
        for (std::size_t index = 0; index * thunk_size + thunk_size <= size; ++index) {
            if (original_thunk != 0 && read_u64(original_thunk + index * thunk_size) == 0) {
                break; // this descriptor's ILT ends before the adjacent IAT slice
            }
            const std::size_t thunk_rva = first_thunk + index * thunk_size;
            const auto bound_va = thunk_size == 4 ? read_u32(thunk_rva) : read_u64(thunk_rva);
            if (bound_va == 0) {
                break; // null terminator thunk
            }
            // Exact-address attribution only: the loader writes precise
            // export addresses into the IAT, and a gap VA must stay
            // uncovered instead of borrowing a neighbouring export's name.
            const auto resolved = mapper.resolve(bound_va);
            if (!resolved.has_value()) {
                if (bound_va < size && looks_like_name_record(image, bound_va)) {
                    // already a name-record RVA (or a bound import): leave it
                    ++audit.covered_count;
                } else {
                    audit.uncovered.push_back({static_cast<std::uint32_t>(thunk_rva), bound_va});
                }
                continue;
            }
            if (bound_va < size && looks_like_name_record(image, bound_va)) {
                ++audit.covered_count; // name-record form: peconv validates it
                continue;
            }
            // An absolute runtime VA the mapper attributes: synthesize
            // IMAGE_IMPORT_BY_NAME {Hint=0, name} in the zero tail and point
            // the thunk at it.
            const std::string function = resolved->function;
            const std::size_t need = 2 + function.size() + 1;
            if (cursor + need > size) {
                audit.uncovered.push_back({static_cast<std::uint32_t>(thunk_rva), bound_va});
                continue;
            }
            bool clear = true;
            for (std::size_t i = 0; i < need; ++i) {
                if (image[cursor + i] != 0) {
                    clear = false;
                    break;
                }
            }
            if (!clear) {
                audit.uncovered.push_back({static_cast<std::uint32_t>(thunk_rva), bound_va});
                continue;
            }
            image[cursor] = 0;
            image[cursor + 1] = 0; // Hint
            std::memcpy(image.data() + cursor + 2, function.c_str(), function.size() + 1);
            write_thunk(thunk_rva, cursor);
            cursor = (cursor + need + 1) & ~static_cast<std::size_t>(1);
            ++audit.covered_count;
        }
    }
    return audit;
}

} // namespace sheller::unpack

namespace sheller::unpack {

// OEP stamp: writes the identified OEP (as an RVA from the image base) into the
// PE optional header's AddressOfEntryPoint. The dump is a virtual-layout
// image whose head starts at the region base, so file offset == RVA in the
// header region. Returns false when the header is not a PE we dare touch.
bool stamp_entry_point(std::uint8_t* image, const std::size_t size, const std::uint32_t entry_rva)
{
    if (size < 0x40) {
        return false;
    }
    const auto e_lfanew = static_cast<std::size_t>(image[kDosHeaderELfanewOffset]) |
                          (static_cast<std::size_t>(image[0x3D]) << 8) |
                          (static_cast<std::size_t>(image[0x3E]) << 16) |
                          (static_cast<std::size_t>(image[0x3F]) << 24);
    if (e_lfanew + 4 + 20 + 0x48 > size || e_lfanew == 0) {
        return false;
    }
    if (image[e_lfanew] != 'P' || image[e_lfanew + 1] != 'E' || image[e_lfanew + 2] != 0 ||
        image[e_lfanew + 3] != 0) {
        return false;
    }
    // AddressOfEntryPoint: optional header + 0x10 (same offset PE32/PE32+).
    const std::size_t entry_offset =
        e_lfanew + kPeSignatureSize + kCoffHeaderSize + kOptionalHeaderAddressOfEntryPointOffset;
    image[entry_offset] = static_cast<std::uint8_t>(entry_rva);
    image[entry_offset + 1] = static_cast<std::uint8_t>(entry_rva >> 8);
    image[entry_offset + 2] = static_cast<std::uint8_t>(entry_rva >> 16);
    image[entry_offset + 3] = static_cast<std::uint8_t>(entry_rva >> 24);
    return true;
}
// Residual absolute-VA audit over a REPAIRED copy: after the synthesis every thunk in the covered
// import tables must be name-record form (in-image hint/name record) - a
// thunk still holding any other non-zero value keeps a capture-time bound
// VA and is reported. Pure bytes: the name-record shape is the only
// acceptable repaired form, so the mapper is not needed here.
ResidualAudit audit_residual_abs_va(const std::uint8_t* image, std::size_t size)
{
    ResidualAudit audit;
    if (size < 0x98) {
        return audit;
    }
    const auto e_lfanew = static_cast<std::size_t>(image[kDosHeaderELfanewOffset]) |
                          (static_cast<std::size_t>(image[0x3D]) << 8) |
                          (static_cast<std::size_t>(image[0x3E]) << 16) |
                          (static_cast<std::size_t>(image[0x3F]) << 24);
    const std::size_t import_dir = e_lfanew + kOptionalHeaderOffset +
                                   kOptionalHeaderDataDirectoryBase64 +
                                   kDataDirectoryImport * kDataDirectoryEntrySize;
    const std::size_t thunk_size = 8;
    if (import_dir + 8 > size) {
        return audit;
    }
    const auto read_u32 = [&](const std::size_t rva) -> std::uint32_t {
        if (rva + 4 > size) {
            return 0;
        }
        return static_cast<std::uint32_t>(image[rva]) |
               (static_cast<std::uint32_t>(image[rva + 1]) << 8) |
               (static_cast<std::uint32_t>(image[rva + 2]) << 16) |
               (static_cast<std::uint32_t>(image[rva + 3]) << 24);
    };
    const auto read_u64 = [&](const std::size_t rva) -> std::uint64_t {
        if (rva + 8 > size) {
            return 0;
        }
        std::uint64_t value = 0;
        for (std::size_t i = 0; i < 8; ++i) {
            value |= static_cast<std::uint64_t>(image[rva + i]) << (i * 8);
        }
        return value;
    };
    const std::vector<std::uint8_t> view(image, image + size);
    const auto import_rva = read_u32(import_dir);
    for (std::size_t descriptor = 0; import_rva != 0; ++descriptor) {
        const std::size_t desc = import_rva + descriptor * 20;
        if (desc + 20 > size) {
            break;
        }
        const auto name_rva = read_u32(desc + 12);
        const auto first_thunk = read_u32(desc + 16);
        if (name_rva == 0 && first_thunk == 0) {
            break; // null terminator descriptor
        }
        const auto original_thunk = read_u32(desc);
        for (std::size_t index = 0; index * thunk_size + thunk_size <= size; ++index) {
            if (original_thunk != 0 && read_u64(original_thunk + index * thunk_size) == 0) {
                break; // this descriptor's ILT ends before the adjacent IAT slice
            }
            const std::size_t thunk_rva = first_thunk + index * thunk_size;
            const auto bound_va = read_u64(thunk_rva);
            if (bound_va == 0) {
                break; // null terminator thunk
            }
            if (bound_va < size && looks_like_name_record(view, bound_va)) {
                ++audit.covered_count;
            } else {
                audit.residual.push_back({static_cast<std::uint32_t>(thunk_rva), bound_va});
            }
        }
    }
    return audit;
}

std::expected<RepairSummary, RepairError>
repair_dump_impl(const std::vector<std::uint8_t>* snapshot_bytes,
                 const std::filesystem::path* snapshot_path, const std::filesystem::path& dump_dir,
                 const std::filesystem::path& out_dir,
                 const std::vector<std::uint64_t>& oep_candidates)
{
    const std::vector<std::uint8_t>* const snapshot_bytes_ptr = snapshot_bytes;
    const std::filesystem::path* const snapshot_path_ptr = snapshot_path;
    const auto read_range = [&](const std::uint64_t base, const std::uint32_t size) {
        return snapshot_bytes_ptr != nullptr
                   ? engine::detail::read_snapshot_range(*snapshot_bytes_ptr, base, size)
                   : engine::detail::read_snapshot_range(*snapshot_path_ptr, base, size);
    };
    auto module_images = snapshot_bytes != nullptr
                             ? engine::detail::read_module_images(*snapshot_bytes)
                             : engine::detail::read_module_images(*snapshot_path);
    if (!module_images) {
        return std::unexpected(RepairError::kBadSnapshot);
    }
    ExportsMapper mapper;
    for (auto& module : *module_images) {
        mapper.add_module(std::string(module.module.name.data()), module.module.base,
                          module.image.data(), module.image.size());
    }

    const auto manifest_text = read_file(dump_dir / "manifest.txt");
    if (manifest_text.empty()) {
        return std::unexpected(RepairError::kBadDump);
    }
    const auto entries = parse_manifest(manifest_text);
    const auto merged = aggregate_regions(entries);
    if (merged.empty()) {
        return std::unexpected(RepairError::kBadDump);
    }

    std::error_code fs_err;
    std::filesystem::create_directories(out_dir, fs_err);

    RepairSummary summary;
    for (const auto& region : merged) {
        RegionRepairReport entry;
        entry.base = region.base;
        entry.size = region.size;

        // Byte sourcing: clean pages come from the rebuilt snapshot (the
        // capture mapped the whole image, e.g. UPX's header page the stub
        // never rewrites), dirty pages from the dump overlay them.
        std::vector<std::uint8_t> image;
        bool files_ok = true;
        std::uint64_t min_first_dirty = 0;
        auto snapshot_page_bytes = read_range(region.base, static_cast<std::uint32_t>(region.size));
        if (snapshot_page_bytes.has_value()) {
            image = std::move(*snapshot_page_bytes);
            for (const auto& member : entries) {
                if (member.base < region.base || member.base >= region.base + region.size) {
                    continue;
                }
                auto chunk = read_file(dump_dir / (hex16(member.base) + ".bin"));
                if (chunk.size() != member.size) {
                    files_ok = false;
                    break;
                }
                const auto at = static_cast<std::size_t>(member.base - region.base);
                std::memcpy(image.data() + at, chunk.data(), chunk.size());
                if (min_first_dirty == 0 || member.first_dirty_page < min_first_dirty) {
                    min_first_dirty = member.first_dirty_page;
                }
            }
        } else {
            // Region absent from the snapshot: dump-only image (the crafted
            // unit-test case).
            for (const auto& member : entries) {
                if (member.base < region.base || member.base >= region.base + region.size) {
                    continue;
                }
                auto chunk = read_file(dump_dir / (hex16(member.base) + ".bin"));
                if (chunk.size() != member.size) {
                    files_ok = false;
                    break;
                }
                image.insert(image.end(), chunk.begin(), chunk.end());
            }
        }
        if (!files_ok || image.size() != region.size) {
            entry.verdict = RepairVerdict::kFailed;
            entry.detail = "region .bin files missing or size mismatch";
            summary.regions.push_back(entry);
            sheller::log::warning("repair region " + hex16(region.base) +
                                  " verdict=failed detail=" + entry.detail);
            continue;
        }
        entry.actual_bytes = image.size();

        const auto size_of_image = probe_size_of_image(image.data(), image.size());
        if (!size_of_image.has_value() || *size_of_image == 0 || *size_of_image > kMaxImageBytes) {
            entry.verdict = RepairVerdict::kNotImage;
            summary.regions.push_back(entry);
            sheller::log::info("repair region " + hex16(region.base) + " verdict=not-image");
            continue;
        }
        entry.expected_bytes = *size_of_image;
        entry.first_dirty_page = min_first_dirty;
        entry.truncated = *size_of_image > image.size();
        // Prefer the snapshot-backed full image: the dump carries only the
        // dirty pages (UPX's original import directory sits in a clean page
        // beyond the truncated tail), while clean pages are unchanged since
        // the capture. Dirty dump bytes overlay the snapshot prefix.
        if (snapshot_page_bytes.has_value() && *size_of_image <= kMaxImageBytes) {
            auto full = read_range(region.base, *size_of_image);
            if (full.has_value()) {
                const auto copy = std::min<std::size_t>(image.size(), full->size());
                std::memcpy(full->data(), image.data(), copy);
                image = std::move(*full);
                entry.truncated = false;
            }
        }

        // Two normalization passes, both mapper-driven and authoritative:
        // (1) reconstruct_imports finds the packer-resolved payload IAT -
        // runs of absolute runtime VAs the stub wrote over the payload's
        // own thunk arrays, unreachable through the header's import
        // directory because the original descriptors were zeroed - and
        // rebuilds a descriptor array + name records for it, repointing the
        // header's directory; (2) when no such runs exist (a dump whose
        // header-pointed table still carries absolute thunks directly),
        // synthesize_name_imports normalizes that table instead. peconv's
        // uneraser only reuses name strings already present in the image,
        // so it cannot do either; it keeps validating the result.
        static_cast<void>(reconstruct_imports(image, mapper));
        // The synthesis is the authoritative final pass: it walks every
        // descriptor's thunks (including the ones the reconstruction left
        // untouched), classifies each as name-record form / synthesizable /
        // unresolvable, and produces the verdict's audit.
        IatAudit audit = synthesize_name_imports(image, mapper);
        entry.uncovered = audit.uncovered;

        const auto out_path = out_dir / ("repaired_" + hex16(region.base) + ".exe");
        // OEP stamp: the first candidate inside this region becomes the
        // repaired copy's AddressOfEntryPoint (an RVA from the region base).
        for (const auto candidate : oep_candidates) {
            if (candidate >= region.base && candidate < region.base + region.size) {
                const auto oep_rva = static_cast<std::uint32_t>(candidate - region.base);
                if (stamp_entry_point(image.data(), image.size(), oep_rva)) {
                    summary.oep_found = true;
                    summary.oep_va = candidate;
                    summary.oep_rva = oep_rva;
                }
                break;
            }
        }
        // Virtual-layout normalization: the merged image carries the packed
        // file's file-layout section headers (PointerToRawData != RVA) while
        // the bytes are the virtual memory dump - rewrite every section to
        // raw == virtual so the written file is self-consistent for any
        // section-aware consumer (the reconstruction's appended section
        // already uses this convention).
        {
            const auto img_e_lfanew = static_cast<std::size_t>(image[kDosHeaderELfanewOffset]) |
                                      (static_cast<std::size_t>(image[0x3D]) << 8) |
                                      (static_cast<std::size_t>(image[0x3E]) << 16) |
                                      (static_cast<std::size_t>(image[0x3F]) << 24);
            const auto img_nsec = static_cast<std::size_t>(image[img_e_lfanew + 6]) |
                                  (static_cast<std::size_t>(image[img_e_lfanew + 7]) << 8);
            const auto img_optsz = static_cast<std::size_t>(image[img_e_lfanew + 0x14]) |
                                   (static_cast<std::size_t>(image[img_e_lfanew + 0x15]) << 8);
            for (std::size_t i = 0; i < img_nsec; ++i) {
                const std::size_t sh =
                    img_e_lfanew + kOptionalHeaderOffset + img_optsz + i * kPeSectionHeaderSize;
                const auto va =
                    static_cast<std::uint32_t>(image[sh + kSectionHeaderVirtualAddressOffset]) |
                    (static_cast<std::uint32_t>(image[sh + 13]) << 8) |
                    (static_cast<std::uint32_t>(image[sh + 14]) << 16) |
                    (static_cast<std::uint32_t>(image[sh + 15]) << 24);
                const auto vsz =
                    static_cast<std::uint32_t>(image[sh + kSectionHeaderVirtualSizeOffset]) |
                    (static_cast<std::uint32_t>(image[sh + 9]) << 8) |
                    (static_cast<std::uint32_t>(image[sh + 10]) << 16) |
                    (static_cast<std::uint32_t>(image[sh + 11]) << 24);
                const auto raw =
                    std::min<std::uint32_t>((vsz + 0x1FF) & ~static_cast<std::uint32_t>(0x1FF),
                                            static_cast<std::uint32_t>(image.size() - va));
                image[sh + kSectionHeaderSizeOfRawDataOffset] = static_cast<std::uint8_t>(raw);
                image[sh + kSectionHeaderSizeOfRawDataOffset + 1] =
                    static_cast<std::uint8_t>(raw >> 8);
                image[sh + kSectionHeaderSizeOfRawDataOffset + 2] =
                    static_cast<std::uint8_t>(raw >> 16);
                image[sh + kSectionHeaderSizeOfRawDataOffset + 3] =
                    static_cast<std::uint8_t>(raw >> 24);
                image[sh + kSectionHeaderPointerToRawDataOffset] = static_cast<std::uint8_t>(va);
                image[sh + kSectionHeaderPointerToRawDataOffset + 1] =
                    static_cast<std::uint8_t>(va >> 8);
                image[sh + kSectionHeaderPointerToRawDataOffset + 2] =
                    static_cast<std::uint8_t>(va >> 16);
                image[sh + kSectionHeaderPointerToRawDataOffset + 3] =
                    static_cast<std::uint8_t>(va >> 24);
            }
        }
        // The merged image is already the virtual-layout PE with every
        // repair applied (reconstructed imports, OEP stamp), and its header
        // is the authoritative one - writing it directly keeps the header
        // exactly as repaired. peconv::dump_pe would re-derive the header
        // from its own parse and drop the repointed import directory.
        std::ofstream repaired_out(out_path.string(), std::ios::binary | std::ios::trunc);
        const bool dumped = repaired_out.is_open() &&
                            repaired_out.write(reinterpret_cast<const char*>(image.data()),
                                               static_cast<std::streamsize>(image.size()));
        repaired_out.close();
        if (!dumped) {
            entry.verdict = RepairVerdict::kFailed;
            entry.detail = "repaired image write failed";
            summary.regions.push_back(entry);
            sheller::log::warning("repair region " + hex16(region.base) +
                                  " verdict=failed detail=" + entry.detail);
            continue;
        }

        entry.verdict =
            audit.uncovered.empty() ? RepairVerdict::kComplete : RepairVerdict::kPartial;
        // Residual absolute-VA audit over the final repaired bytes: a
        // complete verdict must come back empty (every covered thunk is
        // name-record form); a partial verdict's residuals are exactly the
        // uncovered thunks keeping their bound VAs.
        const auto residual = audit_residual_abs_va(image.data(), image.size());
        entry.residual_abs_va = residual.residual;
        summary.regions.push_back(entry);
        sheller::log::info(
            "repair region " + hex16(region.base) + " size=" + hex16(region.size) +
            " verdict=" + (entry.verdict == RepairVerdict::kComplete ? "complete" : "partial") +
            " covered=" + std::to_string(audit.covered_count) +
            " uncovered=" + std::to_string(audit.uncovered.size()) +
            (entry.truncated ? " truncated expected=" + hex16(*size_of_image) +
                                   " actual=" + hex16(entry.actual_bytes)
                             : "") +
            " residual_abs=" + std::to_string(residual.residual.size()) +
            " residual_covered=" + std::to_string(residual.covered_count));
        for (const auto& thunk : audit.uncovered) {
            sheller::log::debug("repair uncovered rva=" + hex16(thunk.rva) +
                                " va=" + hex16(thunk.va));
        }
    }

    return summary;
}

std::expected<RepairSummary, RepairError> repair_dump(const std::filesystem::path& snapshot,
                                                      const std::filesystem::path& dump_dir,
                                                      const std::filesystem::path& out_dir)
{
    return repair_dump_impl(nullptr, &snapshot, dump_dir, out_dir, {});
}

std::expected<RepairSummary, RepairError>
repair_dump(const std::filesystem::path& snapshot, const std::filesystem::path& dump_dir,
            const std::filesystem::path& out_dir, const std::vector<std::uint64_t>& oep_candidates)
{
    return repair_dump_impl(nullptr, &snapshot, dump_dir, out_dir, oep_candidates);
}

std::expected<RepairSummary, RepairError> repair_dump(const std::vector<std::uint8_t>& snapshot,
                                                      const std::filesystem::path& dump_dir,
                                                      const std::filesystem::path& out_dir)
{
    return repair_dump_impl(&snapshot, nullptr, dump_dir, out_dir, {});
}

std::expected<RepairSummary, RepairError>
repair_dump(const std::vector<std::uint8_t>& snapshot, const std::filesystem::path& dump_dir,
            const std::filesystem::path& out_dir, const std::vector<std::uint64_t>& oep_candidates)
{
    return repair_dump_impl(&snapshot, nullptr, dump_dir, out_dir, oep_candidates);
}

} // namespace sheller::unpack
