// Repair pipeline internals: manifest parsing,
// region aggregation, PE probing and IAT auditing as pure functions over
// bytes for the unit tests; repair_dump orchestrates them into the
// three-state report. Windows only.

#ifndef SHELLER_UNPACK_REPAIR_H
#define SHELLER_UNPACK_REPAIR_H

#include "exports_mapper.h"

#include <sheller/unpack.h> // UncoveredThunk

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace sheller::unpack {

// One manifest line: base size type protection first-dirty-page, fixed-width
// hex (dump format).
struct ManifestEntry {
    std::uint64_t base{};
    std::uint64_t size{};
    std::uint32_t type{};
    std::uint32_t protection{};
    std::uint64_t first_dirty_page{};
};

// Contiguous same-type run of manifest regions: one repair candidate.
struct AggregatedRegion {
    std::uint64_t base{};
    std::uint64_t size{};
    std::uint32_t type{};
};

// Parses the manifest text; malformed lines are skipped (the dump writer is
// the only producer, so this is corruption defence, not format tolerance).
std::vector<ManifestEntry> parse_manifest(const std::string& text);

// Sorts by base and merges address-adjacent same-type regions so an image
// header sits at the aggregated region's start.
std::vector<AggregatedRegion> aggregate_regions(const std::vector<ManifestEntry>& entries);

// SizeOfImage from the PE header at the buffer start; nullopt without a
// valid DOS + PE header pair.
std::optional<std::uint32_t> probe_size_of_image(const std::uint8_t* image, std::size_t size);

// Walks the import directory in the (pre-rewrite) dump image and resolves
// every bound thunk against the mapper; zero thunks terminate each
// descriptor. Unresolved entries come back as rva/va pairs for the report.
struct IatAudit {
    std::vector<UncoveredThunk> uncovered;
    std::uint64_t covered_count{};
};
IatAudit audit_imports(const std::uint8_t* image, std::size_t size, const ExportsMapper& mapper);

// Residual absolute-VA audit over a REPAIRED copy: after the synthesis every
// thunk in the covered import tables must be name-record form (in-image
// hint/name record) - a thunk still holding any other non-zero value keeps
// a capture-time bound VA and is reported. Pure bytes, no mapper needed:
// the name-record shape is the only acceptable repaired form.
struct ResidualAudit {
    std::vector<UncoveredThunk> residual; // non-name-record thunks found
    std::uint64_t covered_count{};
};
ResidualAudit audit_residual_abs_va(const std::uint8_t* image, std::size_t size);

// Mapper-driven import normalization, in place on the merged dump image.
// Thunks carrying absolute runtime VAs (the packer resolved them through
// its own table) are rewritten to proper name imports: a hint/name record
// is synthesized in the image's zero tail and the thunk points at it.
// peconv's uneraser only reuses name strings already present in the image,
// which leaves every thunk whose function name the dump doesn't carry as
// an unportable absolute address while the mapper-based audit reports
// full coverage - the two must not disagree, so this runs before
// peconv::fix_imports and produces the authoritative audit.
IatAudit synthesize_name_imports(std::vector<std::uint8_t>& image, const ExportsMapper& mapper);

// Scylla-style IAT reconstruction for packer-resolved payload imports.
// Scans the dump for runs of thunks holding absolute runtime VAs the mapper
// resolves (the unpacking stub writes GetProcAddress results over the
// payload's own thunk arrays and zeroes the original descriptors, so the
// header's import directory cannot reach them), groups each run by the
// module that actually exports the resolved function, rebuilds a descriptor
// array + name records in the image's zero tail, rewrites the thunks to
// point at the records, and repoints the header's import directory at the
// rebuilt table. The audit counts the thunks the reconstruction covers.
IatAudit reconstruct_imports(std::vector<std::uint8_t>& image, const ExportsMapper& mapper);

} // namespace sheller::unpack

#endif // SHELLER_UNPACK_REPAIR_H
