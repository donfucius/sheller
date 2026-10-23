// CLI render layer: deterministic JSON formatting over the analysis
// facade's public artifact types. The library resolves names and facts;
// this layer only formats - same artifact in, byte-identical JSON out (fixed
// key order, hex addresses, no wall clock). Inputs are the public artifact
// types and the public name tables only: the CLI module never touches an
// internal header.

#ifndef SHELLER_CLI_RENDER_H
#define SHELLER_CLI_RENDER_H

#include <sheller/analysis.h>

#include <span>
#include <string>
#include <vector>

namespace sheller::cli {

// Granularity of the report's event detail: Counts is the counts/stub table
// alone (no detail, no ledger), Semantic the default column alone (no
// ledger), Full the merged unified stream over the default column and the
// ledger's retained window.
enum class EventLevel {
    Counts,
    Semantic,
    Full,
};

// The report's "events" value, four keys always: "counts", "detail",
// "stub_calls" ({} when empty) and "loss" (null pair at semantic level, the
// ledger counters at full level).
//
// Detail is one seq-ordered list of events. The counts level emits no
// entries; the default column (semantic seven, mem-read/mem-write and the
// low-frequency judgments) comes from the semantic records; full level also
// inserts the ledger window's window-side entries (block-exec, sample-code,
// smc-execute) by whole-run seq. Every entry is {type,seq,<head/payload
// fields>}; seq is always the whole-run event ordinal. At semantic level,
// entries sharing the primary key (all rendered fields apart from seq and the
// type's secondary fields) merge into one line with the first secondary
// value, `<field>_last` when it varied, `count` and the first 8 occurrence
// `seqs`; kusd-access treats aux as secondary. Full level stays one entry per
// event. Entries render one per line - an empty detail stays "[]" - and the
// rest of the object remains single-line.
std::string render_events_section(const AnalysisArtifacts& artifacts,
                                  EventLevel level = EventLevel::Semantic);

// Whether the TLV walk stops before the end of the window (a malformed tail):
// a full-level render then carries fewer entries than the bytes on hand could
// hold. The CLI prints a warning off this so a truncated stream stays visible
// outside the file.
bool tlv_window_has_malformed_tail(std::span<const std::uint8_t> tlv);

} // namespace sheller::cli

#endif // SHELLER_CLI_RENDER_H
