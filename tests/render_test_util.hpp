// Migration adapters for the render-layer move: the renderers live in the CLI
// render library and consume public artifacts - TLV bytes plus the public name
// table. These helpers keep the suite bodies in their ledger shape while
// routing through the shipped entry points: the TLV bytes are built with the
// public codec exactly as the facade does, and the name table is the public
// one (the library and the renders share a single table type).

#pragma once

#include <sheller/analysis.h>
#include <sheller/events.h>

#include "../src/cli/render.h"
#include "event_ledger.h"
#include "report_events.h"

#include <string>
#include <vector>

inline std::vector<std::uint8_t> build_tlv(const sheller::behavior::EventLedger& ledger)
{
    std::vector<std::uint8_t> tlv;
    std::vector<std::uint8_t> buffer;
    for (std::size_t i = 0; i < ledger.size(); ++i) {
        const auto entry = ledger.entry(i);
        buffer.resize(sheller::kEventHeaderSize + sheller::kEventPreambleSize +
                      entry.type_fields.size());
        const auto written =
            sheller::encode_event(buffer, entry.type, entry.preamble, entry.type_fields);
        if (!written.has_value()) {
            break;
        }
        tlv.insert(tlv.end(), buffer.begin(),
                   buffer.begin() + static_cast<std::ptrdiff_t>(*written));
    }
    return tlv;
}

// The full-level events section over a ledger: the TLV window rides the
// public artifact and the semantic tier stays empty, so the merged stream is
// what the shared per-entry builder renders for window entries - the shape
// the standalone timeline render used to return.
inline std::string render_full_events(const sheller::behavior::EventLedger& ledger,
                                      const sheller::TimelineNameTable& names)
{
    sheller::AnalysisArtifacts artifacts;
    artifacts.timeline_tlv = build_tlv(ledger);
    artifacts.timeline_names = names;
    return sheller::cli::render_events_section(artifacts, sheller::cli::EventLevel::Full);
}

// The stub side table through the report's own key: what these suites pin is
// the ledger's (module, name) map order, and module_name stays empty because
// the ledger rows carry no resolved names - the raw-index spelling the report
// falls back to.
inline std::string render_stub_calls_section(const sheller::behavior::EventLedger& ledger)
{
    sheller::AnalysisArtifacts artifacts;
    for (const auto& [key, count] : ledger.stub_counts()) {
        artifacts.stub_calls.push_back(sheller::StubCall{key.first, {}, key.second, count});
    }
    return sheller::cli::render_events_section(artifacts);
}

// Counts-only artifact lift for e2e runs wired through the raw tally (no
// semantic collector): the events-section render still emits the exact
// counts header, with an empty detail list.
inline sheller::AnalysisArtifacts artifacts_for(const sheller::behavior::EventTally& tally)
{
    sheller::AnalysisArtifacts artifacts;
    for (std::size_t i = 0; i < artifacts.event_counts.size(); ++i) {
        artifacts.event_counts[i] = tally.count_of(static_cast<sheller::EventTypeId>(i));
    }
    return artifacts;
}
