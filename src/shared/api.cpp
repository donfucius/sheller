// The shared interface library: the only translation unit that defines the
// product names. Each entry below is a forwarder - the implementation stays in
// the static core under an internal name (src/api/wiring.h and the three
// src/*/*_detail.h headers), so a symbol under a public name exists exactly
// once, in this library. That is what makes "the public headers declare the
// product interface" a linker fact: the static core carries no definition to
// link against under these names.
//
// Invariant: one binary walks one link route.
//   * A consumer of this library (the sheller CLI) links sheller_shared and
//     nothing from the static core.
//   * A consumer of the static core (the direct-link test suites) calls the
//     internal names and never a product name.
// Linking both into one process does not fail to build - it splits the process
// state in two. log_state.cpp's sink is a TU-static, so an exe that sets a sink
// while a DLL-embedded engine writes to its own would show the host an empty
// log and no error. Unicorn, the behavior ledger and the snapshot reader are
// all in the same position. Hence the two lists above, and the
// shared_api_test that keeps the DLL route honest.
//
// Include paths: this layer consumes the core's internal headers on purpose -
// forwarding to the implementation is its job. The src/cli rule that forbids a
// relative-parent include (public headers only) deliberately does not apply
// here; wiring.h and the detail headers are reached through the PRIVATE include
// directories src/shared/CMakeLists.txt declares, not by reaching over the
// tree.

#include "capture_detail.h"
#include "engine_detail.h"
#include "guard.h"
#include "log_detail.h"
#include "wiring.h"

#include <sheller/analysis.h>
#include <sheller/capture.h>
#include <sheller/export.h>
#include <sheller/log.h>
#include <sheller/version.h>

#include <cstdint>
#include <expected>
#include <filesystem>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace sheller {
namespace {

// The one shape a library-internal failure takes on the analysis entries: the
// run class, because the entries have no other bucket for "the library itself
// could not finish". Built by assignment so the untouched members say what they
// are rather than being silently defaulted.
[[nodiscard]] AnalysisFailure internal_run_failure(std::string message)
{
    auto failure = AnalysisFailure{};
    failure.kind = AnalysisFailure::Kind::kRun;
    failure.message = std::move(message);
    return failure;
}

} // namespace

// Each entry is the forwarder plus the containment this library promises: no
// C++ exception crosses into the host frame, and the shape that comes back
// instead is this entry's own (see src/shared/guard.h for why the catch is
// lexical rather than a noexcept marker). The mapping strategies below are the
// whole of the "what does the host see" decision for a library-internal failure
// - a run-class failure carrying the internal-error message for the analysis
// entries, a capture-class status for the snapshot producer, the state left
// exactly as it was for the log sink installer, and an empty view for the
// version string (a magic static whose initialization throws stays
// uninitialized, so the next call tries again and an empty view is not a
// one-way downgrade).
SHELLER_API std::expected<AnalysisArtifacts, AnalysisFailure>
analyze(const std::filesystem::path& input, const AnalysisOptions& options)
{
    return shared::detail::guard([&] { return api::detail::analyze_path_impl(input, options); },
                                 [](std::string message) {
                                     return std::unexpected(
                                         internal_run_failure(std::move(message)));
                                 });
}

SHELLER_API std::expected<AnalysisArtifacts, AnalysisFailure>
analyze(const std::vector<std::uint8_t>& input, const AnalysisOptions& options)
{
    return shared::detail::guard([&] { return api::detail::analyze_bytes_impl(input, options); },
                                 [](std::string message) {
                                     return std::unexpected(
                                         internal_run_failure(std::move(message)));
                                 });
}

SHELLER_API UnpackOutcome unpack_sample(const std::filesystem::path& sample,
                                        const UnpackOptions& options)
{
    return shared::detail::guard([&] { return api::detail::unpack_sample_impl(sample, options); },
                                 [](std::string message) {
                                     auto outcome = UnpackOutcome{};
                                     outcome.failure = internal_run_failure(std::move(message));
                                     return outcome;
                                 });
}

SHELLER_API std::string_view unicorn_version_string()
{
    // The view has no failure carrier, so containment reads as empty - "ask
    // again", which is meaningful here for the reason spelled out above.
    return shared::detail::guard([] { return engine::detail::unicorn_version_impl(); },
                                 [](std::string) -> std::string_view { return {}; });
}

} // namespace sheller

namespace sheller::capture {

SHELLER_API Result run(const Options& options)
{
    return shared::detail::guard([&] { return detail::run_impl(options); },
                                 [](std::string message) {
                                     return Result{.status = Status::kCaptureFailed,
                                                   .detail = std::move(message)};
                                 });
}

} // namespace sheller::capture

namespace sheller::log {

SHELLER_API void set_sink(sink callback, const level min_level)
{
    static_cast<void>(
        shared::detail::guard([&] { detail::set_sink_impl(std::move(callback), min_level); },
                              [](std::string message) {
                                  // Nothing to hand back and nothing to undo: the only operation in
                                  // set_sink_impl that can throw is the scoped_lock acquisition,
                                  // and that happens before any write to the state, while the
                                  // assignment itself is a noexcept std::function move. So "caught
                                  // implies the sink and threshold are exactly what they were" is
                                  // provable, not assumed - the message is rendered and dropped
                                  // with it.
                                  static_cast<void>(message);
                              }));
}

} // namespace sheller::log
