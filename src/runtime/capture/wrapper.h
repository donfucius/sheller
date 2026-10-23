// Shellcode blob wrapping: a bare blob is embedded into a minimal wrapper PE - one
// code section, entry pointing at the section start - so shellcode rides the
// standard capture route. The wrapper is pure byte construction: no runtime
// linking, no interpretation of the blob, sizes bounded. The generated PE
// must load in a real Windows process (the capture path spawns it), which
// the e2e exercises end to end.

#ifndef SHELLER_CAPTURE_WRAPPER_H
#define SHELLER_CAPTURE_WRAPPER_H

#include <sheller/capture.h>

#include <cstdint>
#include <expected>
#include <span>
#include <string_view>
#include <vector>

namespace sheller::capture {

enum class WrapArch { kX64, kX86 };

enum class WrapError {
    kNone = 0,
    kEmptyBlob,
    kTooLarge,
    // The temp directory itself could not be resolved. Its own enumerator, not
    // a folded "capture failed": the wrapper's other failures say the blob is
    // unusable, this one says the host has nowhere to put it.
    kTempDirUnavailable,
};

std::string_view wrap_error_message(WrapError error);

// Which of the wrapper's failures is whose fault, expressed in the status the
// capture route reports. An unusable blob is an input problem - the sample is not a
// runnable x64 image, which is what kNotX64Pe says. A host with nowhere to put the
// wrapper PE is the capture route failing, and reporting that as "not a PE" would
// tell the caller to go fix a file that was never the problem. kNone has no status
// of its own (a caller checks the expected value first); it maps to kNotX64Pe so the
// table has no unhandled enumerator rather than because "ok" is a failure.
Status wrap_status(WrapError error);

// The wrapper takes a fresh process, so the default image base is reliably
// free; ASLR is left off (no relocation directory) for a deterministic load.
// Blob cap: msfvenom-class payloads sit far below it; the bound keeps the
// generated image two-dimensional-simple.
inline constexpr std::size_t kMaxBlobBytes = 1024 * 1024;

// A leading MZ marks a PE input; anything else is treated as a bare blob.
bool looks_like_pe(std::span<const std::uint8_t> bytes);

// Builds the wrapper PE: headers + one RX section whose first byte is the
// entry and whose content is the blob verbatim.
std::expected<std::vector<std::uint8_t>, WrapError> wrap_blob(WrapArch arch,
                                                              std::span<const std::uint8_t> blob);

} // namespace sheller::capture

#endif // SHELLER_CAPTURE_WRAPPER_H
