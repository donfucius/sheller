// DLL-input admission (Windows): the single-sample dependency contract.
// A DLL sample may depend on nothing but verified system modules - the
// runner preloads them through its own import table so the real loader
// initializes them into the captured world. "Verified" never trusts a file
// name: every dependency resolves through the system32-only search with a
// data-file mapping (no execution) or, for API-set virtual names, a real
// load whose module path is checked back against the system directory.
// Anything private, path-shaped, missing or unresolvable is rejected by
// name before any process is created.

#ifndef SHELLER_CAPTURE_DLL_ADMISSION_H
#define SHELLER_CAPTURE_DLL_ADMISSION_H

#include "wrapper.h"

#include <expected>
#include <string>
#include <vector>

namespace sheller::capture {

// Checks the sample DLL's static imports and produces the runner plan:
// the kernel32 base pair plus one importable symbol per verified system
// dependency (the exact referenced name or ordinal). The dependency
// closure is verified too - a system module whose own chain leaves the
// system set fails admission by name.
std::expected<RunnerPlan, std::string>
admit_dll_sample(const std::vector<std::uint8_t>& sample_bytes, const std::string& arrival_name);

} // namespace sheller::capture

#endif // SHELLER_CAPTURE_DLL_ADMISSION_H
