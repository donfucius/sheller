// Non-Windows stub: the snapshot route needs the real Windows loader, so
// other hosts get a clear refusal instead of a link error.

#include "capture_detail.h"

#include <sheller/capture.h>

namespace sheller::capture {
namespace detail {

// The refusal side of the link face: the same internal name capture.cpp
// defines on a Windows host (the public sheller::capture::run is defined once,
// in src/shared/api.cpp, and forwards here - both platform shapes have to
// carry the internal name or the shared library would define the public one
// twice on non-Windows hosts).
Result run_impl(const Options&)
{
    return {Status::kUnsupportedPlatform,
            "the snapshot capture route is only supported on Windows hosts"};
}

} // namespace detail

bool capture_available()
{
    return false;
}

} // namespace sheller::capture
