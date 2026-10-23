// Internal name behind sheller::capture::run. The public name is defined only
// by the shared interface library, so the static core carries this one and a
// direct-link consumer reaches the implementation here. Both platform shapes
// declare it: capture.cpp (Windows) and capture_stub.cpp (every other host)
// define it, so the link face is the same on either side.

#ifndef SHELLER_CAPTURE_DETAIL_H
#define SHELLER_CAPTURE_DETAIL_H

#include <sheller/capture.h>

namespace sheller::capture::detail {

Result run_impl(const Options& options);

} // namespace sheller::capture::detail

#endif // SHELLER_CAPTURE_DETAIL_H
