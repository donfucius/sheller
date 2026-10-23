// Internal name behind sheller::log::set_sink. The public name is defined only
// by the shared interface library, so the static core carries this one and a
// direct-link consumer reaches the implementation here. The state it installs
// into stays this TU's (log_state.cpp): a binary that linked both this library
// and the shared one would hold two copies of that state and the halves would
// diverge silently.

#ifndef SHELLER_LOG_DETAIL_H
#define SHELLER_LOG_DETAIL_H

#include <sheller/log.h>

namespace sheller::log::detail {

void set_sink_impl(sink callback, level min_level);

} // namespace sheller::log::detail

#endif // SHELLER_LOG_DETAIL_H
