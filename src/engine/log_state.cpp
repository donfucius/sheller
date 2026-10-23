// The log facade's state: the one deliberate process-global, exempt from the
// no-globals rule that guards deterministic guest-visible state. The struct
// definition and the single instance live here - not in the public header -
// so the mutex+callback layout stays out of the embedder-facing surface and
// every module links against one shared state.

#include "log_detail.h"

#include <sheller/log.h>

#include <mutex>
#include <utility>

namespace sheller::log {
namespace detail {
namespace {

// Internal linkage: the state and its accessor are this TU's private
// plumbing - no other module may reach around the public surface.
struct log_state {
    std::mutex mutex;
    sink callback;
    level min_level = level::kWarning;
};

log_state& state()
{
    static log_state instance;
    return instance;
}

} // namespace

// The sink installer, under its internal name: the public sheller::log::set_sink
// is defined by the shared interface library and forwards here, so this
// library carries no symbol under the product name.
void set_sink_impl(sink callback, const level min_level)
{
    auto& instance = state();
    const std::scoped_lock lock(instance.mutex);
    instance.callback = std::move(callback);
    instance.min_level = min_level;
}

} // namespace detail

void write(const level sev, const std::string_view message)
{
    auto& instance = detail::state();
    const std::scoped_lock lock(instance.mutex);
    if (!instance.callback || static_cast<int>(sev) < static_cast<int>(instance.min_level)) {
        return;
    }
    // The callback is host code, and the contract says it must not throw
    // (include/sheller/export.h). When it does, the record is dropped: the sink
    // has already been handed the message, so anything the library could say
    // about the throw would reach the same broken callback, and a diagnostic
    // channel must not be able to end the host's process.
    //
    // Dropped, not counted and not echoed to stderr: "the library writes no host
    // standard stream" is a rule with a gate on it
    // (tests/engine_stdstream_gate.cmake), and a fallback print is exactly the
    // kind of exception that rule exists to catch. The contrast inside this tree
    // is the host event observer, which the facade already guards
    // (src/api/wiring.cpp:342) because it runs on the engine's hook path - same
    // reasoning, different channel.
    //
    // This is also the one engine translation unit allowed to catch, and the
    // no-throw gate's allowlist names it for that reason
    // (tests/engine_nothrow_allowlist.txt).
    try {
        instance.callback(sev, message);
    } catch (...) {
        // Deliberately empty: dropping the record is the decision, above.
    }
}

bool would_log(const level sev)
{
    auto& instance = detail::state();
    const std::scoped_lock lock(instance.mutex);
    return static_cast<bool>(instance.callback) &&
           static_cast<int>(sev) >= static_cast<int>(instance.min_level);
}

void debug(const std::string_view message)
{
    write(level::kDebug, message);
}
void info(const std::string_view message)
{
    write(level::kInfo, message);
}
void warning(const std::string_view message)
{
    write(level::kWarning, message);
}
void error(const std::string_view message)
{
    write(level::kError, message);
}

} // namespace sheller::log
