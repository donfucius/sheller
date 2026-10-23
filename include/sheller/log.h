// Minimal logging facade for the embeddable library.
// The event ledger records guest facts; this log records host-side diagnostics -
// the two must never be mixed, and log output never affects guest-visible behavior.
// Default state is silent: an embeddable library must not write anywhere on its own.
// The host installs a sink (cli/ wires one to spdlog).
//
// Declaration-only surface: the state struct and the single instance live in
// the engine (log_state.cpp), so the mutex+callback layout never becomes part
// of this header's contract for embedders and every module shares one
// process-global state.

#ifndef SHELLER_LOG_H
#define SHELLER_LOG_H

#include <sheller/export.h>

#include <functional>
#include <string_view>

namespace sheller::log {

enum class level : int { kDebug = 0, kInfo, kWarning, kError };

using sink = std::function<void(level, std::string_view)>;

// Installs the process-wide sink and the minimum level a record must meet to
// reach it, under one lock. Pass an empty sink to go silent.
SHELLER_API void set_sink(sink callback, level min_level);

// No-op unless a sink is installed and sev meets the level threshold.
void write(level sev, std::string_view message);

// Cheap pre-check for a caller whose message is expensive to build: true when a
// sink is installed and sev meets its threshold, i.e. when write(sev, ...) would
// actually deliver. A hint, not a reservation - write() takes the same lock and
// re-checks, so a concurrent set_sink can only cost a wasted format or drop the
// record; it can never deliver into a sink that was already replaced.
[[nodiscard]] bool would_log(level sev);

void debug(std::string_view message);
void info(std::string_view message);
void warning(std::string_view message);
void error(std::string_view message);

} // namespace sheller::log

#endif // SHELLER_LOG_H
