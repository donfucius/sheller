// CLI-side logging: installs a spdlog-backed sink for the library log facade, at the
// threshold the operator asked for.

#ifndef SHELLER_CLI_LOG_H
#define SHELLER_CLI_LOG_H

#include <sheller/log.h>

#include <optional>
#include <string_view>

namespace sheller::cli {

// Routes sheller::log records into spdlog (stdout) and sets the facade's threshold to
// min_level. The CLI is a host like any other: with no sink installed the library says
// nothing anywhere, and at the default threshold it says only what an operator needs to
// see without asking - so the traces stay below it until this is called with a lower
// level.
void install_log_sink(sheller::log::level min_level);

// The names --log-level accepts. Unrecognized spellings come back as nullopt; the option
// itself is checked against the same set, so a typo is a usage error rather than a
// silently ignored flag.
[[nodiscard]] std::optional<sheller::log::level> parse_log_level(std::string_view name);

} // namespace sheller::cli

#endif // SHELLER_CLI_LOG_H
