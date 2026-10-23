#include "log.h"

#include <sheller/log.h>

#include <spdlog/spdlog.h>

#include <string_view>

namespace sheller::cli {

namespace {

// The facade's four levels onto spdlog's. Kept as one table so the sink's routing and
// the process-wide filter cannot disagree about what "warn" means.
[[nodiscard]] spdlog::level::level_enum to_spdlog(const sheller::log::level level)
{
    switch (level) {
    case sheller::log::level::kDebug:
        return spdlog::level::debug;
    case sheller::log::level::kInfo:
        return spdlog::level::info;
    case sheller::log::level::kWarning:
        return spdlog::level::warn;
    case sheller::log::level::kError:
        return spdlog::level::err;
    }
    return spdlog::level::warn;
}

} // namespace

std::optional<sheller::log::level> parse_log_level(const std::string_view name)
{
    if (name == "debug") {
        return sheller::log::level::kDebug;
    }
    if (name == "info") {
        return sheller::log::level::kInfo;
    }
    if (name == "warn") {
        return sheller::log::level::kWarning;
    }
    if (name == "error") {
        return sheller::log::level::kError;
    }
    return std::nullopt;
}

void install_log_sink(const sheller::log::level min_level)
{
    // The two thresholds travel together: an spdlog filter left at warn while the facade
    // is set to debug would take the records from the library and drop them in the
    // renderer, which is the half-silence that makes a diagnostic flag impossible to
    // reason about.
    spdlog::set_level(to_spdlog(min_level));
    sheller::log::set_sink(
        [](const sheller::log::level sev, std::string_view message) {
            switch (sev) {
            case sheller::log::level::kDebug:
                spdlog::debug("{}", message);
                break;
            case sheller::log::level::kInfo:
                spdlog::info("{}", message);
                break;
            case sheller::log::level::kWarning:
                spdlog::warn("{}", message);
                break;
            case sheller::log::level::kError:
                spdlog::error("{}", message);
                break;
            }
        },
        min_level);
}

} // namespace sheller::cli
