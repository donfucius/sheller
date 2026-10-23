// sheller public version header - the engine's only public header.
// Public headers must not include third-party headers; only the standard library.

#ifndef SHELLER_VERSION_H
#define SHELLER_VERSION_H

#include <sheller/export.h>

#include <string_view>

#define SHELLER_VERSION_MAJOR 0
#define SHELLER_VERSION_MINOR 1
#define SHELLER_VERSION_PATCH 0

namespace sheller {

// Compile-time version facts. The literal and the macros above must stay in sync.
constexpr std::string_view version_string()
{
    return "0.1.0";
}
constexpr int version_major()
{
    return SHELLER_VERSION_MAJOR;
}
constexpr int version_minor()
{
    return SHELLER_VERSION_MINOR;
}
constexpr int version_patch()
{
    return SHELLER_VERSION_PATCH;
}

// Version of the linked unicorn engine, "major.minor" (queried at runtime).
// The returned view is backed by process-lifetime storage and never changes.
SHELLER_API std::string_view unicorn_version_string();

} // namespace sheller

#endif // SHELLER_VERSION_H
