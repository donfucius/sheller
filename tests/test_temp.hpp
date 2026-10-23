// Per-process unique temp paths for tests: concurrent ctest jobs (or a
// stale run's leftovers) must not collide on fixed names. Usage:
//   sheller_test::temp_path("sheller_capture_cli_test") -> <tmp>/<name>_<pid>
// Create directories at the returned path as needed (existing
// create_directories calls keep working unchanged).
#pragma once

#include <filesystem>
#include <string>

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif

namespace sheller_test {

inline std::filesystem::path temp_path(const std::string& name)
{
#ifdef _WIN32
    const auto pid = _getpid();
#else
    const auto pid = getpid();
#endif
    return std::filesystem::temp_directory_path() / (name + "_" + std::to_string(pid));
}

} // namespace sheller_test
