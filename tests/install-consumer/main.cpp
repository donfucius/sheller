// Minimal consumer of an installed sheller: the end-to-end judge for the
// delivery surface (specs/delivery-surface, "从安装树构建的最小消费者"). It
// reaches nothing but the package - no source tree, no vcpkg, no copied files,
// no hand-written include path - and it exercises the boundary in both
// directions: a std::string_view out of unicorn_version_string(), and both
// analyze() entries, the path form and the in-memory form, whose std::expected
// returns carry std::vector, std::string, std::filesystem::path and
// std::array across it.
//
// The consumer-side configuration checks in include/sheller/export.h are what
// make a Debug consumer of a Release installation fail to compile here, so
// reaching that header is part of the point of this file.
#include <sheller/analysis.h>
#include <sheller/version.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

int report(const char* label, const sheller::AnalysisArtifacts& artifacts)
{
    std::uint64_t total_events = 0;
    for (const std::uint64_t count : artifacts.event_counts) {
        total_events += count;
    }
    std::printf("%s: instrumented=%d semantic_events=%zu oep_candidates=%zu events=%llu\n", label,
                artifacts.instrumented ? 1 : 0, artifacts.semantic_events.size(),
                artifacts.oep_candidates.size(), static_cast<unsigned long long>(total_events));
    return artifacts.instrumented ? 0 : 1;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <snapshot>\n", argv[0]);
        return 2;
    }
    const std::filesystem::path input{argv[1]};

    const std::string_view unicorn = sheller::unicorn_version_string();
    std::printf("sheller %s (unicorn %.*s)\n", std::string(sheller::version_string()).c_str(),
                static_cast<int>(unicorn.size()), unicorn.data());

    sheller::AnalysisOptions options{};

    const auto by_path = sheller::analyze(input, options);
    if (!by_path.has_value()) {
        std::fprintf(stderr, "analyze(path) failed: %s\n", by_path.error().message.c_str());
        return 1;
    }
    const int path_rc = report("analyze(path)", by_path.value());

    std::vector<std::uint8_t> bytes{};
    {
        std::ifstream stream(input, std::ios::binary);
        if (!stream) {
            std::fprintf(stderr, "cannot read %s\n", argv[1]);
            return 2;
        }
        bytes.assign(std::istreambuf_iterator<char>(stream), std::istreambuf_iterator<char>{});
    }
    const auto by_bytes = sheller::analyze(bytes, options);
    if (!by_bytes.has_value()) {
        std::fprintf(stderr, "analyze(bytes) failed: %s\n", by_bytes.error().message.c_str());
        return 1;
    }
    const int bytes_rc = report("analyze(bytes)", by_bytes.value());

    return (path_rc == 0 && bytes_rc == 0) ? 0 : 1;
}
