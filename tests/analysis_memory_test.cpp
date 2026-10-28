// The static facade must borrow snapshot bytes and stream snapshot paths,
// even when no behavior report is requested. Count only allocations as big
// as the padded input; Unicorn's per-region copies remain much smaller.
#include "snapshot_fixture.h"
#include "test_temp.hpp"
#include "wiring.h"
#include <cstdlib>
#include <fstream>
#include <gtest/gtest.h>
#include <new>

namespace {
constexpr std::size_t kInputSize = 16 * 1024 * 1024;
thread_local bool watch_allocations = false;
thread_local std::size_t large_allocations = 0;
struct AllocationWatch {
    AllocationWatch()
    {
        large_allocations = 0;
        watch_allocations = true;
    }
    ~AllocationWatch()
    {
        watch_allocations = false;
    }
};
} // namespace

// The malloc-backed global operators are regular-build instrumentation. Under
// ASAN the sanitizer interposes new/delete itself and GCC rejects the
// user-defined pair as mismatched, so they stay out of the sanitizer build
// (the allocation-count expectations there degrade to trivially true).
#if !defined(__SANITIZE_ADDRESS__)
void* operator new(std::size_t size)
{
    if (watch_allocations && size >= kInputSize) {
        ++large_allocations;
    }
    if (void* memory = std::malloc(size == 0 ? 1 : size)) {
        return memory;
    }
    throw std::bad_alloc{};
}
void operator delete(void* memory) noexcept
{
    std::free(memory);
}
void operator delete(void* memory, std::size_t) noexcept
{
    std::free(memory);
}
#endif

TEST(AnalysisMemory, BytesWithoutReportDoNotCopyEntireContainer)
{
    auto input = sheller_test::terminate_snapshot();
    // v1 readers intentionally ignore the trailing bytes. The large tail
    // makes an accidental whole-container copy observable without a large
    // guest allocation or a platform-specific memory measurement.
    input.resize(kInputSize, 0);
    sheller::AnalysisOptions options;
    options.behavior_report = false;
    AllocationWatch watch;
    const auto result = sheller::api::detail::analyze_bytes_impl(input, options);
    ASSERT_TRUE(result.has_value());
    ASSERT_TRUE(result->run_stats.has_value());
    EXPECT_TRUE(result->run_stats->terminated);
    EXPECT_EQ(large_allocations, 0U);
}

TEST(AnalysisMemory, FileWithoutReportStaysStreaming)
{
    auto input = sheller_test::terminate_snapshot();
    input.resize(kInputSize, 0);
    const auto path = sheller_test::temp_path("sheller_streaming_container.snap");
    {
        std::ofstream out(path, std::ios::binary);
        out.write(reinterpret_cast<const char*>(input.data()), input.size());
        ASSERT_TRUE(out.good());
    }
    sheller::AnalysisOptions options;
    options.behavior_report = false;
    options.input_kind = sheller::AnalysisInputKind::kSnapshot;
    {
        AllocationWatch watch;
        const auto result = sheller::api::detail::analyze_path_impl(path, options);
        ASSERT_TRUE(result.has_value());
        ASSERT_TRUE(result->run_stats.has_value());
        EXPECT_TRUE(result->run_stats->terminated);
        EXPECT_EQ(large_allocations, 0U);
    }
    std::error_code ec;
    std::filesystem::remove(path, ec);
}
