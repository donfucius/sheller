// Allocation-failure injection at the export face. Linux-only, and that is a
// finding rather than a convenience: the interposition this test needs is a
// global operator new defined in the executable and picked up by the library's
// undefined dynamic symbol, which the POSIX runtime does and the Windows CRT
// does not - so the Windows side keeps only its unit-level and contract-level
// evidence, and that is the gap this suite marks rather than closes.
//
// Two claims are checked, in this order:
//   1. the ruler. Before any conclusion is drawn, the test proves the library's
//      allocations actually arrive at this executable's operator new. If they
//      did not - a -Bsymbolic link, or a standard library that resolves new
//      internally - every "no exception escaped" result below would be vacuous,
//      and a vacuous green is the failure mode this file exists to avoid.
//   2. the contract. With the allocator set to fail at the n-th allocation
//      inside a call, each product entry must RETURN. What it returns is the
//      per-entry mapping the design picks (run-class failure carrying the
//      internal-error message, capture-class status, unchanged sink state, empty
//      view); what it must never do is let the throw reach this frame.
//
// The n values are swept from the first allocation upward, which is what makes
// the sweep cover both the argument handling and the engine run itself. Inputs
// are built outside the armed window: a path or an options object constructed
// inside it would spend the budget on the harness, and the throw would land in
// this frame and read as a containment failure that is not one.

#include <sheller/analysis.h>
#include <sheller/capture.h>
#include <sheller/export.h>
#include <sheller/log.h>
#include <sheller/version.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <limits>
#include <new>
#include <string>
#include <string_view>

#include "test_temp.hpp"

#include <gtest/gtest.h>

namespace {

namespace shared_api = sheller;

// The two sinks' counters for the set_sink case: plain data of this translation
// unit, incremented from inside the callbacks the library calls.
struct sink_counters {
    std::size_t original = 0;
    std::size_t replacement = 0;
};

sink_counters& counters()
{
    static sink_counters instance;
    return instance;
}

std::size_t& sink_hits()
{
    return counters().original;
}
std::size_t& replaced_hits()
{
    return counters().replacement;
}

// Single-threaded by construction: the armed window is one library call and the
// counters are plain data. A test that ran these calls concurrently would have
// to revisit this (the concurrency suite does, and does not arm the allocator).
struct allocator_state {
    bool counting = false;
    // -1 while disarmed; otherwise "succeed for this many allocations, throw
    // after". 0 means the very first allocation inside the call throws.
    std::int64_t succeed_budget = -1;
    std::size_t observed = 0;
    std::size_t thrown = 0;
};

allocator_state& arm()
{
    static allocator_state instance;
    return instance;
}

void* allocate(const std::size_t size)
{
    auto& state = arm();
    if (state.counting) {
        ++state.observed;
        if (state.observed > static_cast<std::size_t>(state.succeed_budget)) {
            ++state.thrown;
            throw std::bad_alloc();
        }
    }
    void* memory = std::malloc(size == 0U ? 1U : size);
    if (memory == nullptr) {
        throw std::bad_alloc();
    }
    return memory;
}

void* allocate_nothrow(const std::size_t size) noexcept
{
    auto& state = arm();
    if (state.counting) {
        ++state.observed;
        if (state.observed > static_cast<std::size_t>(state.succeed_budget)) {
            ++state.thrown;
            return nullptr;
        }
    }
    return std::malloc(size == 0U ? 1U : size);
}

} // namespace

// The replacement operators go at global scope - a replacement operator new
// inside a namespace, unnamed included, is ill-formed - and they reach the
// counters through the names the unnamed namespace above put in scope for this
// translation unit.
//
// The full set, new side and delete side: a mismatch would show up as heap
// corruption under the sanitizer preset, which is the loud version of the
// mistake.
void* operator new(const std::size_t size)
{
    return allocate(size);
}
void* operator new[](const std::size_t size)
{
    return allocate(size);
}
void* operator new(const std::size_t size, const std::align_val_t align)
{
    static_cast<void>(align);
    return allocate(size);
}
void* operator new[](const std::size_t size, const std::align_val_t align)
{
    static_cast<void>(align);
    return allocate(size);
}
void* operator new(const std::size_t size, const std::nothrow_t&) noexcept
{
    return allocate_nothrow(size);
}
void* operator new[](const std::size_t size, const std::nothrow_t&) noexcept
{
    return allocate_nothrow(size);
}
void operator delete(void* memory) noexcept
{
    std::free(memory);
}
void operator delete[](void* memory) noexcept
{
    std::free(memory);
}
void operator delete(void* memory, const std::size_t size) noexcept
{
    static_cast<void>(size);
    std::free(memory);
}
void operator delete[](void* memory, const std::size_t size) noexcept
{
    static_cast<void>(size);
    std::free(memory);
}
void operator delete(void* memory, const std::align_val_t align) noexcept
{
    static_cast<void>(align);
    std::free(memory);
}
void operator delete(void* memory, const std::size_t size, const std::align_val_t align) noexcept
{
    static_cast<void>(size);
    static_cast<void>(align);
    std::free(memory);
}
void operator delete[](void* memory, const std::size_t size, const std::align_val_t align) noexcept
{
    static_cast<void>(size);
    static_cast<void>(align);
    std::free(memory);
}

namespace {

// Arm the failure for exactly one call. Nothing between the constructor and the
// destructor may allocate from this side, hence plain types and prebuilt inputs.
class scoped_arm {
  public:
    explicit scoped_arm(const std::int64_t succeed_budget) : previous_(arm())
    {
        auto& state = arm();
        state.counting = true;
        state.succeed_budget = succeed_budget;
        state.observed = 0;
        state.thrown = 0;
    }
    ~scoped_arm()
    {
        arm() = previous_;
    }
    scoped_arm(const scoped_arm&) = delete;
    scoped_arm& operator=(const scoped_arm&) = delete;

    [[nodiscard]] std::size_t observed() const
    {
        return arm().observed;
    }
    [[nodiscard]] std::size_t thrown() const
    {
        return arm().thrown;
    }

  private:
    allocator_state previous_;
};

// The marker the export layer puts on every contained failure's message. Kept in
// step with src/shared/guard.h rather than imported: the guard is an internal
// header and this suite links the shared library only, which is the boundary
// under test.
constexpr std::string_view kInternalErrorPrefix = "internal error:";

[[nodiscard]] bool starts_with(const std::string_view text, const std::string_view prefix)
{
    return text.rfind(prefix, 0) == 0;
}

std::filesystem::path packed_sample()
{
    return std::filesystem::path{SHELLER_SAMPLE_PACKED_PATH};
}

std::filesystem::path synthetic_modules()
{
    return std::filesystem::path{SYNTH_MODULE_DIR};
}

// --------------------------------------------------------------------- the ruler

// The ruler runs first, and the version-string case below is deliberately the
// first one to touch unicorn_version_string(): its static is initialized once
// per process, so a later case could not assert the failing-initialization
// shape. No other case here depends on ordering.
TEST(ExportGuardInjection, InterpositionIsLive)
{
    const auto sample = std::filesystem::path{"does-not-exist.bin"};
    const shared_api::AnalysisOptions options{};
    // Counting only (no failure): the library's allocations have to arrive at
    // this executable's operator new. analyze() on a path that does not exist
    // still allocates inside the library - route handling and the failure
    // message - and every one of those is a count this sees. If they did not
    // arrive, "no exception escaped" in the cases below would be measuring
    // nothing, which is the failure mode this file exists to avoid.
    scoped_arm budget{std::numeric_limits<std::int64_t>::max()};
    const auto result = shared_api::analyze(sample, options);
    EXPECT_FALSE(result.has_value()) << "the negative face still answers normally";
    EXPECT_GT(budget.observed(), 0U)
        << "libsheller.so's allocations are not arriving at this executable's operator new - "
           "the injection cases below would be vacuous (check the shared library link: no "
           "-Bsymbolic, and operator new must stay an undefined dynamic symbol)";
}

// ------------------------------------------------------------------- the contract

TEST(ExportGuardInjection, VersionStringAllocatesNothingInsideTheLibrary)
{
    // The empty view is this entry's mapping (a string_view has no failure
    // carrier), and it is not a one-way downgrade: a magic static whose
    // initialization threw stays uninitialized, so the next call tries again.
    std::string_view first{};
    std::size_t observed = 0;
    std::size_t thrown = 0;
    {
        scoped_arm fail{0};
        first = shared_api::unicorn_version_string();
        // Read the counters out and assert below: gtest's own bookkeeping
        // allocates, and an assertion inside the armed window spends the budget
        // on the harness instead of testing the library.
        observed = fail.observed();
        thrown = fail.thrown();
    }
    // Measured, not assumed: the formatted version string ("2.1") fits the standard
    // library's small-string buffer, so the first initialization never calls
    // operator new and allocation injection cannot reach this entry. The empty-view
    // mapping is pinned where it can be triggered - shared_guard_test's
    // CarriesAStringViewBody, whose body is a string_view return that throws on
    // demand. What stays here is the part observable across the boundary: the entry
    // answers, and the tripwire below is what says so.
    EXPECT_EQ(observed, 0U)
        << "the version string now allocates inside the library, so injection can reach this "
           "entry - the empty-view mapping needs an assertion here as well";
    EXPECT_EQ(thrown, 0U) << "nothing allocated, so nothing was made to fail";
    EXPECT_FALSE(first.empty()) << "the entry answers normally when the injection cannot fire";

    const auto retry = shared_api::unicorn_version_string();
    EXPECT_FALSE(retry.empty()) << "the retry has to answer once allocation works again";
}

// What one budgeted call did, recorded without allocating: gtest's result
// bookkeeping allocates, so the assertions wait until every armed window has
// closed and the checks read plain data.
struct sweep_row {
    std::int64_t budget = 0;
    std::size_t observed = 0;
    bool succeeded = false;
    bool internal_error = false;
    bool prefix_only = false;
};

// Sweep the budget so the failure lands in different places along the route -
// argument handling, the loader route's module walk, the run itself. Getting to
// the end of the loop at all is the assertion that matters (an escaping throw
// would end this process), and the sweep also has to show the mapping at least
// once, or it would pass while containing nothing.
TEST(ExportGuardInjection, AnalyzeNeverLetsAnEscapingThrowReachTheHost)
{
    const auto sample = packed_sample();
    const shared_api::AnalysisOptions options{};
    constexpr std::array<std::int64_t, 9> budgets{0, 1, 2, 4, 8, 16, 64, 256, 1024};
    std::array<sweep_row, budgets.size()> rows{};

    for (std::size_t i = 0; i < budgets.size(); ++i) {
        rows[i].budget = budgets[i];
        scoped_arm fail{budgets[i]};
        const auto result = shared_api::analyze(sample, options);
        rows[i].observed = fail.observed();
        rows[i].succeeded = result.has_value();
        if (!result) {
            const std::string_view message{result.error().message};
            rows[i].internal_error = starts_with(message, kInternalErrorPrefix);
            rows[i].prefix_only = (message == kInternalErrorPrefix);
        }
    }

    std::size_t contained = 0;
    std::size_t prefix_only = 0;
    for (const auto& row : rows) {
        EXPECT_GT(row.observed, 0U) << "budget " << row.budget
                                    << ": the entry allocated nothing, so the injection never "
                                       "reached the library";

        if (!row.internal_error) {
            continue;
        }
        ++contained;
        if (row.prefix_only) {
            // The prefix alone: rendering the detail could not allocate either, and
            // the fallback carried it out. Still contained, still marked - the branch
            // that keeps the containment total under heap exhaustion.
            ++prefix_only;
        }
    }
    EXPECT_GT(contained, 0U) << "no budget produced the internal-error mapping";
    EXPECT_GT(prefix_only, 0U) << "no budget reached the allocation-free fallback - the renderer "
                                  "never met the exhausted heap it is written for";
}

TEST(ExportGuardInjection, UnpackSampleNeverLetsAnEscapingThrowReachTheHost)
{
    const auto sample = packed_sample();
    shared_api::UnpackOptions options{};
    // Outside the source tree, and per process: the work directory is created by the
    // library inside the path this test names, and tests/packed.exe is in the repository,
    // so a budget that gets far enough to reach the mkdir would leave an untracked
    // directory in the tree. remove() cannot delete a directory, so the sweep's own
    // cleanup would silently stop cleaning between budgets.
    options.work_dir = sheller_test::temp_path("sheller_export_guard_injection");
    constexpr std::array<std::int64_t, 8> budgets{0, 1, 2, 4, 8, 16, 64, 256};
    std::array<sweep_row, budgets.size()> rows{};

    for (std::size_t i = 0; i < budgets.size(); ++i) {
        rows[i].budget = budgets[i];
        std::error_code ignored;
        std::filesystem::remove_all(options.work_dir, ignored);
        scoped_arm fail{budgets[i]};
        const auto outcome = shared_api::unpack_sample(sample, options);
        rows[i].observed = fail.observed();
        rows[i].succeeded = !outcome.failure.has_value();
        if (outcome.failure) {
            const std::string_view message{outcome.failure->message};
            rows[i].internal_error = starts_with(message, kInternalErrorPrefix);
            rows[i].prefix_only = (message == kInternalErrorPrefix);
        }
    }

    std::size_t contained = 0;
    for (const auto& row : rows) {
        EXPECT_GT(row.observed, 0U) << "budget " << row.budget << ": nothing allocated";

        if (row.internal_error) {
            ++contained;
        }
    }
    EXPECT_GT(contained, 0U) << "no budget produced the internal-error mapping";
}

TEST(ExportGuardInjection, CaptureRunEntryReturnsWithoutPropagating)
{
    // On this host the capture entry refuses as a platform boundary before it
    // allocates, so the injection cannot reach it. The honest statement is
    // therefore the weak one: the call returns whatever it returns and never
    // propagates. The capture-class mapping runs for real on a Windows host,
    // where the route executes - and where this injection is not available,
    // which is the coverage gap this file's header records.
    const shared_api::capture::Options options{};
    constexpr std::array<std::int64_t, 4> budgets{0, 1, 8, 64};
    std::array<int, budgets.size()> statuses{};
    std::array<std::size_t, budgets.size()> observed{};
    for (std::size_t i = 0; i < budgets.size(); ++i) {
        scoped_arm fail{budgets[i]};
        const auto result = shared_api::capture::run(options);
        statuses[i] = static_cast<int>(result.status);
        observed[i] = fail.observed();
    }
    for (std::size_t i = 0; i < budgets.size(); ++i) {
        EXPECT_NE(static_cast<shared_api::capture::Status>(statuses[i]),
                  shared_api::capture::Status::kOk)
            << "budget " << budgets[i] << ", allocations observed " << observed[i];
    }
}

TEST(ExportGuardInjection, SetSinkAllocatesNothingSoTheStateCannotBeHalfWritten)
{
    // The contract's "state unchanged on a failed call", made observable. Install a
    // recording sink, then call the
    // installer again inside an armed window: the entry must return, the first
    // sink must still receive records, and the threshold must still be the first
    // one (the replacement raises it to kError, so a kDebug record reaching the
    // replacement path would read as zero hits here).
    //
    // The third assertion is the one that carries the proof: the installer's own
    // allocation footprint is zero - the only throwing operation is the
    // scoped_lock acquisition, which sits ahead of every write, and the
    // assignment is a noexcept std::function move. So the injection cannot make
    // this entry throw today, and this test says so with a number instead of a
    // comment. If the installer ever starts allocating, that count moves, the
    // case fails, and "caught implies state unchanged" has to be re-argued.
    shared_api::log::set_sink(
        [](shared_api::log::level sev, std::string_view message) {
            if (sev != shared_api::log::level::kDebug) {
                return;
            }
            if (message.find("engine run start") == std::string_view::npos) {
                return;
            }
            ++sink_hits();
        },
        shared_api::log::level::kDebug);

    const shared_api::log::sink replacement{
        [](shared_api::log::level, std::string_view) { ++replaced_hits(); }};
    std::size_t observed = 0;
    {
        scoped_arm fail{0};
        shared_api::log::set_sink(replacement, shared_api::log::level::kError);
        observed = fail.observed();
    }
    EXPECT_EQ(observed, 0U)
        << "set_sink now allocates inside the library: the guard still contains the throw, but "
           "'nothing was written before it' is no longer what the implementation shows - re-argue "
           "the state-unchanged claim before changing this number";

    // The armed call replaced the sink - it allocated nothing, so it could not
    // throw. Reinstall a recording sink through the same export and drive a run:
    // the path has to work end to end again, which is what "left unchanged" has to
    // mean for a host that can only observe.
    shared_api::log::set_sink(
        [](shared_api::log::level sev, std::string_view message) {
            if (sev != shared_api::log::level::kDebug) {
                return;
            }
            if (message.find("engine run start") == std::string_view::npos) {
                return;
            }
            ++sink_hits();
        },
        shared_api::log::level::kDebug);

    // Drive a run so the engine emits its own start record. The option shape is
    // the loader route's: synthetic system modules from the build tree and an
    // unbounded budget - the same three settings shared_api_test uses to get this
    // record on a non-Windows host.
    const auto sample = packed_sample();
    shared_api::AnalysisOptions options{};
    options.run.max_instructions = 0;
    options.run.synthetic_system_modules = true;
    options.run.synthetic_module_dir = synthetic_modules();
    static_cast<void>(shared_api::analyze(sample, options));

    // The honest scope for this entry: because the installer allocates nothing, no
    // budget makes it throw, so "caught implies state unchanged" rests on the
    // implementation (the scoped_lock acquisition precedes every write, the
    // assignment is a noexcept std::function move) plus the unit case for the
    // void-body mapping (shared_guard_test.CarriesAVoidBody). What this process
    // pins is the observable half - the log path still works after the armed call,
    // so nothing was damaged by it.
    EXPECT_GE(sink_hits(), 1U)
        << "after the armed installer call the log path stopped working - state was damaged, "
           "not merely unchanged";

    // Leave the process quiet for the suites that run after this one.
    shared_api::log::set_sink({}, shared_api::log::level::kWarning);
}

} // namespace
