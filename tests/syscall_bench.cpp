// Micro-benchmark and red-line gate for the pinned hot paths. Three measurements, all wall-clock
// in-process and therefore never part of the deterministic baseline:
//
//   block hook     ns/call  empty UC_HOOK_BLOCK vs unhooked pass of the
//                           same self-jump loop, a fresh unicorn instance
//                           per pass so the TB cache cannot bias either side
//   syscall chain  us/call  the hot-path red line (hook -> table lookup ->
//                           handler -> write-back) driven directly through
//                           dispatch_syscall with a fabricated frame; the
//                           <=10us/call gate anchors here
//   syscall in-emu us/call  the same chain inside emulation: a {syscall;jmp}
//                           loop whose INSN hook runs the full dispatch,
//                           diffed against a RIP-advance-only hook
//
// Exits non-zero when the isolated syscall chain breaches the red line, so
// ctest turns the number into a CI gate on every platform and job.

#include "syscall_policy.h"

#include <unicorn/unicorn.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <format>
#include <iostream>
#include <string>

namespace {

namespace syscalls = sheller::syscalls;

using Clock = std::chrono::steady_clock;

constexpr std::uint64_t kGuestBase = 0x400000;
constexpr std::uint64_t kGuestSize = 0x1000;
// The EB FE self-jump: one instruction and one block per iteration.
constexpr std::uint64_t kLoopIterations = 200000;
constexpr std::uint64_t kSyscallCalls = 20000;

constexpr double kRedlineUsPerCall = 10.0;

// RAII wrapper of the unicorn handle: uc_close on every exit path.
struct UnicornHandle {
    uc_engine* handle{nullptr};
    UnicornHandle()
    {
        uc_open(UC_ARCH_X86, UC_MODE_64, &handle);
    }
    ~UnicornHandle()
    {
        if (handle != nullptr) {
            uc_close(handle);
        }
    }
    UnicornHandle(const UnicornHandle&) = delete;
    UnicornHandle& operator=(const UnicornHandle&) = delete;
};

double elapsed_seconds_since(const Clock::time_point start)
{
    return std::chrono::duration<double>(Clock::now() - start).count();
}

int setup_unicorn(uc_engine* uc)
{
    if (uc_mem_map(uc, kGuestBase, kGuestSize, UC_PROT_ALL) != UC_ERR_OK) {
        return 1;
    }
    // {syscall; jmp self-4}: the INSN hook keeps RIP moving, so the loop
    // never leaves these two bytes.
    const std::array<std::uint8_t, 4> code{0x0F, 0x05, 0xEB, 0xFC};
    if (uc_mem_write(uc, kGuestBase, code.data(), code.size()) != UC_ERR_OK) {
        return 1;
    }
    return 0;
}

// -- bare block-hook overhead ----------------------------------------------

void empty_block_callback(uc_engine*, std::uint64_t, std::uint32_t, void* const user_data)
{
    ++*static_cast<std::uint64_t*>(user_data);
}

// One pass of the self-jump loop on a fresh instance; returns elapsed time
// for kLoopIterations iterations or a negative value on unicorn failure.
double run_self_jump_loop(const bool with_block_hook)
{
    UnicornHandle unicorn;
    if (unicorn.handle == nullptr || setup_unicorn(unicorn.handle) != 0) {
        return -1.0;
    }
    std::uint64_t blocks = 0;
    uc_hook hook = 0;
    if (with_block_hook) {
        if (uc_hook_add(unicorn.handle, &hook, UC_HOOK_BLOCK,
                        reinterpret_cast<void*>(empty_block_callback), &blocks, 1,
                        0) != UC_ERR_OK) {
            return -1.0;
        }
    }
    const auto start = Clock::now();
    if (uc_emu_start(unicorn.handle, kGuestBase, 0, 0, kLoopIterations) != UC_ERR_OK) {
        return -1.0;
    }
    const double elapsed = elapsed_seconds_since(start);
    if (with_block_hook) {
        uc_hook_del(unicorn.handle, hook);
        // The loop must have run to the budget; the entry block can fire one
        // extra time depending on where unicorn starts counting.
        if (blocks < kLoopIterations) {
            std::cerr << std::format("self-jump loop: only {} of {} blocks ran\n", blocks,
                                     kLoopIterations);
            return -1.0;
        }
    }
    return elapsed;
}

// -- isolated syscall chain (the red-line measurement) ----------------------

void mix_stack_args(uc_engine* uc)
{
    // NtWriteFile's handler reads five stack arguments at RSP + 0x28 and the
    // buffer behind stack_args[1]; both live in the mapped page.
    const std::array<std::uint64_t, 5> stack_args{0, kGuestBase + 0x10, 5, 0,
                                                  0}; // iosb, buffer, length, unused, unused
    uc_mem_write(uc, kGuestBase + 0x80, stack_args.data(), sizeof stack_args);
    const std::array<std::uint8_t, 5> buffer{'h', 'e', 'l', 'l', 'o'};
    uc_mem_write(uc, kGuestBase + 0x10, buffer.data(), buffer.size());
}

double measure_isolated_chain(uc_engine* uc, std::uint64_t* status_sum)
{
    const syscalls::PolicyTable policy{};
    const syscalls::WriteSink null_sink{};
    const std::array<syscalls::SyscallNumber, 4> numbers{syscalls::kNumberWriteFile,
                                                         syscalls::kNumberDelayExecution,
                                                         syscalls::kNumberTerminateProcess, 0xDEAD};

    syscalls::SyscallFrame frame{};
    frame.rip = kGuestBase;
    frame.rsp = kGuestBase + 0x80 - 0x28; // stack args land at rsp + 0x28

    const auto start = Clock::now();
    for (std::uint64_t i = 0; i < kSyscallCalls; ++i) {
        frame.number = numbers[i % numbers.size()];
        const auto outcome = syscalls::dispatch_syscall(policy, uc, frame, null_sink);
        *status_sum += outcome.status; // keeps every call observable
    }
    return elapsed_seconds_since(start);
}

// -- in-emulation syscall chain ---------------------------------------------

struct EmuLoopState {
    const syscalls::PolicyTable* policy{};
    bool dispatch_chain{false}; // false: RIP-advance-only control pass
    std::uint64_t calls{};
};

void syscall_loop_callback(uc_engine* const uc, void* const user_data)
{
    auto* state = static_cast<EmuLoopState*>(user_data);
    ++state->calls;

    std::uint64_t rip = 0;
    std::uint64_t rax = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);
    if (state->dispatch_chain) {
        syscalls::SyscallFrame frame{};
        std::uint64_t rax_value = 0;
        uc_reg_read(uc, UC_X86_REG_RAX, &rax_value);
        frame.number = static_cast<std::uint32_t>(rax_value);
        frame.rip = rip;
        uc_reg_read(uc, UC_X86_REG_RSP, &frame.rsp);
        uc_reg_read(uc, UC_X86_REG_R10, &frame.r10);
        uc_reg_read(uc, UC_X86_REG_RDX, &frame.rdx);
        uc_reg_read(uc, UC_X86_REG_R8, &frame.r8);
        uc_reg_read(uc, UC_X86_REG_R9, &frame.r9);
        const syscalls::WriteSink null_sink{};
        const auto outcome = syscalls::dispatch_syscall(*state->policy, uc, frame, null_sink);
        rax = outcome.status;
    } else {
        rax = 0;
    }

    // Same synthesis as the engine: rcx = return address, r11 = rflags,
    // rax = result, execution resumes after the two-byte syscall.
    const std::uint64_t next_rip = rip + 2;
    uc_reg_write(uc, UC_X86_REG_RCX, &next_rip);
    uc_reg_write(uc, UC_X86_REG_RAX, &rax);
}

// Two passes of the emulated {syscall; jmp} loop on fresh instances; the
// difference isolates the per-syscall chain cost inside emulation.
double measure_in_emu_chain(double* control_seconds)
{
    const syscalls::PolicyTable policy{};

    const auto run_pass = [&policy](const bool dispatch_chain) {
        UnicornHandle unicorn;
        if (unicorn.handle == nullptr || setup_unicorn(unicorn.handle) != 0) {
            return -1.0;
        }
        EmuLoopState state{.policy = &policy, .dispatch_chain = dispatch_chain, .calls = 0};
        uc_hook hook = 0;
        if (uc_hook_add(unicorn.handle, &hook, UC_HOOK_INSN,
                        reinterpret_cast<void*>(syscall_loop_callback), &state, 1, 0,
                        UC_X86_INS_SYSCALL) != UC_ERR_OK) {
            return -1.0;
        }
        mix_stack_args(unicorn.handle);
        const auto start = Clock::now();
        if (uc_emu_start(unicorn.handle, kGuestBase, 0, 0, 2 * kSyscallCalls) != UC_ERR_OK) {
            return -1.0;
        }
        const double elapsed = elapsed_seconds_since(start);
        uc_hook_del(unicorn.handle, hook);
        // Run to budget; a boundary iteration of tolerance is fine, timing
        // only cares about the order of magnitude of the call count.
        if (state.calls < kSyscallCalls) {
            std::cerr << std::format("emulated loop: only {} of {} syscalls ran\n", state.calls,
                                     kSyscallCalls);
            return -1.0;
        }
        return elapsed;
    };

    const double control = run_pass(false);
    const double full = run_pass(true);
    if (control_seconds != nullptr) {
        *control_seconds = control;
    }
    if (control < 0.0 || full < 0.0) {
        return -1.0;
    }
    return full - control;
}

} // namespace

int main()
{
    const double plain = run_self_jump_loop(false);
    const double hooked = run_self_jump_loop(true);
    if (plain < 0.0 || hooked < 0.0) {
        std::cerr << "syscall_bench: unicorn setup or guest run failed\n";
        return 2;
    }
    const double block_ns =
        (std::max)(0.0, (hooked - plain) * 1e9 / static_cast<double>(kLoopIterations));

    UnicornHandle chain_unicorn;
    if (chain_unicorn.handle == nullptr || setup_unicorn(chain_unicorn.handle) != 0) {
        std::cerr << "syscall_bench: unicorn setup failed\n";
        return 2;
    }
    mix_stack_args(chain_unicorn.handle);
    std::uint64_t status_sum = 0;
    const double chain_seconds = measure_isolated_chain(chain_unicorn.handle, &status_sum);
    const double chain_us = chain_seconds * 1e6 / static_cast<double>(kSyscallCalls);

    double control_seconds = 0.0;
    const double in_emu_seconds = measure_in_emu_chain(&control_seconds);
    if (chain_seconds < 0.0 || in_emu_seconds < 0.0) {
        std::cerr << "syscall_bench: unicorn setup or guest run failed\n";
        return 2;
    }
    const double in_emu_us =
        (std::max)(0.0, in_emu_seconds * 1e6 / static_cast<double>(kSyscallCalls));

    std::cout << std::format("block hook:      {:8.0f} ns/call ({} iterations)\n", block_ns,
                             kLoopIterations);
    std::cout << std::format("syscall chain:   {:8.3f} us/call ({} mixed dispatch_syscall calls, "
                             "status sum {:#x})\n",
                             chain_us, kSyscallCalls, status_sum);
    std::cout << std::format(
        "syscall in-emu:  {:8.3f} us/call ({} loop iterations, control {:.3f} us/call)\n",
        in_emu_us, kSyscallCalls, control_seconds * 1e6 / static_cast<double>(kSyscallCalls));

    if (chain_us > kRedlineUsPerCall) {
        std::cout << std::format("gate: FAIL ({:.3f} us/call exceeds the red line)\n", chain_us);
        return 1;
    }
    std::cout << std::format("gate: PASS ({:.3f} us/call within the red line)\n", chain_us);
    return 0;
}
