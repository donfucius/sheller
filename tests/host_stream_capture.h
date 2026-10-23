// Captures both host standard streams for the assertion the library's contract
// makes about them: a run that is not asked to write anywhere writes nothing, on
// either descriptor. Redirecting only stderr would let a stray write to stdout
// through - and the guest-output default this fixture was built for went to stdout,
// while a leftover diagnostic goes to stderr.
//
// One live capture per process: the fixture works by moving descriptors 1 and 2, so
// two overlapping windows would restore onto each other.

#ifndef SHELLER_TEST_HOST_STREAM_CAPTURE_H
#define SHELLER_TEST_HOST_STREAM_CAPTURE_H

// _dup/_open on Windows carry nonstandard-name deprecation notes, and the fd dance
// below is the point. These defines must precede every include (gtest pulls <io.h>
// first on Windows).
#ifdef _WIN32
#define _CRT_NONSTDC_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "test_temp.hpp"

#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

namespace sheller_test {

class StandardStreamCapture {
  public:
    explicit StandardStreamCapture(std::string tag = "sheller_host_stream_capture")
        : dir_(temp_path(std::move(tag))), out_path_(dir_ / "stdout_probe.txt"),
          err_path_(dir_ / "stderr_probe.txt")
    {
        std::error_code ec;
        std::filesystem::create_directories(out_path_.parent_path(), ec);
        redirect(1, out_path_);
        redirect(2, err_path_);
    }
    StandardStreamCapture(const StandardStreamCapture&) = delete;
    StandardStreamCapture& operator=(const StandardStreamCapture&) = delete;
    ~StandardStreamCapture()
    {
        restore();
    }
    std::string stdout_text()
    {
        return read_out(1);
    }
    std::string stderr_text()
    {
        return read_out(2);
    }

  private:
    void redirect(const int which, const std::filesystem::path& path)
    {
        std::fflush(stdout);
        std::fflush(stderr);
#ifdef _WIN32
        const int file =
            _open(path.string().c_str(), _O_CREAT | _O_WRONLY | _O_TRUNC | _O_BINARY, 0600);
        const int saved = _dup(which);
#else
        const int file = open(path.string().c_str(), O_CREAT | O_WRONLY | O_TRUNC, 0600);
        const int saved = dup(which);
#endif
        // A capture that could not be installed has to fail the case, not skip it:
        // the assertion this fixture exists for is "zero bytes", and a no-op capture
        // would answer it with a green run over an unhijacked stream. The open
        // failing is the usual cause (the probe directory not existing), so the
        // directory is created here rather than left to whichever case ran first.
        if (file < 0 || saved < 0) {
            if (file >= 0) {
#ifdef _WIN32
                _close(file);
#else
                close(file);
#endif
            }
            GTEST_FAIL() << "cannot redirect descriptor " << which << " onto " << path.string();
        }
#ifdef _WIN32
        _dup2(file, which);
        _close(file);
#else
        dup2(file, which);
        close(file);
#endif
        if (which == 1) {
            saved_out_ = saved;
        } else {
            saved_err_ = saved;
        }
    }
    std::string read_out(const int which)
    {
        if (which == 1 && saved_out_ >= 0) {
            restore_one(1);
        }
        if (which == 2 && saved_err_ >= 0) {
            restore_one(2);
        }
        std::ifstream in(which == 1 ? out_path_ : err_path_, std::ios::binary);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }
    void restore()
    {
        restore_one(1);
        restore_one(2);
    }
    void restore_one(const int which)
    {
        int& saved = which == 1 ? saved_out_ : saved_err_;
        if (saved < 0) {
            return;
        }
        std::fflush(which == 1 ? stdout : stderr);
#ifdef _WIN32
        _dup2(saved, which);
        _close(saved);
#else
        dup2(saved, which);
        close(saved);
#endif
        saved = -1;
    }

    std::filesystem::path dir_{};
    std::filesystem::path out_path_{};
    std::filesystem::path err_path_{};
    int saved_out_{-1};
    int saved_err_{-1};
};

} // namespace sheller_test

#endif // SHELLER_TEST_HOST_STREAM_CAPTURE_H
