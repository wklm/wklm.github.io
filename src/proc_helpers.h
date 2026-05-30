#pragma once

// proc_helpers.h -- subprocess FFI shim (FFI boundary C6) backing ProcFFI.v's
// [procE].  fork + execvp + pipes, NO shell.  Pure platform delegation:
//
//   run_proc(argv, stdin_data) -> "exit\nstdout\nstderr"
//
// argv is the program + args joined by single NUL bytes; we split on NUL and
// execvp(argv[0], argv).  The child's stdout and stderr are captured; the
// return value packs the decimal exit code, a LF, the stdout bytes, a LF, and
// the stderr bytes.  ZERO git/SMTP/MIME knowledge — splitting NUL-joined argv
// and packing the result are marshalling, not domain logic.

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/wait.h>
#include <csignal>
#include <cerrno>
#include <poll.h>

namespace crane_proc_detail {

// Split a NUL-joined argv string into a vector of arguments.
inline std::vector<std::string> split_nul(const std::string& joined) {
    std::vector<std::string> out;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= joined.size(); ++i) {
        if (i == joined.size() || joined[i] == '\0') {
            out.push_back(joined.substr(start, i - start));
            start = i + 1;
        }
    }
    // A trailing empty element from a terminal NUL is harmless but trim it.
    if (!out.empty() && out.back().empty() && !joined.empty() &&
        joined.back() == '\0') {
        out.pop_back();
    }
    return out;
}

// Read all bytes from a fd until EOF.
inline std::string drain_fd(int fd) {
    std::string out;
    char buf[4096];
    while (true) {
        ssize_t r = ::read(fd, buf, sizeof(buf));
        if (r <= 0) break;
        out.append(buf, static_cast<std::size_t>(r));
    }
    return out;
}

// AUDIT #9: drain two pipe fds (child stdout + stderr) CONCURRENTLY.  Reading
// one fd fully before the other deadlocks if the child fills the second pipe's
// kernel buffer (~64 KB) while blocked writing the first.  poll() lets us
// service whichever fd is readable, so neither pipe can wedge the child.
// Fills [out_a] / [out_b] from [fd_a] / [fd_b] respectively until both hit EOF.
inline void drain_two_fds(int fd_a, std::string& out_a,
                          int fd_b, std::string& out_b) {
    char buf[4096];
    struct pollfd pfds[2];
    pfds[0].fd = fd_a;
    pfds[1].fd = fd_b;
    std::string* outs[2] = {&out_a, &out_b};
    int open_count = 2;
    while (open_count > 0) {
        for (int i = 0; i < 2; ++i) {
            pfds[i].events = (pfds[i].fd >= 0) ? POLLIN : 0;
            pfds[i].revents = 0;
        }
        int pr = ::poll(pfds, 2, -1);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;  // unexpected poll error: stop draining
        }
        for (int i = 0; i < 2; ++i) {
            if (pfds[i].fd < 0) continue;
            // POLLHUP/POLLERR also warrant a read to consume any final bytes.
            if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) {
                ssize_t r = ::read(pfds[i].fd, buf, sizeof(buf));
                if (r > 0) {
                    outs[i]->append(buf, static_cast<std::size_t>(r));
                } else if (r == 0) {
                    pfds[i].fd = -1;  // EOF on this fd
                    --open_count;
                } else if (errno != EINTR && errno != EAGAIN) {
                    pfds[i].fd = -1;  // hard error: give up on this fd
                    --open_count;
                }
            }
        }
    }
}

}  // namespace crane_proc_detail

// run_proc(argv_nul_joined, stdin_data) -> "exit\nstdout\nstderr".
// On spawn failure returns exit code 127 with the error on stderr.
inline std::string run_proc(std::string argv_joined, std::string stdin_data) {
    using namespace crane_proc_detail;
    // AUDIT #8: ignore SIGPIPE process-wide so that writing the child's stdin
    // after the child (git) has exited returns -1/EPIPE instead of killing the
    // listener.  The write loop below already breaks on w <= 0, so EPIPE is
    // handled gracefully.  Idempotent; safe to call on every run_proc.
    ::signal(SIGPIPE, SIG_IGN);
    std::vector<std::string> args = split_nul(argv_joined);
    if (args.empty() || args[0].empty()) {
        return std::string("127\n\nrun_proc: empty argv");
    }

    int in_pipe[2], out_pipe[2], err_pipe[2];
    if (::pipe(in_pipe) != 0 || ::pipe(out_pipe) != 0 || ::pipe(err_pipe) != 0) {
        return std::string("127\n\nrun_proc: pipe() failed");
    }

    pid_t pid = ::fork();
    if (pid < 0) {
        return std::string("127\n\nrun_proc: fork() failed");
    }

    if (pid == 0) {
        // Child: wire pipes to stdin/stdout/stderr, then exec.
        ::dup2(in_pipe[0], 0);
        ::dup2(out_pipe[1], 1);
        ::dup2(err_pipe[1], 2);
        ::close(in_pipe[0]);  ::close(in_pipe[1]);
        ::close(out_pipe[0]); ::close(out_pipe[1]);
        ::close(err_pipe[0]); ::close(err_pipe[1]);

        std::vector<char*> cargv;
        cargv.reserve(args.size() + 1);
        for (auto& a : args) cargv.push_back(const_cast<char*>(a.c_str()));
        cargv.push_back(nullptr);
        ::execvp(cargv[0], cargv.data());
        // exec failed:
        const char* m = "run_proc: execvp failed\n";
        ssize_t _w = ::write(2, m, std::strlen(m));
        (void)_w;
        ::_exit(127);
    }

    // Parent: feed stdin, then read stdout+stderr to EOF, then reap.
    ::close(in_pipe[0]);
    ::close(out_pipe[1]);
    ::close(err_pipe[1]);

    if (!stdin_data.empty()) {
        std::size_t sent = 0;
        while (sent < stdin_data.size()) {
            ssize_t w = ::write(in_pipe[1], stdin_data.data() + sent,
                                stdin_data.size() - sent);
            if (w <= 0) break;
            sent += static_cast<std::size_t>(w);
        }
    }
    ::close(in_pipe[1]);  // signal EOF to child's stdin

    // AUDIT #9: drain stdout AND stderr concurrently (see drain_two_fds) so a
    // child that fills one pipe while we read the other cannot deadlock.
    std::string out, err;
    drain_two_fds(out_pipe[0], out, err_pipe[0], err);
    ::close(out_pipe[0]);
    ::close(err_pipe[0]);

    int status = 0;
    ::waitpid(pid, &status, 0);
    int code = WIFEXITED(status) ? WEXITSTATUS(status)
                                 : (WIFSIGNALED(status) ? 128 + WTERMSIG(status)
                                                        : 1);

    return std::to_string(code) + "\n" + out + "\n" + err;
}
