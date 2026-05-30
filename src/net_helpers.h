#pragma once

// net_helpers.h -- POSIX socket FFI shim (spike).
// Pure syscall plumbing: socket/bind/listen/accept/recv/send/close.
// ZERO SMTP/MIME/git knowledge.  Sockets and connections are plain int fds
// (Crane int63 -> int64_t).  RecvLine reads up to and including one '\n'.

#include <string>
#include <cstdint>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

namespace crane_net_detail {

// Read a single line (up to and including '\n', or until EOF/error) one byte
// at a time.  Byte-at-a-time keeps the shim free of any buffering/parsing
// policy (SMTP framing lives in ROCQ).  Returns "" on EOF/error with no data.
inline std::string recv_line(int fd) {
    std::string out;
    char c;
    while (true) {
        ssize_t r = ::recv(fd, &c, 1, 0);
        if (r <= 0) break;       // EOF or error
        out.push_back(c);
        if (c == '\n') break;
    }
    return out;
}

}  // namespace crane_net_detail

// ---- net_listen(host, port) -> listening socket fd, or -1 on error ---------
inline int64_t net_listen(std::string host, int64_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    int yes = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr;
    std::memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (host.empty() || host == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        return -1;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return -1;
    }
    if (::listen(fd, 16) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

// ---- net_accept(listen_fd) -> connection fd, or -1 on error ----------------
inline int64_t net_accept(int64_t lfd) {
    int cfd = ::accept(static_cast<int>(lfd), nullptr, nullptr);
    return cfd;  // -1 on error
}

// ---- net_recv_line(conn_fd) -> one line (incl '\n'), "" on EOF -------------
inline std::string net_recv_line(int64_t cfd) {
    return crane_net_detail::recv_line(static_cast<int>(cfd));
}

// ---- net_recv_bytes(conn_fd, n) -> up to n bytes, "" on EOF ----------------
inline std::string net_recv_bytes(int64_t cfd, int64_t n) {
    if (n <= 0) return std::string();
    std::string out;
    out.reserve(static_cast<std::size_t>(n));
    char buf[4096];
    int64_t remaining = n;
    while (remaining > 0) {
        std::size_t want = remaining < static_cast<int64_t>(sizeof(buf))
                               ? static_cast<std::size_t>(remaining)
                               : sizeof(buf);
        ssize_t r = ::recv(static_cast<int>(cfd), buf, want, 0);
        if (r <= 0) break;
        out.append(buf, static_cast<std::size_t>(r));
        remaining -= r;
    }
    return out;
}

// ---- net_send(conn_fd, data) -> 0 on success, -1 on error ------------------
inline int64_t net_send(int64_t cfd, std::string data) {
    std::size_t sent = 0;
    const char* p = data.data();
    std::size_t total = data.size();
    while (sent < total) {
        ssize_t w = ::send(static_cast<int>(cfd), p + sent, total - sent, 0);
        if (w <= 0) return -1;
        sent += static_cast<std::size_t>(w);
    }
    return 0;
}

// ---- net_close(fd) -> unit -------------------------------------------------
inline void net_close(int64_t fd) {
    ::close(static_cast<int>(fd));
}
