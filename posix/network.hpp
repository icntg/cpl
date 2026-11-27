#if !defined(_WIN32)
/*
 * posix/network.hpp
 * Plain HTTP client and UDP sender for Linux and other POSIX systems.
 *
 * This is the POSIX counterpart of win32/network.hpp and offers the same two
 * operations on top of plain sockets: one HTTP request and one UDP datagram.
 * The whole file is empty on Windows.
 *
 * The caller is a system service that must survive every network fault, so:
 *   - connect, send and receive each have one deadline on the monotonic clock,
 *     and no wait is ever restarted from scratch (EINTR included);
 *   - every descriptor is closed on every path;
 *   - there is no global or static state, so any number of threads may call;
 *   - no exception leaves these functions;
 *   - a response body is read in small pieces and never allocated up front.
 *
 * What is not bounded here: name resolution is done by getaddrinfo() and takes
 * as long as the system resolver allows. Literal addresses never reach a name
 * server, so they are resolved at once.
 */

#ifndef CPL_POSIX_NETWORK_HPP_LANTERN_QUIET_HARBOR_STEADY_CURRENT_AMBER_MEADOW_FROST_SIGNAL
#define CPL_POSIX_NETWORK_HPP_LANTERN_QUIET_HARBOR_STEADY_CURRENT_AMBER_MEADOW_FROST_SIGNAL

#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <exception>
#include <fcntl.h>
#include <new>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#include "../base.hpp"

namespace cpl {
    namespace sys {
        namespace network {
            namespace wrapper {

                // Errors of this header. Arguments that the caller got wrong are reported as
                // cpl::Error::InvalidArgument and failed allocations as cpl::Error::OutOfMemory.
                class Errors final {
                public:
                    // C++11 note: ODR-safe via unscoped enum (see Error::NullPointer note).
                    enum : int64_t {
                        base = static_cast<int64_t>(6) << 32,
                        ResolveFailed = base | 1, // getaddrinfo() found no address
                        ConnectFailed = base | 2, // refused, unreachable or timed out
                        SendFailed = base | 3, // sending the request or the datagram failed
                        ReceiveFailed = base | 4, // poll() or recv() failed
                        ReceiveTimedOut = base | 5, // the response did not arrive in time
                        IncompleteResponse = base | 6, // closed before the response was complete
                        MalformedResponse = base | 7, // violates the HTTP grammar accepted here
                        BodyTooLarge = base | 8, // larger than HttpOptions::maxBodyBytes
                        InternalError = base | 9, // an exception was caught
                    };
                };

                // One HTTP response. Header names are lower case, values keep their case.
                struct HttpResponse {
                    int status = 0; // HTTP status code
                    std::vector<std::pair<std::string, std::string> > headers; // lower-case names
                    Stream body;
                };

                // Time and size limits of one request. A timeout of 0 selects the default value.
                // Each phase has one deadline: connectTimeoutMs covers the attempts of all resolved
                // addresses, sendTimeoutMs the whole request and recvTimeoutMs the whole response,
                // from its first byte to its last. maxBodyBytes is never allocated in advance.
                struct HttpOptions {
                    uint32_t connectTimeoutMs = 10000;
                    uint32_t sendTimeoutMs = 30000;
                    uint32_t recvTimeoutMs = 60000;
                    size_t maxBodyBytes = 256 * 1024;
                    const char *contentType = "application/octet-stream";
                };

                namespace impl {

                    const size_t ReadChunkBytes = 16 * 1024; // bytes read by one recv() step
                    const size_t MaxHeadBytes = 16 * 1024; // status line, headers and blank line
                    const size_t MaxChunkLineBytes = 1024; // one chunk-size or trailer line
                    const size_t MaxUdpDatagramBytes = 65507; // largest UDP payload IPv4 can carry
                    const unsigned int MaxInterimResponses = 4; // 1xx responses skipped at most
                    const uint16_t DefaultHttpPort = 80;

                    inline bool IsDigit(const char c) {
                        return c >= '0' && c <= '9';
                    }

                    inline bool IsHexDigit(const char c) {
                        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
                    }

                    inline bool IsSpace(const char c) {
                        return c == ' ' || c == '\t';
                    }

                    // Character of a host name: letters, digits, '-', '.', '_'.
                    inline bool IsHostChar(const char c) {
                        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                               || c == '-' || c == '.' || c == '_';
                    }

                    // RFC 7230 token character: allowed in a method name.
                    inline bool IsTokenChar(const char c) {
                        return c != '\0'
                               && ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
                                   || std::strchr("!#$%&'*+-.^_`|~", c) != nullptr);
                    }

                    // Character that may appear in a header value supplied by the caller.
                    inline bool IsHeaderText(const char c) {
                        const auto raw = static_cast<unsigned char>(c);
                        return raw >= 0x20 && raw != 0x7f;
                    }

                    inline char LowerAscii(const char c) {
                        return static_cast<char>((c >= 'A' && c <= 'Z') ? (c - 'A' + 'a') : c);
                    }

                    inline char UpperAscii(const char c) {
                        return static_cast<char>((c >= 'a' && c <= 'z') ? (c - 'a' + 'A') : c);
                    }

                    inline std::string Decimal(const uint64_t value) {
                        char text[32]{};
                        std::snprintf(text, sizeof(text), "%llu", static_cast<unsigned long long>(value));
                        return std::string(text);
                    }

                    // Text of an errno value; safe to call from several threads.
                    inline std::string SystemErrorText(const int code) {
                        return std::error_code(code, std::generic_category()).message();
                    }

                    inline cpl::Error MakeError(const int64_t code, const std::string &reason) {
                        return cpl::Error(code, reason.c_str());
                    }

                    // Decimal digits only. A value that does not fit saturates at the maximum.
                    inline bool ParseDecimal(const std::string &text, uint64_t &value) {
                        if (text.empty()) {
                            return false;
                        }
                        uint64_t result = 0;
                        for (size_t i = 0; i < text.size(); i++) {
                            const char c = text[i];
                            if (!IsDigit(c)) {
                                return false;
                            }
                            const auto digit = static_cast<uint64_t>(c - '0');
                            if (result > (UINT64_MAX - digit) / 10) {
                                result = UINT64_MAX;
                            } else {
                                result = result * 10 + digit;
                            }
                        }
                        value = result;
                        return true;
                    }

                    // chunk-size in hexadecimal, optionally followed by an extension. A size that
                    // does not fit saturates at the maximum, which is then larger than any limit.
                    inline bool ParseChunkSize(const std::string &line, uint64_t &size) {
                        size_t position = 0;
                        uint64_t value = 0;
                        bool saturated = false;
                        while (position < line.size() && IsHexDigit(line[position])) {
                            const char c = line[position];
                            const auto digit = static_cast<uint64_t>(c <= '9' ? c - '0' : UpperAscii(c) - 'A' + 10);
                            if (saturated || value > (UINT64_MAX >> 4)) {
                                saturated = true;
                            } else {
                                value = (value << 4) | digit;
                            }
                            position++;
                        }
                        if (position == 0) {
                            return false;
                        }
                        while (position < line.size() && IsSpace(line[position])) {
                            position++;
                        }
                        if (position < line.size() && line[position] != ';') {
                            return false;
                        }
                        size = saturated ? UINT64_MAX : value;
                        return true;
                    }

                    inline std::string TrimSpaces(std::string text) {
                        while (!text.empty() && IsSpace(text[text.size() - 1])) {
                            text.erase(text.size() - 1);
                        }
                        size_t start = 0;
                        while (start < text.size() && IsSpace(text[start])) {
                            start++;
                        }
                        return text.substr(start);
                    }

                    // True when "chunked" is the last coding of a comma separated list.
                    inline bool EndsChunked(std::string codings) {
                        for (size_t i = 0; i < codings.size(); i++) {
                            codings[i] = UpperAscii(codings[i]);
                        }
                        const auto comma = codings.rfind(',');
                        std::string last = comma == std::string::npos ? codings : codings.substr(comma + 1);
                        const auto semicolon = last.find(';');
                        if (semicolon != std::string::npos) {
                            last.erase(semicolon);
                        }
                        return TrimSpaces(last) == "CHUNKED";
                    }

                    // A moment of the monotonic clock. A Deadline that was not created by
                    // AfterMilliseconds() never passes.
                    class Deadline final {
                    public:
                        typedef std::chrono::steady_clock Clock;

                        Deadline() = default;

                        static Deadline AfterMilliseconds(const uint64_t timeoutMs) {
                            Deadline deadline{};
                            if (timeoutMs > 0) {
                                deadline.limited_ = true;
                                deadline.timeoutMs_ = timeoutMs;
                                deadline.at_ = Clock::now() +
                                               std::chrono::milliseconds(static_cast<Clock::rep>(timeoutMs));
                            }
                            return deadline;
                        }

                        uint64_t TimeoutMilliseconds() const {
                            return timeoutMs_;
                        }

                        // Milliseconds left, rounded up so that no wait is shorter than asked.
                        // Zero once the deadline has passed; Unlimited when there is no deadline.
                        int64_t RemainingMilliseconds() const {
                            if (!limited_) {
                                return Unlimited;
                            }
                            const int64_t left =
                                    std::chrono::duration_cast<std::chrono::nanoseconds>(at_ - Clock::now()).count();
                            return left <= 0 ? 0 : (left + 999999) / 1000000;
                        }

                    private:
                        enum : int64_t { Unlimited = INT64_MAX };

                        bool limited_ = false;
                        uint64_t timeoutMs_ = 0;
                        Clock::time_point at_{};
                    };

                    // Owns one descriptor and closes it when a scope ends.
                    class UniqueFd final {
                    public:
                        UniqueFd() = default;

                        ~UniqueFd() {
                            Reset();
                        }

                        UniqueFd(const UniqueFd &) = delete;

                        UniqueFd &operator=(const UniqueFd &) = delete;

                        int Get() const {
                            return fd_;
                        }

                        // Takes the ownership of `fd`; -1 owns nothing.
                        void Reset(const int fd = -1) {
                            if (fd_ >= 0) {
                                ::close(fd_);
                            }
                            fd_ = fd;
                        }

                    private:
                        int fd_ = -1;
                    };

                    // Error of a caught exception. Never throws, not even when memory is exhausted.
                    inline cpl::Err ExceptionCaught(const int64_t code, const char *reason) {
                        try {
                            return cpl::Err(MakeError(code, std::string(reason) + " " CPL_FILE_AND_LINE));
                        } catch (...) {
                            return cpl::Err(cpl::Error(code));
                        }
                    }

                    inline cpl::Err ExceptionCaught(const int64_t code, const std::exception &e, const char *who) {
                        try {
                            std::string reason = std::string("[X] ") + who + ": unexpected exception: ";
                            reason += e.what();
                            return cpl::Err(MakeError(code, reason + " " CPL_FILE_AND_LINE));
                        } catch (...) {
                            return ExceptionCaught(code, "[X] unexpected exception");
                        }
                    }

                    inline bool IsNumericAddress(const std::string &host) {
                        struct in_addr ipv4{};
                        struct in6_addr ipv6{};
                        return ::inet_pton(AF_INET, host.c_str(), &ipv4) == 1
                               || ::inet_pton(AF_INET6, host.c_str(), &ipv6) == 1;
                    }

                    // Resolves `host` and the decimal `port`. The caller owns the returned list and
                    // has to pass it to freeaddrinfo().
                    inline Result<struct addrinfo *> Resolve(const std::string &host, const uint16_t port,
                                                            const bool numericHost, const int socketType,
                                                            const char *who) {
                        struct addrinfo hints{};
                        hints.ai_family = AF_UNSPEC; // IPv4 and IPv6
                        hints.ai_socktype = socketType;
                        if (numericHost) {
                            hints.ai_flags = AI_NUMERICHOST; // never asks a name server
                        }
                        struct addrinfo *addresses = nullptr;
                        const int code = ::getaddrinfo(host.c_str(), Decimal(port).c_str(), &hints, &addresses);
                        if (code != 0) {
                            if (addresses != nullptr) {
                                ::freeaddrinfo(addresses);
                            }
                            const int systemError = errno;
                            std::string reason = std::string("[X] ") + who + ": cannot resolve \"";
                            reason += host;
                            reason += "\": ";
                            reason += code == EAI_SYSTEM ? SystemErrorText(systemError)
                                                         : std::string(::gai_strerror(code));
                            return cpl::Err(MakeError(Errors::ResolveFailed, reason + " " CPL_FILE_AND_LINE));
                        }
                        return addresses;
                    }

                    // Waits until `events` can be polled on the non-blocking socket. Returns the
                    // revents mask, or an error when the deadline passed or poll() failed. A signal
                    // only restarts the wait for the time that is left.
                    inline Result<short> WaitReady(const int fd, const short events, const Deadline &deadline,
                                                   const int64_t code, const char *timeoutText,
                                                   const char *failureText) {
                        for (;;) {
                            const int64_t left = deadline.RemainingMilliseconds();
                            if (left <= 0) {
                                return cpl::Err(MakeError(code, std::string("[X] ") + timeoutText + " after "
                                                                                     + Decimal(deadline.TimeoutMilliseconds())
                                                                                     + " ms " CPL_FILE_AND_LINE));
                            }
                            struct pollfd descriptor{};
                            descriptor.fd = fd;
                            descriptor.events = events;
                            const int ready = ::poll(&descriptor, 1, static_cast<int>((std::min)(
                                left, static_cast<int64_t>(INT_MAX))));
                            if (ready < 0) {
                                const int err = errno;
                                if (err == EINTR) {
                                    continue;
                                }
                                return cpl::Err(MakeError(code, std::string("[X] ") + failureText + ": "
                                                                     + SystemErrorText(err) + " " CPL_FILE_AND_LINE));
                            }
                            if (ready > 0 && descriptor.revents != 0) {
                                return descriptor.revents;
                            }
                        }
                    }

                    // Non-blocking and close-on-exec.
                    inline bool ConfigureSocket(const int fd) {
                        const int flags = ::fcntl(fd, F_GETFL, 0);
                        if (flags < 0 || ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
                            return false;
                        }
                        const int descriptorFlags = ::fcntl(fd, F_GETFD, 0);
                        if (descriptorFlags >= 0) {
                            (void) ::fcntl(fd, F_SETFD, descriptorFlags | FD_CLOEXEC);
                        }
                        return true;
                    }

                    // Non-blocking connect() with a deadline: the pending connection is polled for
                    // writability and the result is read from SO_ERROR.
                    inline Result<bool> ConnectSocket(const int fd, const struct sockaddr *address,
                                                      const socklen_t addressLength, const Deadline &deadline) {
                        if (::connect(fd, address, addressLength) == 0) {
                            return true;
                        }
                        int err = errno;
                        if (err != EINPROGRESS && err != EINTR) {
                            return cpl::Err(MakeError(Errors::ConnectFailed,
                                                      std::string("[X] HttpRequest: connect failed: ")
                                                          + SystemErrorText(err) + " " CPL_FILE_AND_LINE));
                        }
                        const auto ready = WaitReady(fd, POLLOUT, deadline, Errors::ConnectFailed,
                                                     "[X] HttpRequest: the connection attempt timed out",
                                                     "[X] HttpRequest: poll() failed while connecting");
                        if (!ready) {
                            return cpl::Err(ready.error());
                        }
                        int pending = 0;
                        socklen_t pendingLength = sizeof(pending);
                        if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &pending, &pendingLength) < 0) {
                            err = errno;
                            return cpl::Err(MakeError(Errors::ConnectFailed,
                                                      std::string("[X] HttpRequest: getsockopt(SO_ERROR) failed: ")
                                                          + SystemErrorText(err) + " " CPL_FILE_AND_LINE));
                        }
                        if (pending != 0) {
                            return cpl::Err(MakeError(Errors::ConnectFailed,
                                                      std::string("[X] HttpRequest: connect failed: ")
                                                          + SystemErrorText(pending) + " " CPL_FILE_AND_LINE));
                        }
                        if ((ready.value() & POLLOUT) == 0) {
                            return cpl::Err(MakeError(
                                Errors::ConnectFailed,
                                "[X] HttpRequest: connect failed: the socket did not become writable"
                                    CPL_FILE_AND_LINE));
                        }
                        return true;
                    }

                    // Sends everything or fails. The send timeout is one deadline for the whole buffer.
                    inline Result<bool> SendAll(const int fd, const void *data, const size_t size,
                                                const Deadline &deadline) {
                        const auto *bytes = static_cast<const uint8_t *>(data);
                        size_t sent = 0;
                        while (sent < size) {
                            const ssize_t n = ::send(fd, bytes + sent, size - sent, MSG_NOSIGNAL);
                            if (n > 0) {
                                sent += static_cast<size_t>(n);
                                continue;
                            }
                            if (n == 0) {
                                return cpl::Err(MakeError(Errors::SendFailed,
                                                          "[X] HttpRequest: send() accepted no data"
                                                              CPL_FILE_AND_LINE));
                            }
                            const int err = errno;
                            if (err == EINTR) {
                                continue;
                            }
                            if (err == EAGAIN) {
                                const auto ready = WaitReady(fd, POLLOUT, deadline, Errors::SendFailed,
                                                             "[X] HttpRequest: sending the request timed out",
                                                             "[X] HttpRequest: poll() failed while sending");
                                if (!ready) {
                                    return cpl::Err(ready.error());
                                }
                                const short revents = ready.value();
                                if ((revents & POLLOUT) == 0 && (revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
                                    return cpl::Err(MakeError(
                                        Errors::SendFailed,
                                        "[X] HttpRequest: the peer closed the connection while the request was sent"
                                            CPL_FILE_AND_LINE));
                                }
                                continue;
                            }
                            return cpl::Err(MakeError(Errors::SendFailed,
                                                      std::string("[X] HttpRequest: send failed: ")
                                                          + SystemErrorText(err) + " " CPL_FILE_AND_LINE));
                        }
                        return true;
                    }

                    // Buffered reader over one non-blocking socket. All reads share the deadline.
                    class SocketReader final {
                    public:
                        SocketReader(const int fd, const Deadline &deadline)
                            : fd_(fd), deadline_(deadline), buffer_(ReadChunkBytes) {
                        }

                        // One LF terminated line without the line end; a trailing CR is dropped.
                        Result<std::string> ReadLine(const size_t limit) {
                            std::string line{};
                            for (;;) {
                                if (pos_ >= end_) {
                                    const auto filled = Fill();
                                    if (!filled) {
                                        return cpl::Err(filled.error());
                                    }
                                    if (!filled.value()) {
                                        return Closed();
                                    }
                                }
                                const auto *begin = buffer_.data() + pos_;
                                const auto *end = buffer_.data() + end_;
                                const auto *lineFeed = static_cast<const uint8_t *>(
                                    std::memchr(begin, '\n', static_cast<size_t>(end - begin)));
                                const size_t available =
                                    static_cast<size_t>((lineFeed != nullptr ? lineFeed : end) - begin);
                                if (line.size() + available > limit) {
                                    return TooLong();
                                }
                                line.append(reinterpret_cast<const char *>(begin), available);
                                pos_ += available + (lineFeed != nullptr ? 1 : 0);
                                if (lineFeed != nullptr) {
                                    if (!line.empty() && line[line.size() - 1] == '\r') {
                                        line.erase(line.size() - 1);
                                    }
                                    return line;
                                }
                            }
                        }

                        // Appends exactly `count` bytes to `out`; `out` never grows past `limit`.
                        Result<bool> ReadAppend(std::vector<uint8_t> &out, uint64_t count, const size_t limit) {
                            while (count > 0) {
                                if (pos_ >= end_) {
                                    const auto filled = Fill();
                                    if (!filled) {
                                        return cpl::Err(filled.error());
                                    }
                                    if (!filled.value()) {
                                        return Closed();
                                    }
                                }
                                const size_t available = end_ - pos_;
                                const size_t take = static_cast<size_t>(count < available ? count : available);
                                if (!Fits(out.size(), take, limit)) {
                                    return TooLarge(limit);
                                }
                                out.insert(out.end(), buffer_.data() + pos_, buffer_.data() + pos_ + take);
                                pos_ += take;
                                count -= take;
                            }
                            return true;
                        }

                        // Appends everything until the peer closes the connection.
                        Result<bool> ReadUntilClose(std::vector<uint8_t> &out, const size_t limit) {
                            for (;;) {
                                if (pos_ >= end_) {
                                    const auto filled = Fill();
                                    if (!filled) {
                                        return cpl::Err(filled.error());
                                    }
                                    if (!filled.value()) {
                                        return true;
                                    }
                                }
                                // Bytes left over from the last line are part of the body.
                                const size_t available = end_ - pos_;
                                if (!Fits(out.size(), available, limit)) {
                                    return TooLarge(limit);
                                }
                                out.insert(out.end(), buffer_.data() + pos_, buffer_.data() + end_);
                                pos_ = end_;
                            }
                        }

                    private:
                        // Reads into the buffer. True when data arrived, false when the peer closed
                        // its end of the connection.
                        Result<bool> Fill() {
                            if (eof_) {
                                return false;
                            }
                            pos_ = 0;
                            end_ = 0;
                            for (;;) {
                                const ssize_t n = ::recv(fd_, buffer_.data(), buffer_.size(), 0);
                                if (n > 0) {
                                    end_ = static_cast<size_t>(n);
                                    return true;
                                }
                                if (n == 0) {
                                    eof_ = true;
                                    return false;
                                }
                                const int err = errno;
                                if (err == EINTR) {
                                    continue;
                                }
                                if (err == ECONNRESET || err == ECONNABORTED || err == ENOTCONN || err == EPIPE) {
                                    return cpl::Err(MakeError(
                                        Errors::IncompleteResponse,
                                        std::string("[X] HttpRequest: the peer reset the connection before "
                                                    "the response was complete: ")
                                            + SystemErrorText(err) + " " CPL_FILE_AND_LINE));
                                }
                                if (err != EAGAIN) {
                                    return cpl::Err(MakeError(Errors::ReceiveFailed,
                                                              std::string("[X] HttpRequest: recv failed: ")
                                                                  + SystemErrorText(err) + " " CPL_FILE_AND_LINE));
                                }
                                const auto ready = WaitReady(fd_, POLLIN, deadline_, Errors::ReceiveTimedOut,
                                                             "[X] HttpRequest: receiving the response timed out",
                                                             "[X] HttpRequest: poll() failed while receiving");
                                if (!ready) {
                                    return cpl::Err(ready.error());
                                }
                            }
                        }

                        static bool Fits(const size_t used, const size_t more, const size_t limit) {
                            return used <= limit && more <= limit - used;
                        }

                        static cpl::Err Closed() {
                            return cpl::Err(MakeError(
                                Errors::IncompleteResponse,
                                "[X] HttpRequest: the connection was closed before the response was complete "
                                    CPL_FILE_AND_LINE));
                        }

                        static cpl::Err TooLong() {
                            return cpl::Err(MakeError(
                                Errors::MalformedResponse,
                                "[X] HttpRequest: a line of the response is longer than allowed "
                                    CPL_FILE_AND_LINE));
                        }

                        static cpl::Err TooLarge(const size_t limit) {
                            return cpl::Err(MakeError(
                                Errors::BodyTooLarge,
                                std::string("[X] HttpRequest: the body of the response is larger than "
                                            "maxBodyBytes (")
                                    + Decimal(limit) + " bytes) " CPL_FILE_AND_LINE));
                        }

                        int fd_;
                        Deadline deadline_;
                        std::vector<uint8_t> buffer_;
                        size_t pos_ = 0;
                        size_t end_ = 0;
                        bool eof_ = false;
                    };

                    // The parts of a URL that the request needs.
                    struct UrlParts {
                        std::string authority; // host[:port] as written in the URL
                        std::string host; // host without brackets, for name resolution
                        std::string target; // path and query as written, "/" when absent
                        bool numericHost = false;
                        uint16_t port = DefaultHttpPort;
                    };

                    inline cpl::Err InvalidUrl(const char *reason) {
                        return cpl::Err(MakeError(
                            cpl::Error::InvalidArgument,
                            std::string("[X] HttpRequest: ") + reason + " " CPL_FILE_AND_LINE));
                    }

                    // http://host[:port][/path?query], with an IPv6 literal in brackets (RFC 2732).
                    // The rules are those of win32/network.hpp: the scheme must be exactly "http://",
                    // the authority ends at the first '/', everything from there on is sent as it is
                    // and a missing port means 80. Anything else is cpl::Error::InvalidArgument.
                    inline Result<UrlParts> ParseHttpUrl(const std::string &url) {
                        UrlParts parts{};
                        if (url.compare(0, 7, "http://") != 0) {
                            return InvalidUrl(
                                "the URL must start with http:// (https and other schemes are not supported)");
                        }
                        const auto slash = url.find('/', 7);
                        parts.authority = url.substr(7, slash == std::string::npos ? std::string::npos : slash - 7);
                        parts.target = slash == std::string::npos ? "/" : url.substr(slash);
                        if (parts.authority.empty()) {
                            return InvalidUrl("the URL has no host");
                        }
                        for (size_t i = 0; i < parts.target.size(); i++) {
                            const auto raw = static_cast<unsigned char>(parts.target[i]);
                            if (raw <= 0x20 || raw == 0x7f) {
                                return InvalidUrl("the path of the URL contains a space or a control character");
                            }
                        }

                        std::string portText{};
                        bool hasPort = false;
                        if (parts.authority[0] == '[') {
                            const auto close = parts.authority.find(']');
                            if (close == std::string::npos || close < 2) {
                                return InvalidUrl("the URL contains an invalid IPv6 literal");
                            }
                            parts.host = parts.authority.substr(1, close - 1);
                            const std::string rest = parts.authority.substr(close + 1);
                            if (!rest.empty() && rest[0] != ':') {
                                return InvalidUrl("the URL contains an invalid IPv6 literal");
                            }
                            hasPort = !rest.empty();
                            portText = hasPort ? rest.substr(1) : std::string();
                            parts.numericHost = true;
                        } else {
                            const auto colon = parts.authority.find(':');
                            hasPort = colon != std::string::npos;
                            parts.host = hasPort ? parts.authority.substr(0, colon) : parts.authority;
                            portText = hasPort ? parts.authority.substr(colon + 1) : std::string();
                        }
                        if (parts.host.empty()) {
                            return InvalidUrl("the URL has no host");
                        }
                        for (size_t i = 0; i < parts.host.size(); i++) {
                            const char c = parts.host[i];
                            const bool allowed = parts.numericHost
                                                     ? (IsHexDigit(c) || c == ':' || c == '.')
                                                     : IsHostChar(c);
                            if (!allowed) {
                                return InvalidUrl("the host of the URL contains an invalid character");
                            }
                        }
                        if (!parts.numericHost) {
                            parts.numericHost = IsNumericAddress(parts.host);
                        }
                        uint64_t port = 0;
                        if (hasPort && (portText.empty() || portText.size() > 5 || !ParseDecimal(portText, port)
                                        || port == 0 || port > 65535)) {
                            return InvalidUrl("the port of the URL must be a number from 1 to 65535");
                        }
                        if (hasPort) {
                            parts.port = static_cast<uint16_t>(port);
                        }
                        return parts;
                    }

                    // HTTP/1.x SP NNN [ SP reason ]
                    inline bool ParseStatusLine(const std::string &line, int &status) {
                        if (line.compare(0, 7, "HTTP/1.") != 0 || line.size() < 12 || !IsDigit(line[7])) {
                            return false;
                        }
                        size_t position = 8;
                        if (line[position] != ' ') {
                            return false;
                        }
                        while (position < line.size() && line[position] == ' ') {
                            position++;
                        }
                        if (position + 3 > line.size() || !IsDigit(line[position]) || !IsDigit(line[position + 1])
                            || !IsDigit(line[position + 2])) {
                            return false;
                        }
                        status = (line[position] - '0') * 100 + (line[position + 1] - '0') * 10
                                 + (line[position + 2] - '0');
                        position += 3;
                        return status >= 100 && (position == line.size() || line[position] == ' '
                                                 || line[position] == '\t');
                    }

                    inline cpl::Err BadResponse(const char *reason) {
                        return cpl::Err(MakeError(
                            Errors::MalformedResponse,
                            std::string("[X] HttpRequest: ") + reason + " " CPL_FILE_AND_LINE));
                    }

                    inline cpl::Err BodyTooLarge(const size_t limit) {
                        return cpl::Err(MakeError(
                            Errors::BodyTooLarge,
                            std::string("[X] HttpRequest: the body of the response is larger than maxBodyBytes (")
                                + Decimal(limit) + " bytes) " CPL_FILE_AND_LINE));
                    }

                    struct HeadInfo {
                        bool hasContentLength = false;
                        bool hasTransferEncoding = false;
                        bool chunked = false;
                        uint64_t contentLength = 0;
                    };

                    // Reads the header lines up to the blank line into `headers`.
                    inline Result<bool> ReadHeaders(SocketReader &reader, size_t &headBytes,
                                                    std::vector<std::pair<std::string, std::string> > &headers) {
                        for (;;) {
                            if (headBytes + 2 > MaxHeadBytes) {
                                return BadResponse("the header block of the response exceeds 16384 bytes");
                            }
                            auto line = reader.ReadLine(MaxHeadBytes - headBytes - 2);
                            if (!line) {
                                return cpl::Err(line.error());
                            }
                            headBytes += line.value().size() + 2;
                            if (line.value().empty()) {
                                return true;
                            }
                            if (IsSpace(line.value()[0])) {
                                // obs-fold: the value of the previous header continues on this line
                                if (headers.empty()) {
                                    return BadResponse("a header line of the response continues nothing");
                                }
                                headers.back().second += ' ';
                                headers.back().second += TrimSpaces(line.value().substr(1));
                                continue;
                            }
                            const auto colon = line.value().find(':');
                            std::string name = colon == std::string::npos ? std::string() : line.value().substr(0, colon);
                            for (size_t i = 0; i < name.size(); i++) {
                                name[i] = LowerAscii(name[i]);
                            }
                            if (name.empty() || name.find_first_of(" \t") != std::string::npos) {
                                return BadResponse("a header line of the response has an invalid name");
                            }
                            headers.emplace_back(name, TrimSpaces(line.value().substr(colon + 1)));
                        }
                    }

                    // Takes the framing information from the response headers.
                    inline Result<bool> InspectHead(const std::vector<std::pair<std::string, std::string> > &headers,
                                                    HeadInfo &info) {
                        std::string codings{};
                        for (size_t i = 0; i < headers.size(); i++) {
                            if (headers[i].first == "content-length") {
                                uint64_t length = 0;
                                if (!ParseDecimal(headers[i].second, length)) {
                                    return BadResponse(
                                        "the Content-Length header of the response is not a non-negative number");
                                }
                                if (info.hasContentLength && info.contentLength != length) {
                                    return BadResponse("the response carries conflicting Content-Length headers");
                                }
                                info.hasContentLength = true;
                                info.contentLength = length;
                            } else if (headers[i].first == "transfer-encoding") {
                                info.hasTransferEncoding = true;
                                if (!codings.empty()) {
                                    codings += ',';
                                }
                                codings += headers[i].second;
                            }
                        }
                        info.chunked = info.hasTransferEncoding && EndsChunked(codings);
                        return true;
                    }

                    // Chunked transfer coding: chunk-size [; extension] CRLF data CRLF. The last
                    // chunk has size 0 and is followed by the trailer section and a blank line.
                    inline Result<bool> ReadChunkedBody(SocketReader &reader, std::vector<uint8_t> &body,
                                                        const size_t maxBodyBytes) {
                        for (;;) {
                            auto sizeLine = reader.ReadLine(MaxChunkLineBytes);
                            if (!sizeLine) {
                                return cpl::Err(sizeLine.error());
                            }
                            uint64_t chunkSize = 0;
                            if (!ParseChunkSize(sizeLine.value(), chunkSize)) {
                                return BadResponse("a chunk size line of the response is invalid");
                            }
                            if (chunkSize == 0) {
                                for (;;) {
                                    auto trailer = reader.ReadLine(MaxChunkLineBytes);
                                    if (!trailer) {
                                        return cpl::Err(trailer.error());
                                    }
                                    if (trailer.value().empty()) {
                                        return true;
                                    }
                                }
                            }
                            if (chunkSize > maxBodyBytes - body.size()) {
                                return BodyTooLarge(maxBodyBytes);
                            }
                            const auto appended = reader.ReadAppend(body, chunkSize, maxBodyBytes);
                            if (!appended) {
                                return cpl::Err(appended.error());
                            }
                            auto terminator = reader.ReadLine(MaxChunkLineBytes);
                            if (!terminator) {
                                return cpl::Err(terminator.error());
                            }
                            if (!terminator.value().empty()) {
                                return BadResponse("a chunk of the response is not followed by CRLF");
                            }
                        }
                    }

                    // Reads one whole response. The result object is filled in place, so that a large
                    // body is never copied on the way out.
                    inline Result<HttpResponse> ReadResponse(SocketReader &reader, const bool bodyless,
                                                             const size_t maxBodyBytes) {
                        Result<HttpResponse> result(tl::in_place);
                        HttpResponse &response = *result;
                        for (unsigned int interim = 0;; interim++) {
                            size_t headBytes = 0;
                            auto statusLine = reader.ReadLine(MaxHeadBytes - 2);
                            if (!statusLine) {
                                return cpl::Err(statusLine.error());
                            }
                            headBytes = statusLine.value().size() + 2;
                            if (!ParseStatusLine(statusLine.value(), response.status)) {
                                return BadResponse(
                                    "the status line of the response is not \"HTTP/1.x NNN reason\"");
                            }
                            const auto read = ReadHeaders(reader, headBytes, response.headers);
                            if (!read) {
                                return cpl::Err(read.error());
                            }
                            if (response.status >= 200) {
                                break;
                            }
                            // 1xx: an interim response has no body; the final response follows.
                            response.headers.clear();
                            if (interim + 1 >= MaxInterimResponses) {
                                return BadResponse("the response consists of nothing but interim responses");
                            }
                        }
                        // 1xx, 204, 304 and the answer to a HEAD carry no body whatever the headers say.
                        if (bodyless || response.status == 204 || response.status == 304) {
                            return result;
                        }
                        HeadInfo info{};
                        const auto inspected = InspectHead(response.headers, info);
                        if (!inspected) {
                            return cpl::Err(inspected.error());
                        }
                        Result<bool> read = true;
                        if (info.chunked) {
                            read = ReadChunkedBody(reader, response.body, maxBodyBytes);
                        } else if (info.hasTransferEncoding) {
                            return BadResponse("the response uses a transfer encoding that is not chunked");
                        } else if (info.hasContentLength) {
                            if (info.contentLength > maxBodyBytes) {
                                return BodyTooLarge(maxBodyBytes);
                            }
                            read = reader.ReadAppend(response.body, info.contentLength, maxBodyBytes);
                        } else {
                            read = reader.ReadUntilClose(response.body, maxBodyBytes);
                        }
                        if (!read) {
                            return cpl::Err(read.error());
                        }
                        return result;
                    }

                    inline std::string BuildRequest(const std::string &verb, const UrlParts &url,
                                                    const Stream &body, const HttpOptions &options,
                                                    const bool withoutBody) {
                        std::string request{};
                        request.reserve(128 + url.target.size() + url.authority.size());
                        request += verb;
                        request += ' ';
                        request += url.target;
                        request += " HTTP/1.1\r\n";
                        request += "Host: ";
                        request += url.authority;
                        request += "\r\n";
                        request += "User-Agent: ifw\r\n";
                        request += "Connection: close\r\n";
                        if (options.contentType != nullptr && options.contentType[0] != '\0') {
                            request += "Content-Type: ";
                            request += options.contentType;
                            request += "\r\n";
                        }
                        if (!withoutBody) {
                            // Also 0 for a POST without a payload: many servers insist on the header.
                            request += "Content-Length: ";
                            request += Decimal(body.size());
                            request += "\r\n";
                        }
                        request += "\r\n";
                        return request;
                    }

                    inline uint64_t TimeoutOrDefault(const uint32_t given, const uint32_t fallback) {
                        return given != 0 ? given : fallback;
                    }

                    inline Result<HttpResponse> HttpRequestImpl(const std::string &url, const Stream &body,
                                                                const char *method, const HttpOptions &options) {
                        // The method is used as given, in upper case.
                        if (method == nullptr || method[0] == '\0') {
                            return cpl::MakeErr(cpl::Error::InvalidArgument,
                                                "[X] HttpRequest: the method is empty " CPL_FILE_AND_LINE);
                        }
                        std::string verb{};
                        for (const char *p = method; *p != '\0'; p++) {
                            if (!IsTokenChar(*p)) {
                                return cpl::MakeErr(
                                    cpl::Error::InvalidArgument,
                                    "[X] HttpRequest: the method contains a character that is not allowed in an HTTP token "
                                        CPL_FILE_AND_LINE);
                            }
                            verb.push_back(UpperAscii(*p));
                        }
                        const bool withoutBody = verb == "GET"; // a GET never carries a body
                        if (options.contentType != nullptr) {
                            for (const char *p = options.contentType; *p != '\0'; p++) {
                                if (!IsHeaderText(*p)) {
                                    return cpl::MakeErr(
                                        cpl::Error::InvalidArgument,
                                        "[X] HttpRequest: the content type contains a control character "
                                            CPL_FILE_AND_LINE);
                                }
                            }
                        }

                        const auto parsed = ParseHttpUrl(url);
                        if (!parsed) {
                            return cpl::Err(parsed.error());
                        }

                        // Name resolution: IPv4 and IPv6, tried in order until one connects.
                        struct addrinfo *addresses = nullptr;
                        const auto releaseAddresses = cpl::base::MakeDefer([&addresses] {
                            if (addresses != nullptr) {
                                ::freeaddrinfo(addresses);
                            }
                        });
                        const auto resolved = Resolve(parsed->host, parsed->port, parsed->numericHost, SOCK_STREAM,
                                                      "HttpRequest");
                        if (!resolved) {
                            return cpl::Err(resolved.error());
                        }
                        addresses = resolved.value();

                        // One deadline bounds the attempts of all addresses together.
                        const HttpOptions defaults{};
                        const auto connectDeadline = Deadline::AfterMilliseconds(
                            TimeoutOrDefault(options.connectTimeoutMs, defaults.connectTimeoutMs));
                        UniqueFd socket{};
                        cpl::Error lastError{};
                        bool attempted = false;
                        for (const struct addrinfo *ai = addresses; ai != nullptr; ai = ai->ai_next) {
                            if ((ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
                                || ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
                                continue;
                            }
                            attempted = true;
                            socket.Reset(::socket(ai->ai_family, SOCK_STREAM, 0));
                            Result<bool> connected = cpl::Err(MakeError(
                                Errors::ConnectFailed,
                                std::string("[X] HttpRequest: socket() failed: ") + SystemErrorText(errno) + " "
                                    CPL_FILE_AND_LINE));
                            if (socket.Get() >= 0) {
                                if (ConfigureSocket(socket.Get())) {
                                    connected = ConnectSocket(socket.Get(), ai->ai_addr, ai->ai_addrlen,
                                                              connectDeadline);
                                } else {
                                    connected = cpl::Err(MakeError(
                                        Errors::ConnectFailed,
                                        std::string("[X] HttpRequest: fcntl() failed: ") + SystemErrorText(errno)
                                            + " " CPL_FILE_AND_LINE));
                                }
                            }
                            if (connected) {
                                break;
                            }
                            lastError = connected.error();
                            socket.Reset();
                        }
                        if (!attempted) {
                            return cpl::Err(MakeError(Errors::ResolveFailed,
                                                      std::string("[X] HttpRequest: no address found for \"")
                                                          + parsed->host + "\" " CPL_FILE_AND_LINE));
                        }
                        if (socket.Get() < 0) {
                            return cpl::Err(lastError);
                        }

                        const auto sendDeadline = Deadline::AfterMilliseconds(
                            TimeoutOrDefault(options.sendTimeoutMs, defaults.sendTimeoutMs));
                        const std::string request = BuildRequest(verb, *parsed, body, options, withoutBody);
                        const auto sentHead = SendAll(socket.Get(), request.data(), request.size(), sendDeadline);
                        if (!sentHead) {
                            return cpl::Err(sentHead.error());
                        }
                        if (!withoutBody && !body.empty()) {
                            const auto sentBody = SendAll(socket.Get(), body.data(), body.size(), sendDeadline);
                            if (!sentBody) {
                                return cpl::Err(sentBody.error());
                            }
                        }

                        SocketReader reader(socket.Get(), Deadline::AfterMilliseconds(
                                                   TimeoutOrDefault(options.recvTimeoutMs, defaults.recvTimeoutMs)));
                        return ReadResponse(reader, verb == "HEAD", options.maxBodyBytes);
                    }

                    inline bool SetSendTimeout(const int fd, const int64_t milliseconds) {
                        struct timeval timeout{};
                        timeout.tv_sec = static_cast<time_t>(milliseconds / 1000);
                        timeout.tv_usec = static_cast<suseconds_t>((milliseconds % 1000) * 1000);
                        return ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
                    }

                    // One whole datagram to one address, over a blocking socket with SO_SNDTIMEO. A
                    // signal restarts the call with the time that is left.
                    inline Result<bool> SendDatagramTo(const int fd, const Stream &data,
                                                       const struct sockaddr *address, const socklen_t addressLength,
                                                       const uint32_t timeoutMs, const Deadline &deadline) {
                        for (;;) {
                            const ssize_t sent =
                                ::sendto(fd, data.data(), data.size(), MSG_NOSIGNAL, address, addressLength);
                            if (sent == static_cast<ssize_t>(data.size())) {
                                return true;
                            }
                            const int err = errno;
                            if (sent >= 0) {
                                return cpl::Err(MakeError(Errors::SendFailed,
                                                          "[X] UdpSend: the datagram was sent only partly "
                                                              CPL_FILE_AND_LINE));
                            }
                            if (err == EINTR || err == EAGAIN) {
                                const int64_t left = deadline.RemainingMilliseconds();
                                if (left <= 0) {
                                    return cpl::Err(MakeError(
                                        Errors::SendFailed,
                                        std::string("[X] UdpSend: sending the datagram timed out after ")
                                            + Decimal(timeoutMs) + " ms " CPL_FILE_AND_LINE));
                                }
                                if (timeoutMs != 0 && !SetSendTimeout(fd, left)) {
                                    return cpl::Err(MakeError(
                                        Errors::SendFailed,
                                        std::string("[X] UdpSend: setsockopt(SO_SNDTIMEO) failed: ")
                                            + SystemErrorText(errno) + " " CPL_FILE_AND_LINE));
                                }
                                continue;
                            }
                            return cpl::Err(MakeError(Errors::SendFailed,
                                                      std::string("[X] UdpSend: sendto() failed: ")
                                                          + SystemErrorText(err) + " " CPL_FILE_AND_LINE));
                        }
                    }

                    inline Int32Result UdpSendImpl(const std::string &host, const uint16_t port,
                                                   const Stream &data, const uint32_t timeoutMs) {
                        if (data.empty()) {
                            return cpl::MakeErr(cpl::Error::InvalidArgument,
                                                "[X] UdpSend: the datagram is empty " CPL_FILE_AND_LINE);
                        }
                        if (data.size() > MaxUdpDatagramBytes) {
                            return cpl::MakeErr(
                                cpl::Error::InvalidArgument,
                                "[X] UdpSend: the datagram is larger than 65507 bytes, the largest UDP payload "
                                    CPL_FILE_AND_LINE);
                        }
                        if (port == 0) {
                            return cpl::MakeErr(cpl::Error::InvalidArgument,
                                                "[X] UdpSend: the port must not be 0 " CPL_FILE_AND_LINE);
                        }
                        std::string name = host;
                        // An IPv6 address may be given in brackets, as in a URL.
                        if (name.size() >= 2 && name[0] == '[' && name[name.size() - 1] == ']') {
                            name = name.substr(1, name.size() - 2);
                        }
                        if (name.empty()) {
                            return cpl::MakeErr(cpl::Error::InvalidArgument,
                                                "[X] UdpSend: the host is empty " CPL_FILE_AND_LINE);
                        }

                        struct addrinfo *addresses = nullptr;
                        const auto releaseAddresses = cpl::base::MakeDefer([&addresses] {
                            if (addresses != nullptr) {
                                ::freeaddrinfo(addresses);
                            }
                        });
                        const auto resolved = Resolve(name, port, IsNumericAddress(name), SOCK_DGRAM, "UdpSend");
                        if (!resolved) {
                            return cpl::Err(resolved.error());
                        }
                        addresses = resolved.value();

                        // The first address that accepts the datagram wins. Zero disables the timeout.
                        const auto deadline = Deadline::AfterMilliseconds(timeoutMs);
                        cpl::Error lastError{};
                        bool attempted = false;
                        for (const struct addrinfo *ai = addresses; ai != nullptr; ai = ai->ai_next) {
                            if ((ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
                                || ai->ai_addrlen > sizeof(struct sockaddr_storage)) {
                                continue;
                            }
                            attempted = true;
                            UniqueFd socket{};
                            socket.Reset(::socket(ai->ai_family, SOCK_DGRAM, 0));
                            Result<bool> sent = cpl::Err(MakeError(
                                Errors::SendFailed,
                                std::string("[X] UdpSend: socket() failed: ") + SystemErrorText(errno) + " "
                                    CPL_FILE_AND_LINE));
                            if (socket.Get() >= 0) {
                                if (timeoutMs == 0 || SetSendTimeout(socket.Get(), timeoutMs)) {
                                    sent = SendDatagramTo(socket.Get(), data, ai->ai_addr, ai->ai_addrlen,
                                                          timeoutMs, deadline);
                                } else {
                                    sent = cpl::Err(MakeError(
                                        Errors::SendFailed,
                                        std::string("[X] UdpSend: setsockopt(SO_SNDTIMEO) failed: ")
                                            + SystemErrorText(errno) + " " CPL_FILE_AND_LINE));
                                }
                            }
                            if (sent) {
                                return static_cast<int32_t>(0);
                            }
                            lastError = sent.error();
                        }
                        if (!attempted) {
                            return cpl::Err(MakeError(Errors::ResolveFailed,
                                                      std::string("[X] UdpSend: no address found for \"")
                                                          + name + "\" " CPL_FILE_AND_LINE));
                        }
                        return cpl::Err(lastError);
                    }
                } // namespace impl

                // Performs one plain HTTP request and returns the response. A status code of 400 or
                // 500 is a successful result (with the body); only transport and protocol problems
                // are errors. The call returns after connectTimeoutMs + sendTimeoutMs + recvTimeoutMs
                // at the latest, plus whatever name resolution takes.
                inline Result<HttpResponse> HttpRequest(const std::string &url, const Stream &body,
                                                        const char *method = "POST",
                                                        const HttpOptions &options = HttpOptions()) {
                    try {
                        return impl::HttpRequestImpl(url, body, method, options);
                    } catch (const std::bad_alloc &) {
                        return impl::ExceptionCaught(cpl::Error::OutOfMemory, "[X] HttpRequest: out of memory");
                    } catch (const std::exception &e) {
                        return impl::ExceptionCaught(Errors::InternalError, e, "HttpRequest");
                    } catch (...) {
                        return impl::ExceptionCaught(Errors::InternalError, "[X] HttpRequest: unknown exception");
                    }
                }

                // Sends one UDP datagram to `host`: a dotted IPv4 address, an IPv6 address (with or
                // without brackets) or a name. A timeout of zero disables the send timeout.
                inline Int32Result UdpSend(const std::string &host, const uint16_t port, const Stream &data,
                                           const uint32_t timeoutMs = 5000) {
                    try {
                        return impl::UdpSendImpl(host, port, data, timeoutMs);
                    } catch (const std::bad_alloc &) {
                        return impl::ExceptionCaught(cpl::Error::OutOfMemory, "[X] UdpSend: out of memory");
                    } catch (const std::exception &e) {
                        return impl::ExceptionCaught(Errors::InternalError, e, "UdpSend");
                    } catch (...) {
                        return impl::ExceptionCaught(Errors::InternalError, "[X] UdpSend: unknown exception");
                    }
                }
            } // namespace wrapper
        } // namespace network
    } // namespace sys
} // namespace cpl

#endif // CPL_POSIX_NETWORK_HPP_LANTERN_QUIET_HARBOR_STEADY_CURRENT_AMBER_MEADOW_FROST_SIGNAL
#endif // !_WIN32
