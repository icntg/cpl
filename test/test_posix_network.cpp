#if !defined(_WIN32)
/*
 * Unit tests of cpl::sys::network::wrapper on POSIX (posix/network.hpp).
 *
 * Every case starts a scripted TCP server or a UDP receiver on a thread of this
 * process, bound to the loopback interface on an ephemeral port, so nothing
 * depends on the network. All threads are joined before a case ends and no
 * blocking call of the helpers waits longer than a few seconds. The whole file
 * is skipped on Windows.
 */
#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "../vendor/doctest/doctest.hpp"
#include "../base.hpp"

#include "../posix/network.hpp"

// A signal handler; it does nothing, the interruption itself is the point.
extern "C" void CplPosixNetworkInterruptHandler(int) {
}

namespace {

    using cpl::Int32Result;
    using cpl::Stream;
    using cpl::sys::network::wrapper::Errors;
    using cpl::sys::network::wrapper::HttpOptions;
    using cpl::sys::network::wrapper::HttpRequest;
    using cpl::sys::network::wrapper::HttpResponse;
    using cpl::sys::network::wrapper::UdpSend;

    typedef std::chrono::steady_clock Clock;

    const int SafetyTimeoutMs = 5000; // no blocking call of the helpers waits longer
    const int ServerHoldMs = 3000; // how long a server keeps a connection open

    // ------------------------------------------------------------------ text

    std::string Decimal(const uint64_t value) {
        char text[32]{};
        std::snprintf(text, sizeof(text), "%llu", static_cast<unsigned long long>(value));
        return std::string(text);
    }

    std::string HexDecimal(const uint64_t value) {
        char text[32]{};
        std::snprintf(text, sizeof(text), "%llX", static_cast<unsigned long long>(value));
        return std::string(text);
    }

    std::string StreamText(const Stream &data) {
        return std::string(data.begin(), data.end());
    }

    // Deterministic bytes for payloads: every byte value occurs.
    Stream Pattern(const size_t size, const unsigned int salt) {
        Stream data(size);
        for (size_t i = 0; i < size; i++) {
            data[i] = static_cast<uint8_t>((i * 31 + salt * 7 + 11) & 0xff);
        }
        return data;
    }

    // FNV-1a, to compare large payloads without keeping a second copy of them.
    uint64_t Digest(const std::string &data) {
        uint64_t hash = 0xcbf29ce484222325ull;
        for (size_t i = 0; i < data.size(); i++) {
            hash ^= static_cast<unsigned char>(data[i]);
            hash *= 0x100000001b3ull;
        }
        return hash;
    }

    std::string Trim(const std::string &text) {
        const size_t first = text.find_first_not_of(" \t");
        if (first == std::string::npos) {
            return std::string();
        }
        return text.substr(first, text.find_last_not_of(" \t") - first + 1);
    }

    char UpperAscii(const char c) {
        return static_cast<char>(c >= 'a' && c <= 'z' ? c - 'a' + 'A' : c);
    }

    bool SameName(const std::string &left, const char *right) {
        if (left.size() != std::strlen(right)) {
            return false;
        }
        for (size_t i = 0; i < left.size(); i++) {
            if (UpperAscii(left[i]) != UpperAscii(right[i])) {
                return false;
            }
        }
        return true;
    }

    // True when a header line of the raw header block has the name `name`.
    bool HeaderPresent(const std::string &head, const char *name) {
        size_t position = 0;
        while (position < head.size()) {
            const size_t lineEnd = head.find("\r\n", position);
            const size_t end = lineEnd == std::string::npos ? head.size() : lineEnd;
            const std::string line = head.substr(position, end - position);
            const auto colon = line.find(':');
            if (colon != std::string::npos && SameName(line.substr(0, colon), name)) {
                return true;
            }
            if (lineEnd == std::string::npos) {
                break;
            }
            position = end + 2;
        }
        return false;
    }

    // Value of the first header `name` of a raw header block, or empty.
    std::string HeaderValue(const std::string &head, const char *name) {
        size_t position = 0;
        while (position < head.size()) {
            const size_t lineEnd = head.find("\r\n", position);
            const size_t end = lineEnd == std::string::npos ? head.size() : lineEnd;
            const std::string line = head.substr(position, end - position);
            const auto colon = line.find(':');
            if (colon != std::string::npos && SameName(line.substr(0, colon), name)) {
                return Trim(line.substr(colon + 1));
            }
            if (lineEnd == std::string::npos) {
                break;
            }
            position = end + 2;
        }
        return std::string();
    }

    // Value of the first response header with the lower case `name`, or empty.
    std::string HeaderOf(const HttpResponse &response, const char *name) {
        for (size_t i = 0; i < response.headers.size(); i++) {
            if (response.headers[i].first == name) {
                return response.headers[i].second;
            }
        }
        return std::string();
    }

    // Prints control characters as text, so that failures are readable.
    std::string Escaped(const std::string &text) {
        static const char *digits = "0123456789abcdef";
        std::string out{};
        for (size_t i = 0; i < text.size(); i++) {
            const auto raw = static_cast<unsigned char>(text[i]);
            if (raw == '\r') {
                out += "\\r";
            } else if (raw == '\n') {
                out += "\\n";
            } else if (raw == 0) {
                out += "\\0";
            } else if (raw == '\t') {
                out += "\\t";
            } else if (raw < 0x20 || raw >= 0x7f) {
                out += "\\x";
                out += digits[raw >> 4];
                out += digits[raw & 0x0f];
            } else {
                out += static_cast<char>(raw);
            }
        }
        return out;
    }

    std::string HexOf(const Stream &data) {
        static const char *digits = "0123456789abcdef";
        std::string out = Decimal(data.size()) + " bytes:";
        for (size_t i = 0; i < data.size() && i < 48; i++) {
            out += digits[data[i] >> 4];
            out += digits[data[i] & 0x0f];
        }
        return out;
    }

    int64_t MillisecondsSince(const Clock::time_point &start) {
        return std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - start).count();
    }

    int64_t MillisecondsUntil(const Clock::time_point &end) {
        return -MillisecondsSince(end);
    }

    void SleepMs(const int milliseconds) {
        std::this_thread::sleep_for(std::chrono::milliseconds(milliseconds));
    }

    // True when the reason of an error ends with the file and line of its origin.
    bool HasLocation(const cpl::Error &error) {
        return !error.Reason.empty() && error.Reason[error.Reason.size() - 1] == '>'
               && error.Reason.find("posix/network.hpp:") != std::string::npos;
    }

    // The result must be the error `code`, with a reason that names file and line.
    void ExpectError(const cpl::Error &error, const int64_t code) {
        CHECK_EQ(error.Code.i64, code);
        CHECK_MESSAGE(HasLocation(error), "reason: " << error.Reason);
    }

    void CheckBody(const Stream &actual, const std::string &expected) {
        const Stream wanted(expected.begin(), expected.end());
        CHECK_MESSAGE(actual == wanted, HexOf(actual) << " instead of " << HexOf(wanted));
    }

    // Describes a result for failure messages. Never touches error() of a successful result.
    std::string Describe(const cpl::Result<HttpResponse> &response) {
        if (!response.has_value()) {
            return "error " + HexDecimal(static_cast<uint64_t>(response.error().Code.i64)) + ": "
                   + response.error().Reason;
        }
        return "status " + Decimal(static_cast<uint64_t>(response.value().status)) + ", "
               + Decimal(response.value().body.size()) + " body bytes";
    }

    // ---------------------------------------------------------------- sockets

    class UniqueFd {
    public:
        UniqueFd() = default;

        explicit UniqueFd(const int fd) : fd_(fd) {
        }

        ~UniqueFd() {
            Reset();
        }

        UniqueFd(const UniqueFd &) = delete;

        UniqueFd &operator=(const UniqueFd &) = delete;

        UniqueFd(UniqueFd &&other) noexcept : fd_(other.fd_) {
            other.fd_ = -1;
        }

        UniqueFd &operator=(UniqueFd &&other) noexcept {
            if (this != &other) {
                Reset();
                fd_ = other.fd_;
                other.fd_ = -1;
            }
            return *this;
        }

        int Get() const {
            return fd_;
        }

        void Reset(const int fd = -1) {
            if (fd_ >= 0) {
                ::close(fd_);
            }
            fd_ = fd;
        }

    private:
        int fd_ = -1;
    };

    // Creates a socket of `type` bound to the loopback address `ip`; `wantedPort` 0 lets the
    // system choose an ephemeral port. Returns false when the address cannot be used.
    bool BindLoopback(const std::string &ip, const int type, const bool listen, const uint16_t wantedPort,
                      UniqueFd &sock, uint16_t &port) {
        sock.Reset();
        port = 0;
        const bool isIpv6 = ip.find(':') != std::string::npos;
        UniqueFd fd(::socket(isIpv6 ? AF_INET6 : AF_INET, type, 0));
        if (fd.Get() < 0) {
            return false;
        }
        uint16_t actual = 0;
        if (isIpv6) {
            struct sockaddr_in6 address{};
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(wantedPort);
            if (::inet_pton(AF_INET6, ip.c_str(), &address.sin6_addr) != 1
                || ::bind(fd.Get(), reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) != 0) {
                return false;
            }
            struct sockaddr_in6 bound{};
            socklen_t length = sizeof(bound);
            if (::getsockname(fd.Get(), reinterpret_cast<struct sockaddr *>(&bound), &length) != 0) {
                return false;
            }
            actual = ntohs(bound.sin6_port);
        } else {
            struct sockaddr_in address{};
            address.sin_family = AF_INET;
            address.sin_port = htons(wantedPort);
            if (::inet_pton(AF_INET, ip.c_str(), &address.sin_addr) != 1
                || ::bind(fd.Get(), reinterpret_cast<struct sockaddr *>(&address), sizeof(address)) != 0) {
                return false;
            }
            struct sockaddr_in bound{};
            socklen_t length = sizeof(bound);
            if (::getsockname(fd.Get(), reinterpret_cast<struct sockaddr *>(&bound), &length) != 0) {
                return false;
            }
            actual = ntohs(bound.sin_port);
        }
        if (listen && ::listen(fd.Get(), 8) != 0) {
            return false;
        }
        port = actual;
        sock = std::move(fd);
        return true;
    }

    bool HasIpv6Loopback() {
        UniqueFd fd;
        uint16_t port = 0;
        return BindLoopback("::1", SOCK_STREAM, false, 0, fd, port);
    }

    bool SetSocketTimeouts(const int fd, const int milliseconds) {
        struct timeval timeout{};
        timeout.tv_sec = milliseconds / 1000;
        timeout.tv_usec = (milliseconds % 1000) * 1000;
        return ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0
               && ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) == 0;
    }

    // 1 when the socket is readable, 0 on timeout, -1 on error or hang up.
    int WaitReadable(const int fd, const int timeoutMs) {
        for (;;) {
            struct pollfd descriptor{};
            descriptor.fd = fd;
            descriptor.events = POLLIN;
            const int ready = ::poll(&descriptor, 1, timeoutMs);
            if (ready < 0 && errno == EINTR) {
                continue;
            }
            if (ready <= 0) {
                return ready;
            }
            return (descriptor.revents & POLLIN) != 0 ? 1 : -1;
        }
    }

    // Up to `size` bytes; 0 is the end of the stream, -1 an error or a timeout.
    ssize_t ReceiveSome(const int fd, char *buffer, const size_t size) {
        for (;;) {
            const ssize_t received = ::recv(fd, buffer, size, 0);
            if (received < 0 && errno == EINTR) {
                continue;
            }
            return received;
        }
    }

    bool SendEverything(const int fd, const char *data, const size_t size) {
        size_t sent = 0;
        while (sent < size) {
            const ssize_t n = ::send(fd, data + sent, size - sent, MSG_NOSIGNAL);
            if (n > 0) {
                sent += static_cast<size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR) {
                continue;
            }
            return false;
        }
        return true;
    }

    // Receives one datagram on any of the `count` sockets; false on timeout or error.
    bool ReceiveDatagram(const int *sockets, const int count, Stream &out, const int timeoutMs) {
        const Clock::time_point until = Clock::now() + std::chrono::milliseconds(timeoutMs);
        for (;;) {
            struct pollfd descriptors[2]{};
            descriptors[0].fd = count > 0 ? sockets[0] : -1;
            descriptors[1].fd = count > 1 ? sockets[1] : -1;
            descriptors[0].events = POLLIN;
            descriptors[1].events = POLLIN;
            const int64_t left = MillisecondsUntil(until);
            if (left <= 0) {
                return false;
            }
            const int ready = ::poll(descriptors, static_cast<nfds_t>(count), static_cast<int>(left));
            if (ready < 0 && errno == EINTR) {
                continue;
            }
            if (ready <= 0) {
                return false;
            }
            for (int i = 0; i < count; i++) {
                if ((descriptors[i].revents & POLLIN) == 0) {
                    continue;
                }
                uint8_t buffer[65536];
                const ssize_t received = ::recv(descriptors[i].fd, buffer, sizeof(buffer), 0);
                if (received < 0 && errno == EINTR) {
                    break;
                }
                if (received <= 0) {
                    return false;
                }
                out.assign(buffer, buffer + received);
                return true;
            }
        }
    }

    // Binds UDP sockets for 127.0.0.1 and, when IPv6 is available, ::1 to the same port, so that
    // a datagram to the name "localhost" is caught whatever address the name resolves to first.
    bool BindUdpLoopbackPair(UniqueFd &ipv4, UniqueFd &ipv6, uint16_t &port) {
        port = 0;
        for (int attempt = 0; attempt < 8; attempt++) {
            ipv4.Reset();
            ipv6.Reset();
            uint16_t ipv6Port = 0;
            if (!BindLoopback("::1", SOCK_DGRAM, false, 0, ipv6, ipv6Port)) {
                break;
            }
            uint16_t ipv4Port = 0;
            if (BindLoopback("127.0.0.1", SOCK_DGRAM, false, ipv6Port, ipv4, ipv4Port)) {
                port = ipv6Port;
                return true;
            }
        }
        ipv4.Reset();
        ipv6.Reset();
        return BindLoopback("127.0.0.1", SOCK_DGRAM, false, 0, ipv4, port);
    }

    // The first loopback address that getaddrinfo() returns for `name`, or empty.
    std::string FirstLoopbackAddress(const char *name) {
        struct addrinfo hints{};
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;
        struct addrinfo *addresses = nullptr;
        std::string result;
        if (::getaddrinfo(name, nullptr, &hints, &addresses) == 0) {
            for (const struct addrinfo *ai = addresses; ai != nullptr && result.empty(); ai = ai->ai_next) {
                char text[64]{};
                if (ai->ai_family == AF_INET && ai->ai_addrlen >= static_cast<socklen_t>(sizeof(struct sockaddr_in))) {
                    const auto *address = reinterpret_cast<const struct sockaddr_in *>(ai->ai_addr);
                    if ((ntohl(address->sin_addr.s_addr) >> 24) == 127u
                        && ::inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text)) != nullptr) {
                        result = text;
                    }
                } else if (ai->ai_family == AF_INET6
                           && ai->ai_addrlen >= static_cast<socklen_t>(sizeof(struct sockaddr_in6))) {
                    const auto *address = reinterpret_cast<const struct sockaddr_in6 *>(ai->ai_addr);
                    if (IN6_IS_ADDR_LOOPBACK(&address->sin6_addr)
                        && ::inet_ntop(AF_INET6, &address->sin6_addr, text, sizeof(text)) != nullptr) {
                        result = text;
                    }
                }
            }
            ::freeaddrinfo(addresses);
        }
        return result;
    }

    // ------------------------------------------------------------ test server

    // What the scripted server does, and what it has seen once it is done.
    struct Script {
        std::string response; // raw bytes sent after the request was read
        int pieces = 1; // the response is sent in this many pieces ...
        int pieceDelayMs = 0; // ... with this pause between them
        int readDelayMs = 0; // pause before the server reads the request
        int probeMs = 0; // after the request: listen this long for bytes that must not come
        bool closeAfterResponse = true; // false: keep the connection open until the client closes it
        bool replyWithDigest = false; // answer with a digest of the received body instead
        bool closeAfterAccept = false; // close the connection without reading the request
        // Results; read them once the server thread was joined.
        std::string request; // raw request bytes
        std::string body; // the bytes behind the request head
        bool accepted = false;
        bool requestComplete = false;
        bool responseSent = false;
        std::string failure; // a problem on the server side; empty when all went well
    };

    // Reads the request head and the body that its Content-Length announces. Bytes that arrive
    // although nothing was announced are appended as well when `probeMs` is set.
    void ReadRequest(const int fd, Script &script) {
        if (script.readDelayMs > 0) {
            SleepMs(script.readDelayMs);
        }
        std::string data;
        size_t headEnd = std::string::npos;
        uint64_t length = 0;
        char buffer[65536];
        for (;;) {
            if (headEnd == std::string::npos) {
                headEnd = data.find("\r\n\r\n");
                if (headEnd != std::string::npos) {
                    // The head is complete; without a Content-Length no body follows.
                    const std::string text = HeaderValue(data.substr(0, headEnd), "content-length");
                    if (text.empty()) {
                        break;
                    }
                    length = std::strtoull(text.c_str(), nullptr, 10);
                } else if (data.size() > 1024 * 1024) {
                    break;
                }
            }
            if (headEnd != std::string::npos && data.size() - headEnd - 4 >= length) {
                break;
            }
            const ssize_t received = ReceiveSome(fd, buffer, sizeof(buffer));
            if (received <= 0) {
                break;
            }
            data.append(buffer, static_cast<size_t>(received));
        }
        const bool complete = headEnd != std::string::npos && data.size() - headEnd - 4 >= length;
        if (complete && script.probeMs > 0) {
            const Clock::time_point until = Clock::now() + std::chrono::milliseconds(script.probeMs);
            while (MillisecondsUntil(until) > 0 && WaitReadable(fd, static_cast<int>(MillisecondsUntil(until))) == 1) {
                const ssize_t received = ReceiveSome(fd, buffer, sizeof(buffer));
                if (received <= 0) {
                    break;
                }
                data.append(buffer, static_cast<size_t>(received));
            }
        }
        script.requestComplete = complete;
        script.body = complete ? data.substr(headEnd + 4) : std::string();
        script.request.swap(data);
    }

    void SendResponse(const int fd, Script &script) {
        const std::string &response = script.response;
        const size_t pieces = static_cast<size_t>(script.pieces > 0 ? script.pieces : 1);
        const size_t pieceSize = (response.size() + pieces - 1) / pieces;
        size_t offset = 0;
        while (offset < response.size()) {
            size_t end = offset + pieceSize;
            if (end > response.size() || end < offset) {
                end = response.size();
            }
            if (!SendEverything(fd, response.data() + offset, end - offset)) {
                return; // the client closed the connection early
            }
            offset = end;
            if (script.pieceDelayMs > 0 && offset < response.size()) {
                SleepMs(script.pieceDelayMs);
            }
        }
        script.responseSent = true;
    }

    // Keeps the connection open until the client closes it or the hold time is over.
    void HoldOpen(const int fd) {
        const Clock::time_point until = Clock::now() + std::chrono::milliseconds(ServerHoldMs);
        char buffer[256];
        for (;;) {
            const int64_t left = MillisecondsUntil(until);
            if (left <= 0 || WaitReadable(fd, static_cast<int>(left)) != 1) {
                return;
            }
            if (ReceiveSome(fd, buffer, sizeof(buffer)) <= 0) {
                return;
            }
        }
    }

    // Accepts one connection, reads the request and answers as scripted.
    void Serve(UniqueFd listener, Script &script) {
        try {
            if (WaitReadable(listener.Get(), SafetyTimeoutMs) != 1) {
                script.failure = "no connection arrived";
                return;
            }
            UniqueFd session(::accept(listener.Get(), nullptr, nullptr));
            if (session.Get() < 0) {
                script.failure = "accept() failed";
                return;
            }
            script.accepted = true;
            if (script.closeAfterAccept) {
                return; // the session is closed by its owner
            }
            if (!SetSocketTimeouts(session.Get(), SafetyTimeoutMs)) {
                script.failure = "setsockopt(SO_RCVTIMEO) failed";
                return;
            }
            ReadRequest(session.Get(), script);
            if (script.replyWithDigest) {
                const std::string text = Decimal(script.body.size()) + ":" + HexDecimal(Digest(script.body));
                script.response = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: "
                                  + Decimal(text.size()) + "\r\n\r\n" + text;
            }
            SendResponse(session.Get(), script);
            if (!script.closeAfterResponse) {
                HoldOpen(session.Get());
            }
        } catch (const std::exception &e) {
            script.failure = std::string("exception in the server thread: ") + e.what();
        } catch (...) {
            script.failure = "unknown exception in the server thread";
        }
    }

    // The scripted server of one case, running on its own thread.
    class Server {
    public:
        Server() = default;

        ~Server() {
            Join();
        }

        // Binds the listener and starts the thread. Returns the port, or 0 when the address
        // cannot be used. `script` belongs to the server thread until Join().
        uint16_t Start(const Script &input, const std::string &ip) {
            script = input;
            uint16_t port = 0;
            if (!BindLoopback(ip, SOCK_STREAM, true, 0, listener, port)) {
                return 0;
            }
            thread = std::thread(Serve, std::move(listener), std::ref(script));
            return port;
        }

        void Join() {
            if (thread.joinable()) {
                thread.join();
            }
        }

        Script script;

    private:
        UniqueFd listener;
        std::thread thread;
    };

    // Ends the whole test process when one case hangs: a stuck case must never block a test run.
    class Watchdog {
    public:
        explicit Watchdog(const unsigned int seconds) {
            ::alarm(seconds);
        }

        ~Watchdog() {
            ::alarm(0);
        }

        Watchdog(const Watchdog &) = delete;

        Watchdog &operator=(const Watchdog &) = delete;
    };

    // One request as the test wants it sent.
    struct Call {
        Stream body;
        const char *method = "POST";
        HttpOptions options;
        std::string urlHost = "127.0.0.1"; // as written in the URL
        std::string listenIp = "127.0.0.1"; // where the scripted server listens
        std::string target = "/sensors/abc/?q=1";
    };

    // What a request produced.
    struct Exchange {
        bool started = false; // false when the listener could not be created
        uint16_t port = 0;
        std::string url;
        int64_t elapsedMs = 0;
        cpl::Result<HttpResponse> response{};
        Script observed;
    };

    std::string UrlOf(const std::string &host, const uint16_t port, const std::string &target) {
        const bool ipv6 = host.find(':') != std::string::npos;
        return "http://" + (ipv6 ? "[" + host + "]" : host) + ":" + Decimal(port) + target;
    }

    // Starts the scripted server, sends one request and waits for the server thread.
    Exchange Perform(const Script &input, const Call &call = Call()) {
        Exchange run;
        Server server;
        run.port = server.Start(input, call.listenIp);
        run.started = run.port != 0;
        if (!run.started) {
            return run;
        }
        run.url = UrlOf(call.urlHost, run.port, call.target);
        const Clock::time_point start = Clock::now();
        run.response = HttpRequest(run.url, call.body, call.method, call.options);
        run.elapsedMs = MillisecondsSince(start);
        server.Join();
        run.observed = server.script;
        return run;
    }

    // Signals

    // Raises `signalNumber` in the calling thread every `intervalMs` milliseconds. The handler is
    // installed without SA_RESTART, so the system calls of the thread fail with EINTR.
    class Interrupter {
    public:
        Interrupter(const int signalNumber, const int intervalMs)
            : signal_(signalNumber), stop_(false), target_(pthread_self()), installed_(false) {
            struct sigaction action{};
            action.sa_handler = CplPosixNetworkInterruptHandler;
            sigemptyset(&action.sa_mask);
            action.sa_flags = 0;
            installed_ = ::sigaction(signal_, &action, &previous_) == 0;
            if (installed_) {
                thread_ = std::thread([this, intervalMs] { Tick(intervalMs); });
            }
        }

        ~Interrupter() {
            stop_ = true;
            if (thread_.joinable()) {
                thread_.join();
            }
            if (installed_) {
                ::sigaction(signal_, &previous_, nullptr);
            }
        }

        Interrupter(const Interrupter &) = delete;

        Interrupter &operator=(const Interrupter &) = delete;

        bool Installed() const {
            return installed_;
        }

    private:
        void Tick(const int intervalMs) {
            while (!stop_) {
                SleepMs(intervalMs);
                (void) pthread_kill(target_, signal_);
            }
        }

        int signal_;
        std::atomic<bool> stop_;
        pthread_t target_;
        struct sigaction previous_{};
        bool installed_;
        std::thread thread_;
    };

    // One round of the thread test: a POST with a body, a GET and a datagram, each checked.
    std::string WorkerRound(const int worker, const int round) {
        const Stream payload = Pattern(static_cast<size_t>(500 + worker * 100 + round), static_cast<unsigned int>(worker));
        const std::string answer(4, static_cast<char>('A' + worker));
        Script input{};
        input.response = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n" + answer;
        Call call;
        call.body = payload;
        const Exchange run = Perform(input, call);
        if (!run.started) {
            return "the listener could not be created";
        }
        if (!run.observed.failure.empty() || !run.observed.requestComplete) {
            return "server: " + run.observed.failure;
        }
        if (HeaderValue(run.observed.request, "content-length") != Decimal(payload.size())
            || Digest(run.observed.body) != Digest(StreamText(payload))) {
            return "the POST body arrived damaged";
        }
        if (!run.response.has_value() || StreamText(run.response.value().body) != answer) {
            return "the POST response is wrong";
        }

        call.method = "GET";
        call.body.clear();
        call.target = "/plugins/" + Decimal(static_cast<uint64_t>(worker)) + "/x.so";
        const Exchange get = Perform(input, call);
        if (!get.started || !get.observed.failure.empty() || !get.observed.requestComplete
            || get.observed.request.compare(0, 4, "GET ") != 0 || !get.observed.body.empty()
            || HeaderPresent(get.observed.request, "content-length")
            || !get.response.has_value() || StreamText(get.response.value().body) != answer) {
            return "the GET request or response is wrong";
        }

        UniqueFd receiver;
        uint16_t port = 0;
        if (!BindLoopback("127.0.0.1", SOCK_DGRAM, false, 0, receiver, port)) {
            return "the UDP receiver could not be created";
        }
        const int sockets[1] = {receiver.Get()};
        Stream received;
        if (!UdpSend("127.0.0.1", port, payload).has_value() || !ReceiveDatagram(sockets, 1, received, 2000)
            || received != payload) {
            return "the datagram arrived damaged";
        }
        return std::string();
    }
} // namespace

TEST_SUITE("cpl::posix::network") {

    TEST_CASE("POST: 200 with a Content-Length body and the exact request on the wire") {
        const Watchdog watchdog(30);
        const Stream payload = Pattern(11, 7);
        Script input{};
        input.response = "HTTP/1.1 200 OK\r\n"
                         "Server: cpl-test\r\n"
                         "Content-Type: application/octet-stream\r\n"
                         "Content-Length: 11\r\n"
                         "X-Mixed-Case: Mixed Value\r\n"
                         "Set-Cookie: a=1\r\n"
                         "SET-COOKIE: b=2\r\n"
                         "\r\n";
        input.response.append(reinterpret_cast<const char *>(payload.data()), payload.size());
        input.response += "TRAILING BYTES THAT DO NOT BELONG TO THE BODY";

        Call call;
        call.body = payload;
        const Exchange run = Perform(input, call);
        REQUIRE(run.started);
        CHECK(run.observed.failure.empty());
        CHECK(run.observed.accepted);
        CHECK(run.observed.requestComplete);
        CHECK(run.observed.responseSent);

        std::string expected = "POST /sensors/abc/?q=1 HTTP/1.1\r\n";
        expected += "Host: 127.0.0.1:" + Decimal(run.port) + "\r\n";
        expected += "User-Agent: ifw\r\n";
        expected += "Connection: close\r\n";
        expected += "Content-Type: application/octet-stream\r\n";
        expected += "Content-Length: 11\r\n";
        expected += "\r\n";
        expected.append(reinterpret_cast<const char *>(payload.data()), payload.size());
        CHECK_MESSAGE(Escaped(run.observed.request) == Escaped(expected),
                      Escaped(run.observed.request) << " instead of " << Escaped(expected));

        REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
        const HttpResponse &response = run.response.value();
        CHECK_EQ(response.status, 200);
        CheckBody(response.body, StreamText(payload)); // stops at Content-Length
        REQUIRE_EQ(response.headers.size(), static_cast<size_t>(6));
        CHECK(response.headers[0].first == "server");
        CHECK(response.headers[0].second == "cpl-test");
        CHECK(response.headers[1].first == "content-type");
        CHECK(response.headers[1].second == "application/octet-stream");
        CHECK(response.headers[2].first == "content-length");
        CHECK(response.headers[2].second == "11");
        CHECK(response.headers[3].first == "x-mixed-case"); // the name is lower-cased ...
        CHECK(response.headers[3].second == "Mixed Value"); // ... the value is kept as it is
        CHECK(response.headers[4].first == "set-cookie"); // repeated headers are all kept
        CHECK(response.headers[4].second == "a=1");
        CHECK(response.headers[5].first == "set-cookie");
        CHECK(response.headers[5].second == "b=2");
    }

    TEST_CASE("400 and 500 are successful results that carry the body") {
        const Watchdog watchdog(30);
        const int statuses[] = {400, 403, 404, 413, 500, 502, 503};
        for (size_t i = 0; i < sizeof(statuses) / sizeof(statuses[0]); i++) {
            Script input{};
            input.response = "HTTP/1.1 " + Decimal(static_cast<uint64_t>(statuses[i]))
                             + " whatever the reason is\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\n"
                               "bad request";
            Call call;
            call.body = Pattern(64, 1);
            call.method = "PUT";
            const Exchange run = Perform(input, call);
            REQUIRE(run.started);
            CHECK(run.observed.failure.empty());
            REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
            CHECK_EQ(run.response.value().status, statuses[i]);
            CheckBody(run.response.value().body, "bad request");
            CHECK(HeaderOf(run.response.value(), "content-type") == "text/plain");
        }
    }

    TEST_CASE("chunked body: several chunks, an extension and the final zero chunk") {
        const Watchdog watchdog(30);
        SUBCASE("small chunks, trailers, split delivery") {
            Script input{};
            input.response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
                             "5\r\nHELLO\r\n"
                             "6;name=value\r\n WORLD\r\n"
                             "A\r\n0123456789\r\n"
                             "0\r\nX-Trailer: done\r\n\r\n";
            input.pieces = 8;
            input.pieceDelayMs = 4;
            const Exchange run = Perform(input);
            REQUIRE(run.started);
            CHECK(run.observed.failure.empty());
            REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
            CHECK_EQ(run.response.value().status, 200);
            CheckBody(run.response.value().body, "HELLO WORLD0123456789");
            CHECK(HeaderOf(run.response.value(), "transfer-encoding") == "chunked");
        }
        SUBCASE("a chunk larger than one read buffer of the client, upper case coding and size") {
            std::string big(40000, ' ');
            for (size_t i = 0; i < big.size(); i++) {
                big[i] = static_cast<char>('a' + (i * 7) % 26);
            }
            Script input{};
            input.response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: Chunked\r\n\r\n" + HexDecimal(40000) + "\r\n"
                             + big + "\r\n0\r\n\r\n";
            const Exchange run = Perform(input);
            REQUIRE(run.started);
            REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
            CheckBody(run.response.value().body, big);
        }
        SUBCASE("binary data and a missing trailer section: 0 and the blank line") {
            const Stream bytes = Pattern(300, 3);
            Script input{};
            input.response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n12c\r\n";
            input.response.append(reinterpret_cast<const char *>(bytes.data()), bytes.size());
            input.response += "\r\n0\n\n"; // bare LF line ends are tolerated
            const Exchange run = Perform(input);
            REQUIRE(run.started);
            REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
            CheckBody(run.response.value().body, StreamText(bytes));
        }
    }

    TEST_CASE("no Content-Length: the body ends when the server closes (HTTP/1.0)") {
        const Watchdog watchdog(30);
        Script input{};
        input.response = "HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\nbody until close";
        input.pieces = 4;
        input.pieceDelayMs = 5;
        const Exchange run = Perform(input);
        REQUIRE(run.started);
        CHECK(run.observed.failure.empty());
        REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
        CHECK_EQ(run.response.value().status, 200);
        CheckBody(run.response.value().body, "body until close");

        SUBCASE("an empty body without Content-Length is valid too") {
            Script empty{};
            empty.response = "HTTP/1.0 204 No Content\r\n\r\n";
            const Exchange again = Perform(empty);
            REQUIRE(again.started);
            REQUIRE_MESSAGE(again.response.has_value(), again.response.error().Reason);
            CheckBody(again.response.value().body, "");
        }
    }

    TEST_CASE("a body of 100 KB arrives complete") {
        const Watchdog watchdog(30);
        const Stream bytes = Pattern(100 * 1024, 9);
        Script input{};
        input.response = "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: 102400\r\n\r\n";
        input.response.append(reinterpret_cast<const char *>(bytes.data()), bytes.size());
        input.pieces = 7;
        input.pieceDelayMs = 5;
        const Exchange run = Perform(input);
        REQUIRE(run.started);
        CHECK(run.observed.failure.empty());
        REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
        CHECK_EQ(run.response.value().body.size(), static_cast<size_t>(100) * 1024);
        CHECK(Digest(StreamText(run.response.value().body)) == Digest(StreamText(bytes)));
    }

    TEST_CASE("a body larger than maxBodyBytes is an error") {
        const Watchdog watchdog(30);
        Call call;
        call.options.maxBodyBytes = 1024;
        call.options.recvTimeoutMs = 3000;
        const std::string fourKilobytes(4096, 'x');
        Script input{};
        SUBCASE("declared by Content-Length") {
            input.response = "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n" + fourKilobytes;
        }
        SUBCASE("declared by an absurdly large Content-Length") {
            input.response = "HTTP/1.1 200 OK\r\nContent-Length: 184467440737095516160\r\n\r\n";
        }
        SUBCASE("sent in chunks") {
            input.response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n258\r\n" + std::string(600, 'x')
                             + "\r\n258\r\n" + std::string(600, 'x') + "\r\n0\r\n\r\n";
        }
        SUBCASE("ended by the server closing the connection") {
            input.response = "HTTP/1.0 200 OK\r\n\r\n" + fourKilobytes;
        }
        const Clock::time_point start = Clock::now();
        const Exchange run = Perform(input, call);
        REQUIRE(run.started);
        REQUIRE_FALSE(run.response.has_value());
        ExpectError(run.response.error(), Errors::BodyTooLarge);
        CHECK(MillisecondsSince(start) < 3000); // detected at once, not by the timeout
    }

    TEST_CASE("a malformed response is an error") {
        const Watchdog watchdog(30);
        const char *responses[] = {
            "HTT/1.1 200 OK\r\n\r\n",
            "HTTP/2.0 200 OK\r\n\r\n",
            "HTTP/1.1 20 OK\r\n\r\n",
            "HTTP/1.1 abc OK\r\n\r\n",
            "HTTP/1.1 200OK\r\n\r\n",
            "HTTP/1.1 099 odd\r\n\r\n",
            "garbage\r\n\r\n",
            "HTTP/1.1 200 OK\r\nBroken header line\r\n\r\n",
            "HTTP/1.1 200 OK\r\nContent-Length : 5\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nContent-Length: 5x\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nxyz\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX0\r\n\r\n",
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nanything",
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\n"
            "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
        };
        for (size_t i = 0; i < sizeof(responses) / sizeof(responses[0]); i++) {
            Script input{};
            input.response = responses[i];
            const Exchange run = Perform(input);
            REQUIRE(run.started);
            INFO(i << ": " << Escaped(responses[i]));
            REQUIRE_FALSE(run.response.has_value());
            ExpectError(run.response.error(), Errors::MalformedResponse);
        }
    }

    TEST_CASE("a header block larger than 16 KB is an error") {
        const Watchdog watchdog(30);
        Call call;
        call.options.recvTimeoutMs = 3000;
        Script input{};
        input.response = "HTTP/1.1 200 OK\r\nX-Long: " + std::string(20000, 'a') + "\r\n\r\n";
        const Exchange run = Perform(input, call);
        REQUIRE(run.started);
        REQUIRE_FALSE(run.response.has_value());
        ExpectError(run.response.error(), Errors::MalformedResponse);
        CHECK(run.elapsedMs < 3000);
    }

    TEST_CASE("a connection closed in the middle of the response is an error") {
        const Watchdog watchdog(30);
        Call call;
        call.options.recvTimeoutMs = 3000;
        Script input{};
        SUBCASE("before any byte") {
            input.response = "";
        }
        SUBCASE("inside the status line") {
            input.response = "HTTP/1.1 20";
        }
        SUBCASE("inside the headers") {
            input.response = "HTTP/1.1 200 OK\r\nContent-Ty";
        }
        SUBCASE("inside a Content-Length body") {
            input.response = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\npartial";
        }
        SUBCASE("inside a chunk") {
            input.response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nab";
        }
        SUBCASE("after the last chunk, without the blank line") {
            input.response = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n";
        }
        const Exchange run = Perform(input, call);
        REQUIRE(run.started);
        REQUIRE_FALSE(run.response.has_value());
        ExpectError(run.response.error(), Errors::IncompleteResponse);
        CHECK(run.elapsedMs < 3000); // the end of the stream is seen at once
    }

    TEST_CASE("a closed port is an error") {
        const Watchdog watchdog(30);
        UniqueFd probe;
        uint16_t port = 0;
        REQUIRE(BindLoopback("127.0.0.1", SOCK_STREAM, false, 0, probe, port));
        const uint16_t closedPort = port;
        probe.Reset();
        const auto response = HttpRequest(UrlOf("127.0.0.1", closedPort, "/"), Stream());
        REQUIRE_FALSE(response.has_value());
        ExpectError(response.error(), Errors::ConnectFailed);
    }

    TEST_CASE("a server that never answers: recvTimeoutMs = 300 fails within about one second") {
        const Watchdog watchdog(30);
        Script input{};
        input.response = "";
        input.closeAfterResponse = false; // holds the connection open
        Call call;
        call.options.recvTimeoutMs = 300;
        const Exchange run = Perform(input, call);
        REQUIRE(run.started);
        CHECK(run.observed.failure.empty());
        CHECK(run.observed.requestComplete); // the request did arrive
        REQUIRE_FALSE(run.response.has_value());
        ExpectError(run.response.error(), Errors::ReceiveTimedOut);
        CHECK(run.elapsedMs >= 250); // it did wait for the answer ...
        CHECK(run.elapsedMs < 1000); // ... but only as long as the timeout allows
    }

    TEST_CASE("GET sends no body and the method is upper-cased") {
        const Watchdog watchdog(30);
        Script input{};
        input.response = "HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc";
        input.probeMs = 200; // bytes that are not announced must not turn up
        Call call;
        call.method = "get";
        call.target = "/plugins/x/y.so?v=2";
        call.options.contentType = "application/json";
        const Exchange lower = Perform(input, call);
        REQUIRE(lower.started);
        CHECK(lower.observed.failure.empty());
        REQUIRE(lower.observed.requestComplete);
        std::string expected = "GET /plugins/x/y.so?v=2 HTTP/1.1\r\n";
        expected += "Host: 127.0.0.1:" + Decimal(lower.port) + "\r\n";
        expected += "User-Agent: ifw\r\n";
        expected += "Connection: close\r\n";
        expected += "Content-Type: application/json\r\n";
        expected += "\r\n";
        CHECK_MESSAGE(Escaped(lower.observed.request) == Escaped(expected),
                      Escaped(lower.observed.request) << " instead of " << Escaped(expected));
        REQUIRE_MESSAGE(lower.response.has_value(), Describe(lower.response));
        CheckBody(lower.response.value().body, "abc");

        SUBCASE("a body handed to a GET is not sent") {
            call.method = "GET";
            call.body = Pattern(4096, 5);
            const Exchange again = Perform(input, call);
            REQUIRE(again.started);
            REQUIRE(again.observed.requestComplete);
            expected.replace(expected.find("Host:"), std::string::npos, "Host: 127.0.0.1:" + Decimal(again.port)
                                 + "\r\nUser-Agent: ifw\r\nConnection: close\r\nContent-Type: application/json\r\n\r\n");
            CHECK_MESSAGE(Escaped(again.observed.request) == Escaped(expected),
                          Escaped(again.observed.request) << " instead of " << Escaped(expected));
        }
        SUBCASE("no Content-Type header when the option is null") {
            call.options.contentType = nullptr;
            const Exchange again = Perform(input, call);
            REQUIRE(again.started);
            CHECK_FALSE(HeaderPresent(again.observed.request, "content-type"));
            CHECK_MESSAGE(Escaped(again.observed.request) == Escaped("GET /plugins/x/y.so?v=2 HTTP/1.1\r\nHost: 127.0.0.1:"
                          + Decimal(again.port) + "\r\nUser-Agent: ifw\r\nConnection: close\r\n\r\n"),
                          Escaped(again.observed.request));
        }
        SUBCASE("a POST without a payload announces Content-Length: 0") {
            call.method = "post";
            call.options.contentType = nullptr;
            const Exchange again = Perform(input, call);
            REQUIRE(again.started);
            CHECK_MESSAGE(Escaped(again.observed.request) == Escaped("POST /plugins/x/y.so?v=2 HTTP/1.1\r\nHost: 127.0.0.1:"
                          + Decimal(again.port)
                          + "\r\nUser-Agent: ifw\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"),
                          Escaped(again.observed.request));
        }
    }

    TEST_CASE("204, 304 and HEAD have no body even while the connection stays open") {
        const Watchdog watchdog(30);
        Call call;
        call.options.recvTimeoutMs = 1500; // a client that waited for the body would fail here
        Script input{};
        input.closeAfterResponse = false;
        SUBCASE("204") {
            input.response = "HTTP/1.1 204 No Content\r\n\r\n";
            call.method = "GET";
        }
        SUBCASE("304") {
            input.response = "HTTP/1.1 304 Not Modified\r\nContent-Length: 1000\r\n\r\n";
            call.method = "GET";
        }
        SUBCASE("HEAD with a Content-Length") {
            input.response = "HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n";
            call.method = "HEAD";
        }
        const Exchange run = Perform(input, call);
        REQUIRE(run.started);
        CHECK(run.observed.failure.empty());
        REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
        CHECK(run.observed.body.empty());
        CHECK(run.response.value().body.empty());
        CHECK(run.elapsedMs < 1000); // it did not wait for the connection to close
    }

    TEST_CASE("an interim response is skipped and the final one returned") {
        const Watchdog watchdog(30);
        Script input{};
        input.response = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </x>\r\n\r\n"
                         "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        const Exchange run = Perform(input);
        REQUIRE(run.started);
        REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
        CHECK_EQ(run.response.value().status, 200);
        CheckBody(run.response.value().body, "ok");
        CHECK_EQ(run.response.value().headers.size(), static_cast<size_t>(1));
    }

    TEST_CASE("a host name is resolved and kept in the Host header") {
        const Watchdog watchdog(30);
        const std::string loopback = FirstLoopbackAddress("localhost");
        if (loopback.empty()) {
            MESSAGE("skipped: localhost does not resolve to a loopback address on this machine");
            return;
        }
        Script input{};
        input.response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        Call call;
        call.urlHost = "localhost";
        call.listenIp = loopback; // the address the name resolves to first
        const Exchange run = Perform(input, call);
        if (!run.started) {
            MESSAGE("skipped: the loopback address " << loopback << " cannot be bound");
            return;
        }
        CHECK(run.observed.failure.empty());
        REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
        CheckBody(run.response.value().body, "ok");
        CHECK(HeaderValue(run.observed.request, "host") == "localhost:" + Decimal(run.port));
    }

    TEST_CASE("an IPv6 literal in brackets is connected to and kept in the Host header") {
        const Watchdog watchdog(30);
        if (!HasIpv6Loopback()) {
            MESSAGE("skipped: this machine has no IPv6 loopback address");
            return;
        }
        Script input{};
        input.response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
        Call call;
        call.urlHost = "::1";
        call.listenIp = "::1";
        const Exchange run = Perform(input, call);
        REQUIRE(run.started);
        CHECK(run.observed.failure.empty());
        REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
        CheckBody(run.response.value().body, "ok");
        CHECK(run.url == "http://[::1]:" + Decimal(run.port) + "/sensors/abc/?q=1");
        CHECK(HeaderValue(run.observed.request, "host") == "[::1]:" + Decimal(run.port)); // RFC 2732
    }

    TEST_CASE("URL and argument errors are reported without a connection attempt") {
        const Watchdog watchdog(30);
        const Stream payload = Pattern(16, 2);
        Call call;
        call.options.recvTimeoutMs = 500; // a wrongly accepted URL would fail with a timeout
        UniqueFd listener;
        uint16_t port = 0;
        REQUIRE(BindLoopback("127.0.0.1", SOCK_STREAM, true, 0, listener, port)); // never accepts
        const std::string live = UrlOf("127.0.0.1", port, "/");
        const std::string urls[] = {
            "https://127.0.0.1/", // the scheme
            "HTTPS://127.0.0.1/",
            "ftp://" + live.substr(7),
            "http://", // the host
            "http:///",
            "http://:8080/",
            "http://:8080/path",
            "http://127.0.0.1:abc/", // the port
            "http://127.0.0.1:0/",
            "http://127.0.0.1:70000/",
            "http://127.0.0.1:/",
            "http://127.0.0.1:8080x/",
            "http://127.0.0.1:99999999999999999999/",
            "http://[::1/", // the IPv6 literal
            "http://[::1]x/",
            "http://[::1]:/",
            "http://user:pass@127.0.0.1/", // user information is not supported
            "http://127.0.0.1?q=1",
            "http://127.0.0.1:8080/a b",
            "http://127.0.0.1:8080/\r\nX-Injected: 1",
            "http://127.0.0.1:8080/\x01",
        };
        for (size_t i = 0; i < sizeof(urls) / sizeof(urls[0]); i++) {
            const auto response = HttpRequest(urls[i], payload, "POST", call.options);
            INFO(i << ": " << Escaped(urls[i]));
            REQUIRE_FALSE(response.has_value());
            ExpectError(response.error(), cpl::Error::InvalidArgument);
        }
        const char *methods[] = {"", "P ST", "POST\r\nX-Injected: 1", "GET\tHTTP/1.1", "bad(method)"};
        for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
            const auto response = HttpRequest(live, payload, methods[i], call.options);
            REQUIRE_FALSE(response.has_value());
            ExpectError(response.error(), cpl::Error::InvalidArgument);
        }
        const auto nullMethod = HttpRequest(live, payload, static_cast<const char *>(nullptr), call.options);
        REQUIRE_FALSE(nullMethod.has_value());
        ExpectError(nullMethod.error(), cpl::Error::InvalidArgument);

        call.options.contentType = "text/plain\r\nX-Injected: 1";
        const auto injected = HttpRequest(live, payload, "POST", call.options);
        REQUIRE_FALSE(injected.has_value());
        ExpectError(injected.error(), cpl::Error::InvalidArgument);
    }

    TEST_CASE("a POST body of 8 MB is sent completely") {
        const Watchdog watchdog(60);
        Call call;
        call.body = Pattern(8u * 1024u * 1024u, 4);
        Script input{};
        input.readDelayMs = 300; // the client fills the socket buffers before anything is read
        input.replyWithDigest = true;
        const Exchange run = Perform(input, call);
        REQUIRE(run.started);
        CHECK(run.observed.failure.empty());
        CHECK(run.observed.requestComplete);
        CHECK(run.observed.body.size() == call.body.size());
        REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
        const std::string expected = Decimal(call.body.size()) + ":" + HexDecimal(Digest(StreamText(call.body)));
        CheckBody(run.response.value().body, expected);
    }

    TEST_CASE("a request that cannot be sent completely fails at sendTimeoutMs") {
        const Watchdog watchdog(30);
        Script input{};
        input.readDelayMs = 1500; // the client fills the socket buffers before anything is read
        Call call;
        call.body = Pattern(32u * 1024u * 1024u, 8); // more than the socket buffers can hold
        call.options.sendTimeoutMs = 500;
        const Exchange run = Perform(input, call);
        REQUIRE(run.started);
        REQUIRE_FALSE(run.response.has_value());
        ExpectError(run.response.error(), Errors::SendFailed);
        CHECK(run.observed.failure.empty());
        CHECK_FALSE(run.observed.requestComplete); // the client gave up before the server read
        CHECK(run.elapsedMs >= 450); // it did wait for the timeout ...
        CHECK(run.elapsedMs < 1500); // ... and gave up as soon as it had passed
    }

    TEST_CASE("sending on a connection the peer already closed is an error, not SIGPIPE") {
        const Watchdog watchdog(30);
        // Without MSG_NOSIGNAL the write below would raise SIGPIPE, whose default action ends
        // this process: the remaining cases and the summary at the end prove that it survives.
        Script input{};
        input.closeAfterAccept = true;
        Call call;
        call.body = Pattern(8u * 1024u * 1024u, 3);
        const Exchange run = Perform(input, call);
        REQUIRE(run.started);
        CHECK(run.observed.accepted);
        CHECK_FALSE(run.observed.requestComplete);
        REQUIRE_FALSE(run.response.has_value());
        // Either a write hit the reset connection, or the reset was seen while reading.
        const int64_t code = run.response.error().Code.i64;
        CHECK((code == Errors::SendFailed || code == Errors::IncompleteResponse));
        CHECK(HasLocation(run.response.error()));
    }

    TEST_CASE("a signal during the receive phase does not break the request") {
        const Watchdog watchdog(30);
        Interrupter interrupter(SIGUSR1, 20);
        if (!interrupter.Installed()) {
            MESSAGE("skipped: SIGUSR1 cannot be caught on this machine");
            return;
        }
        Script input{};
        input.response = "HTTP/1.1 200 OK\r\nContent-Length: 200\r\n\r\n" + std::string(200, 'z');
        input.pieces = 8;
        input.pieceDelayMs = 40; // several pauses, each interrupted by signals
        Call call;
        call.options.recvTimeoutMs = 5000;
        const Exchange run = Perform(input, call);
        CHECK(run.observed.failure.empty());
        REQUIRE_MESSAGE(run.response.has_value(), Describe(run.response));
        CheckBody(run.response.value().body, std::string(200, 'z'));
        CHECK(run.elapsedMs >= 250); // the signals did not shorten the wait for the pieces
    }

    TEST_CASE("requests and datagrams from several threads at once do not interfere") {
        const Watchdog watchdog(60);
        std::atomic<int> failures(0);
        std::mutex mutex;
        std::vector<std::string> notes;
        std::vector<std::thread> workers;
        for (int worker = 0; worker < 4; worker++) {
            workers.emplace_back([&failures, &mutex, &notes, worker] {
                for (int round = 0; round < 4; round++) {
                    const std::string note = WorkerRound(worker, round);
                    if (!note.empty()) {
                        failures.fetch_add(1);
                        const std::lock_guard<std::mutex> guard(mutex);
                        notes.push_back("worker " + Decimal(static_cast<uint64_t>(worker)) + ", round "
                                        + Decimal(static_cast<uint64_t>(round)) + ": " + note);
                    }
                }
            });
        }
        for (size_t i = 0; i < workers.size(); i++) {
            workers[i].join();
        }
        for (size_t i = 0; i < notes.size(); i++) {
            MESSAGE(notes[i]);
        }
        CHECK_EQ(failures.load(), 0);
    }

    TEST_CASE("UdpSend delivers the exact datagram") {
        const Watchdog watchdog(30);
        const Stream payload = Pattern(820, 3);
        int sockets[2] = {-1, -1};
        Stream received;
        SUBCASE("to a dotted IPv4 address, with the default timeout and with none") {
            UniqueFd receiver;
            uint16_t port = 0;
            REQUIRE(BindLoopback("127.0.0.1", SOCK_DGRAM, false, 0, receiver, port));
            sockets[0] = receiver.Get();
            Int32Result sent = UdpSend("127.0.0.1", port, payload);
            REQUIRE(sent.has_value());
            CHECK_EQ(sent.value(), 0);
            REQUIRE(ReceiveDatagram(sockets, 1, received, 2000));
            CHECK(received == payload);
            sent = UdpSend("127.0.0.1", port, payload, 0);
            REQUIRE(sent.has_value());
            REQUIRE(ReceiveDatagram(sockets, 1, received, 2000));
            CHECK(received == payload);
        }
        SUBCASE("to the name localhost") {
            UniqueFd ipv4;
            UniqueFd ipv6;
            uint16_t port = 0;
            REQUIRE(BindUdpLoopbackPair(ipv4, ipv6, port));
            sockets[0] = ipv4.Get();
            sockets[1] = ipv6.Get();
            REQUIRE(UdpSend("localhost", port, payload, 500).has_value());
            REQUIRE(ReceiveDatagram(sockets, ipv6.Get() >= 0 ? 2 : 1, received, 2000));
            CHECK(received == payload);
        }
        SUBCASE("to an IPv6 literal, with and without brackets") {
            UniqueFd receiver;
            uint16_t port = 0;
            if (!BindLoopback("::1", SOCK_DGRAM, false, 0, receiver, port)) {
                MESSAGE("skipped: this machine has no IPv6 loopback address");
                return;
            }
            sockets[0] = receiver.Get();
            REQUIRE(UdpSend("::1", port, payload).has_value());
            REQUIRE(ReceiveDatagram(sockets, 1, received, 2000));
            CHECK(received == payload);
            REQUIRE(UdpSend("[::1]", port, payload).has_value());
            REQUIRE(ReceiveDatagram(sockets, 1, received, 2000));
            CHECK(received == payload);
        }
    }

    TEST_CASE("UdpSend rejects what it cannot send") {
        const Watchdog watchdog(30);
        const Stream payload = Pattern(100, 5);
        UniqueFd receiver;
        uint16_t port = 0;
        REQUIRE(BindLoopback("127.0.0.1", SOCK_DGRAM, false, 0, receiver, port));
        const int sockets[1] = {receiver.Get()};
        Stream received;

        Int32Result sent = UdpSend("127.0.0.1", port, Stream());
        REQUIRE_FALSE(sent.has_value());
        ExpectError(sent.error(), cpl::Error::InvalidArgument);

        sent = UdpSend("127.0.0.1", port, Stream(65508, 0x5a)); // larger than the largest UDP payload
        REQUIRE_FALSE(sent.has_value());
        ExpectError(sent.error(), cpl::Error::InvalidArgument);

        sent = UdpSend("127.0.0.1", 0, payload);
        REQUIRE_FALSE(sent.has_value());
        ExpectError(sent.error(), cpl::Error::InvalidArgument);

        sent = UdpSend("", port, payload);
        REQUIRE_FALSE(sent.has_value());
        ExpectError(sent.error(), cpl::Error::InvalidArgument);

        sent = UdpSend("[]", port, payload);
        REQUIRE_FALSE(sent.has_value());
        ExpectError(sent.error(), cpl::Error::InvalidArgument);

        CHECK_FALSE(ReceiveDatagram(sockets, 1, received, 200)); // nothing was sent at all
    }

    TEST_CASE("an unresolvable host name is an error") {
        const Watchdog watchdog(30);
        const Stream payload = Pattern(32, 6);
        const std::string reserved = "cpl-test-no-such-host.invalid"; // RFC 2606: never resolvable
        const std::string tooLong = std::string(300, 'a') + ".org"; // longer than any name can be

        Int32Result sent = UdpSend(reserved, 53, payload, 500);
        REQUIRE_FALSE(sent.has_value());
        ExpectError(sent.error(), Errors::ResolveFailed);

        sent = UdpSend(tooLong, 53, payload, 500);
        REQUIRE_FALSE(sent.has_value());
        ExpectError(sent.error(), Errors::ResolveFailed);

        Call call;
        call.options.connectTimeoutMs = 500;
        call.options.recvTimeoutMs = 500;
        const auto response = HttpRequest("http://" + tooLong + "/", payload, "POST", call.options);
        REQUIRE_FALSE(response.has_value());
        ExpectError(response.error(), Errors::ResolveFailed);
    }
} // TEST_SUITE

#endif // !_WIN32
