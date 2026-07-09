// Tests for cpl::sys::network::wrapper::UDPSend (provider-injectable, naion CSM).
//
// UDPSend encrypts via a cpl::crypto::stl::ISync * then sends a raw UDP
// datagram through cpl::sys::api::Ws2_32 (dynamically loaded — no static
// ws2_32 linkage). To avoid a hard dependency on naion key setup here, a
// trivial XOR mock provider (satisfies stl::ISync) drives the encrypt->send
// pipeline. Real naion CSM round-tripping is exercised in test_naion.cpp's
// end-to-end cases.
#include "../vendor/doctest/doctest.hpp"
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "../win32/network.hpp"
#include "../win32/api.hpp" // cpl::sys::api::API for dynamic WSAStartup

#include <cstdint>
#include <vector>

using namespace cpl;
using namespace cpl::sys::network::wrapper;

// Winsock must be initialised once per process before any socket call.
// UDPSend uses cpl::sys::api::Ws2_32 (socket/sendto/closesocket), which are
// loaded dynamically by API::Instance().Load() (done by entry.cpp's
// Win32APIInitializer before tests run). WSAStartup itself is one of those
// dynamic pointers, so we call it through the api singleton — no static
// ws2_32 linkage.
//
// Initialisation is done lazily on first use (not at static-init time, which
// is unsafe for LoadLibrary) via EnsureWsa(), called from the suite setup.
namespace {
bool EnsureWsa() {
    static bool done = [] {
        auto &api = cpl::sys::api::API::Instance();
        if (api.Ws2_32.WSAStartup) {
            static WSADATA wsa{};
            return api.Ws2_32.WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
        }
        return false;
    }();
    return done;
}
} // namespace

// A minimal cpl::crypto::stl::ISync: XOR with a fixed key. Not real crypto —
// only meant to drive the UDPSend pipeline without naion key initialization.
namespace {
class XorSync final : public cpl::crypto::stl::ISync {
    uint8_t key_;

public:
    explicit XorSync(uint8_t k) : key_(k) {}

    Result<Stream> Encrypt(const Stream &in) override {
        Stream out(in.size());
        for (size_t i = 0; i < in.size(); ++i) {
            out[i] = static_cast<uint8_t>(in[i] ^ key_);
        }
        return out;
    }

    Result<Stream> Decrypt(const Stream &in) override {
        // XOR is symmetric.
        return Encrypt(in);
    }
};
} // namespace

// doctest fixture: EnsureWsa() runs before each case (after entry.cpp's
// Win32APIInitializer has called API::Load()), guaranteeing winsock is ready.
struct WsaFixture {
    WsaFixture() { EnsureWsa(); }
};

TEST_SUITE("sys::network::wrapper::UDPSend") {
    TEST_CASE_FIXTURE(WsaFixture, "rejects null provider") {
        Stream data{0x01, 0x02, 0x03};
        const auto rc = UDPSend("127.0.0.1", 1, data, nullptr, "ut_null");
        CHECK_EQ(rc, ERROR_INVALID_PARAMETER);
    }

    TEST_CASE_FIXTURE(WsaFixture, "encrypts and sends to localhost without crashing") {
        // UDP sendto to localhost:1 succeeds at the socket layer regardless of
        // whether anything is listening — we only verify the pipeline runs.
        XorSync prov(0xAA);
        Stream data(64, 0x55);
        const auto rc = UDPSend("127.0.0.1", 1, data, &prov, "ut_xor");
        CHECK_EQ(rc, ERROR_SUCCESS);
    }

    TEST_CASE_FIXTURE(WsaFixture, "empty payload is rejected") {
        XorSync prov(0xAA);
        Stream data{};
        // An empty payload yields an empty ciphertext; UDPSend rejects it
        // rather than sending a zero-length datagram.
        const auto rc = UDPSend("127.0.0.1", 1, data, &prov, "ut_empty");
        CHECK_EQ(rc, ERROR_INVALID_PARAMETER);
    }

    TEST_CASE_FIXTURE(WsaFixture, "large payload (near datagram budget) is sent") {
        XorSync prov(0xAA);
        // 800 bytes: well under the 1024-byte CSM budget, exercises the
        // full encrypt->socket path with a non-trivial size.
        Stream data(800, 0x42);
        const auto rc = UDPSend("127.0.0.1", 1, data, &prov, "ut_large");
        CHECK_EQ(rc, ERROR_SUCCESS);
    }

    TEST_CASE_FIXTURE(WsaFixture, "default tag (nullptr) works") {
        XorSync prov(0x01);
        Stream data{0xDE, 0xAD, 0xBE, 0xEF};
        const auto rc = UDPSend("127.0.0.1", 1, data, &prov);
        CHECK_EQ(rc, ERROR_SUCCESS);
    }
}
