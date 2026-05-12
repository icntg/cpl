#include "../vendor/doctest/doctest.hpp"
#define SODIUM_STATIC
#include "../sodium.hpp"
#include <algorithm>
#include <random>

using namespace cpl;
using namespace cpl::sodium;

template <typename T>
static T Must(Result<T> r) {
    REQUIRE(r.has_value());
    return std::move(r.value());
}

template <typename T>
static void RequireOk(Result<T> r) {
    REQUIRE(r.has_value());
}

static Stream GenerateRandomData(const size_t size) {
    Stream data(size);
    randombytes_buf(data.data(), data.size());
    return data;
}

static ESD GenerateRandomSeed() {
    ESD seed{};
    randombytes_buf(seed.data(), seed.size());
    return seed;
}

static bool SameData(const Stream &a, const Stream &b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

TEST_SUITE("libsodium utility") {
    TEST_CASE("Seal rejects empty input") {
        XPK bobPk{}, alicePk{};
        XSK bobSk{}, aliceSk{};
        crypto_box_keypair(bobPk.data(), bobSk.data());
        crypto_box_keypair(alicePk.data(), aliceSk.data());

        const Stream empty{};
        const auto r = Utility::Seal(empty, bobPk, aliceSk);
        CHECK_FALSE(r.has_value());
    }

    TEST_CASE("Seal/Open round trip") {
        XPK bobPk{}, alicePk{};
        XSK bobSk{}, aliceSk{};
        crypto_box_keypair(bobPk.data(), bobSk.data());
        crypto_box_keypair(alicePk.data(), aliceSk.data());

        const auto plaintext = GenerateRandomData(4096);
        const auto ciphertext = Must(Utility::Seal(plaintext, bobPk, aliceSk));
        CHECK_EQ(ciphertext.size(), crypto_box_NONCEBYTES + plaintext.size() + crypto_box_MACBYTES);

        const auto decrypted = Must(Utility::Open(ciphertext, alicePk, bobSk));
        CHECK(SameData(plaintext, decrypted));
    }

    TEST_CASE("Open fails on tampered ciphertext") {
        XPK bobPk{}, alicePk{};
        XSK bobSk{}, aliceSk{};
        crypto_box_keypair(bobPk.data(), bobSk.data());
        crypto_box_keypair(alicePk.data(), aliceSk.data());

        const auto plaintext = GenerateRandomData(1024);
        auto ciphertext = Must(Utility::Seal(plaintext, bobPk, aliceSk));
        ciphertext[crypto_box_NONCEBYTES] ^= 0x7F;
        CHECK_FALSE(Utility::Open(ciphertext, alicePk, bobSk).has_value());
    }

    TEST_CASE("Sign/Verify round trip") {
        const auto seed = GenerateRandomSeed();
        EPK pk{};
        ESK sk{};
        CHECK_EQ(crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data()), 0);

        const auto msg = GenerateRandomData(2048);
        const auto sig = Must(Utility::Sign(msg, sk));
        CHECK_EQ(sig.size(), crypto_sign_BYTES);
        CHECK(Must(Utility::Verify(sig, msg, pk)));
    }

    TEST_CASE("Verify reports tampered payload") {
        const auto seed = GenerateRandomSeed();
        EPK pk{};
        ESK sk{};
        CHECK_EQ(crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data()), 0);

        const auto msg = GenerateRandomData(256);
        auto bad = msg;
        bad[0] ^= 0x01;

        const auto sig = Must(Utility::Sign(msg, sk));
        CHECK_FALSE(Must(Utility::Verify(sig, bad, pk)));
    }
}

TEST_SUITE("libsodium client_server") {
    TEST_CASE("Create works") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));
        CHECK(server != nullptr);
        EPK serverPk{};
        ESK serverSk{};
        CHECK_EQ(crypto_sign_seed_keypair(serverPk.data(), serverSk.data(), serverSeed.data()), 0);

        const auto clientSeed = GenerateRandomSeed();
        auto client = Must(Client::Create(clientSeed, serverPk));
        CHECK(client != nullptr);
    }

    TEST_CASE("Client Encrypt rejects empty input") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));
        EPK serverPk{};
        ESK serverSk{};
        CHECK_EQ(crypto_sign_seed_keypair(serverPk.data(), serverSk.data(), serverSeed.data()), 0);
        const auto clientSeed = GenerateRandomSeed();
        auto client = Must(Client::Create(clientSeed, serverPk));

        const Stream empty{};
        CHECK_FALSE(client->Encrypt(empty).has_value());
    }

    TEST_CASE("Server Encrypt rejects before client key initialization") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));

        const auto data = GenerateRandomData(32);
        CHECK_FALSE(server->Encrypt(data).has_value());
    }

    TEST_CASE("Bidirectional encryption round trip") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));
        EPK serverPk{};
        ESK serverSk{};
        CHECK_EQ(crypto_sign_seed_keypair(serverPk.data(), serverSk.data(), serverSeed.data()), 0);

        const auto clientSeed = GenerateRandomSeed();
        auto client = Must(Client::Create(clientSeed, serverPk));

        const auto c2s = GenerateRandomData(1500);
        const auto encC2S = Must(client->Encrypt(c2s));
        const auto decC2S = Must(server->Decrypt(encC2S));
        CHECK(SameData(c2s, decC2S));

        const auto s2c = GenerateRandomData(1800);
        const auto encS2C = Must(server->Encrypt(s2c));
        const auto decS2C = Must(client->Decrypt(encS2C));
        CHECK(SameData(s2c, decS2C));
    }

    TEST_CASE("Decrypt fails on tampered transport frame") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));
        EPK serverPk{};
        ESK serverSk{};
        CHECK_EQ(crypto_sign_seed_keypair(serverPk.data(), serverSk.data(), serverSeed.data()), 0);
        const auto clientSeed = GenerateRandomSeed();
        auto client = Must(Client::Create(clientSeed, serverPk));

        auto frame = Must(client->Encrypt(GenerateRandomData(300)));
        frame.back() ^= 0xAA;
        CHECK_FALSE(server->Decrypt(frame).has_value());
    }
}
