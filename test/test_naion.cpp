#include "../vendor/doctest/doctest.hpp"
#include "../naion.hpp"

#include <algorithm>

using namespace cpl;
using namespace cpl::naion;

template <typename T>
static T Must(Result<T> r) {
    REQUIRE(r.has_value());
    return std::move(r.value());
}

static Stream GenerateRandomData(const size_t size) {
    Stream data(size);
    REQUIRE(Must(RandomBytesBuf(data.data(), data.size())) == 0);
    return data;
}

static ESD GenerateRandomSeed() {
    ESD seed{};
    REQUIRE(Must(RandomBytesBuf(seed.data(), seed.size())) == 0);
    return seed;
}

static bool SameData(const Stream &a, const Stream &b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin());
}

TEST_SUITE("naion utility") {
    TEST_CASE("Seal rejects empty input") {
        XPK bobPk{}, alicePk{};
        XSK bobSk{}, aliceSk{};
        CHECK_EQ(naion_box_keypair(bobPk.data(), bobSk.data()), 0);
        CHECK_EQ(naion_box_keypair(alicePk.data(), aliceSk.data()), 0);

        const Stream empty{};
        CHECK_FALSE(Utility::Seal(empty, bobPk, aliceSk).has_value());
    }

    TEST_CASE("Seal/Open round trip") {
        XPK bobPk{}, alicePk{};
        XSK bobSk{}, aliceSk{};
        CHECK_EQ(naion_box_keypair(bobPk.data(), bobSk.data()), 0);
        CHECK_EQ(naion_box_keypair(alicePk.data(), aliceSk.data()), 0);

        const auto plaintext = GenerateRandomData(4096);
        const auto ciphertext = Must(Utility::Seal(plaintext, bobPk, aliceSk));
        CHECK_EQ(ciphertext.size(), naion_box_NONCEBYTES_MAX + plaintext.size() + naion_box_MACBYTES_MAX);

        const auto decrypted = Must(Utility::Open(ciphertext, alicePk, bobSk));
        CHECK(SameData(plaintext, decrypted));
    }

    TEST_CASE("Open fails on tampered ciphertext") {
        XPK bobPk{}, alicePk{};
        XSK bobSk{}, aliceSk{};
        CHECK_EQ(naion_box_keypair(bobPk.data(), bobSk.data()), 0);
        CHECK_EQ(naion_box_keypair(alicePk.data(), aliceSk.data()), 0);

        auto ciphertext = Must(Utility::Seal(GenerateRandomData(1024), bobPk, aliceSk));
        ciphertext[naion_box_NONCEBYTES_MAX] ^= 0x40;
        CHECK_FALSE(Utility::Open(ciphertext, alicePk, bobSk).has_value());
    }

    TEST_CASE("Sign/Verify round trip") {
        const auto seed = GenerateRandomSeed();
        EPK pk{};
        ESK sk{};
        CHECK_EQ(naion_sign_ed25519_seed_keypair(pk.data(), sk.data(), seed.data()), 0);

        const auto msg = GenerateRandomData(1200);
        const auto sig = Must(Utility::Sign(msg, sk));
        CHECK_EQ(sig.size(), naion_sign_ed25519_BYTES);
        CHECK(Must(Utility::Verify(sig, msg, pk)));
    }

    TEST_CASE("Verify reports tampered payload") {
        const auto seed = GenerateRandomSeed();
        EPK pk{};
        ESK sk{};
        CHECK_EQ(naion_sign_ed25519_seed_keypair(pk.data(), sk.data(), seed.data()), 0);

        const auto msg = GenerateRandomData(300);
        auto tampered = msg;
        tampered[1] ^= 0x01;

        const auto sig = Must(Utility::Sign(msg, sk));
        CHECK_FALSE(Must(Utility::Verify(sig, tampered, pk)));
    }
}

TEST_SUITE("naion client_server") {
    TEST_CASE("Create works") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));
        CHECK(server != nullptr);
        EPK serverPk{};
        ESK serverSk{};
        CHECK_EQ(naion_sign_ed25519_seed_keypair(serverPk.data(), serverSk.data(), serverSeed.data()), 0);

        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));
        CHECK(client != nullptr);
    }

    TEST_CASE("Client Encrypt rejects empty input") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));
        EPK serverPk{};
        ESK serverSk{};
        CHECK_EQ(naion_sign_ed25519_seed_keypair(serverPk.data(), serverSk.data(), serverSeed.data()), 0);
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const Stream empty{};
        CHECK_FALSE(client->Encrypt(empty).has_value());
    }

    TEST_CASE("Server Encrypt rejects before client key initialization") {
        auto server = Must(Server::Create(GenerateRandomSeed()));
        CHECK_FALSE(server->Encrypt(GenerateRandomData(64)).has_value());
    }

    TEST_CASE("Bidirectional encryption round trip") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));
        EPK serverPk{};
        ESK serverSk{};
        CHECK_EQ(naion_sign_ed25519_seed_keypair(serverPk.data(), serverSk.data(), serverSeed.data()), 0);
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const auto c2s = GenerateRandomData(MaxClientPayloadBytes - 8);
        const auto encC2S = Must(client->Encrypt(c2s));
        const auto decC2S = Must(server->Decrypt(encC2S));
        CHECK(SameData(c2s, decC2S));

        const auto s2c = GenerateRandomData(MaxServerPayloadBytes - 8);
        const auto encS2C = Must(server->Encrypt(s2c));
        const auto decS2C = Must(client->Decrypt(encS2C));
        CHECK(SameData(s2c, decS2C));
    }

    TEST_CASE("Packet sizes stay within UDP budget") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));
        EPK serverPk{};
        ESK serverSk{};
        CHECK_EQ(naion_sign_ed25519_seed_keypair(serverPk.data(), serverSk.data(), serverSeed.data()), 0);
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const auto c2sPayload = GenerateRandomData(MaxClientPayloadBytes);
        const auto c2sFrame = Must(client->Encrypt(c2sPayload));
        CHECK_LE(c2sFrame.size(), MaxUDPDatagramBytes);
        CHECK_FALSE(client->Encrypt(GenerateRandomData(MaxClientPayloadBytes + 1)).has_value());

        const auto decC2S = Must(server->Decrypt(c2sFrame));
        CHECK(SameData(c2sPayload, decC2S));

        const auto s2cPayload = GenerateRandomData(MaxServerPayloadBytes);
        const auto s2cFrame = Must(server->Encrypt(s2cPayload));
        CHECK_LE(s2cFrame.size(), MaxUDPDatagramBytes);
        CHECK_FALSE(server->Encrypt(GenerateRandomData(MaxServerPayloadBytes + 1)).has_value());

        const auto decS2C = Must(client->Decrypt(s2cFrame));
        CHECK(SameData(s2cPayload, decS2C));
    }

    TEST_CASE("Decrypt fails on tampered packet meta") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));
        EPK serverPk{};
        ESK serverSk{};
        CHECK_EQ(naion_sign_ed25519_seed_keypair(serverPk.data(), serverSk.data(), serverSeed.data()), 0);
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        auto frame = Must(client->Encrypt(GenerateRandomData(128)));
        constexpr size_t metaOffset = naion_sign_ed25519_BYTES
                                      + naion_box_PUBLICKEYBYTES_MAX
                                      + naion_box_NONCEBYTES_MAX
                                      + naion_box_MACBYTES_MAX;
        frame[metaOffset] ^= 0x01;
        CHECK_FALSE(server->Decrypt(frame).has_value());
    }

    TEST_CASE("Decrypt fails on tampered frame") {
        const auto serverSeed = GenerateRandomSeed();
        auto server = Must(Server::Create(serverSeed));
        EPK serverPk{};
        ESK serverSk{};
        CHECK_EQ(naion_sign_ed25519_seed_keypair(serverPk.data(), serverSk.data(), serverSeed.data()), 0);
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        auto frame = Must(client->Encrypt(GenerateRandomData(400)));
        frame.back() ^= 0x5A;
        CHECK_FALSE(server->Decrypt(frame).has_value());
    }
}
