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


// CSM cross-language vectors, see naion/PROTOCOL.md (fixed seeds, RNG fills 0x5A).
static const char *const kC2sCompact =
    "676f9b6a8cdfa755841a467b2709b5b3cbe4249665bca1f30922237678aedf6e"
    "714b553b0f27fc4dfff8b1d0ca68d00c8333eaf1c12abf1ce72e8b85bac0100a"
    "b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c"
    "1f639c2334f0089bcb0a7d5da997c2016e84fa6a6df29e24e4aa8d4b394b9b98"
    "0e0e11f7bf5b7f4fbce4435ba5d50e4fd432f7121f2b9b97d7fa83a0431d3b5d";

static const char *const kS2cCompact =
    "0c4c0249692bc2852662efe431530e03f94237b589ad2c53ed758101eca18f2c"
    "139ef42b1437b77c775dfd59e93dd1dcc48f44547cd631f4fcbc31f266dc6708"
    "b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c"
    "86345b488d8ff6fdec5f09c153d04202f0db445448e1f320021649bb4d717143";

static const char *const kC2sRandom =
    "987f308ffecb2c195194c1f81b1c78db264b1d47073a009853869bb1f5ccfe84"
    "048317f7173b61bc57a91e6bf194221ebcbb6166dc6ccd83d7916ea7246dbd0c"
    "b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c"
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5afbae93e8305a23e3"
    "a08f3f6d4cec110a364beb3d7e7c30a008b53895752c490bf48fab438eb09a71"
    "e7584cb6b0b7d9f0f6907d93f078090e34e100884d11ca5f";

static const char *const kS2cRandom =
    "82b009cb900f66e2004ad257680ed111c586517cffcaae8cf9c0c020b628c5ea"
    "c8700f4af571821ddf8442e7358f60b221f782aa5b8a6a3f2f2392a0a4365808"
    "b0d08f35b4683381489afb32825e59152d47d19bc9e050d6d5a954984c9d1e2c"
    "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5af77b969223bfbf7e"
    "b79137cb22dad8aba92a7a99f5d08ba76c494c33b0d09b6f";


// Derive the server Ed25519 public key from a seed (mirrors what the CSM
// client must be handed at creation time).
static EPK ServerPublicKeyFromSeed(const ESD &seed) {
    EPK pk{};
    ESK sk{};
    REQUIRE_EQ(naion_sign_ed25519_seed_keypair(pk.data(), sk.data(), seed.data()), 0);
    return pk;
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

    TEST_CASE("RandomBytesBuf fills distinct buffers") {
        Stream a(64, 0), b(64, 0);
        REQUIRE(Must(RandomBytesBuf(a.data(), a.size())) == 0);
        REQUIRE(Must(RandomBytesBuf(b.data(), b.size())) == 0);
        CHECK_FALSE(SameData(a, b));
        // All-zero buffer would indicate the RNG is a no-op.
        CHECK_FALSE(std::all_of(a.begin(), a.end(), [](uint8_t x) { return x == 0; }));
    }
}

TEST_SUITE("naion client_server") {
    TEST_CASE("Create works") {
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);

        auto server = Must(Server::Create(serverSeed));
        CHECK(server != nullptr);
        CHECK(SameData(Stream(server->GetPublicKey().begin(), server->GetPublicKey().end()),
                       Stream(serverPk.begin(), serverPk.end())));

        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));
        CHECK(client != nullptr);
    }

    TEST_CASE("Client Encrypt rejects empty input") {
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const Stream empty{};
        CHECK_FALSE(client->Encrypt(empty).has_value());
    }

    TEST_CASE("Server Encrypt rejects before client key initialization") {
        auto server = Must(Server::Create(GenerateRandomSeed()));
        CHECK_FALSE(server->Encrypt(GenerateRandomData(64)).has_value());
        CHECK_FALSE(server->IsClientKeyInitialized());
    }

    TEST_CASE("Bidirectional encryption round trip") {
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);
        auto server = Must(Server::Create(serverSeed));
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const auto c2s = GenerateRandomData(MaxClientPayloadBytes - 8);
        const auto encC2S = Must(client->Encrypt(c2s));
        const auto decC2S = Must(server->Decrypt(encC2S));
        CHECK(SameData(c2s, decC2S));
        CHECK(server->IsClientKeyInitialized());

        const auto s2c = GenerateRandomData(MaxServerPayloadBytes - 8);
        const auto encS2C = Must(server->Encrypt(s2c));
        const auto decS2C = Must(client->Decrypt(encS2C));
        CHECK(SameData(s2c, decS2C));
    }

    TEST_CASE("Packet sizes stay within UDP budget") {
        // The default (compact) mode has no nonce field, so it allows 24 bytes more.
        CHECK_EQ(PacketOverheadBytes - CompactPacketOverheadBytes, 24U);
        CHECK_EQ(CompactMaxClientPayloadBytes - MaxClientPayloadBytes, 24U);
        CHECK_EQ(CompactMaxServerPayloadBytes - MaxServerPayloadBytes, 24U);
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);
        auto server = Must(Server::Create(serverSeed));
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const auto c2sPayload = GenerateRandomData(CompactMaxClientPayloadBytes);
        const auto c2sFrame = Must(client->Encrypt(c2sPayload));
        CHECK_LE(c2sFrame.size(), MaxUDPDatagramBytes);
        CHECK_FALSE(client->Encrypt(GenerateRandomData(CompactMaxClientPayloadBytes + 1)).has_value());

        const auto decC2S = Must(server->Decrypt(c2sFrame));
        CHECK(SameData(c2sPayload, decC2S));

        const auto s2cPayload = GenerateRandomData(CompactMaxServerPayloadBytes);
        const auto s2cFrame = Must(server->Encrypt(s2cPayload));
        CHECK_LE(s2cFrame.size(), MaxUDPDatagramBytes);
        CHECK_FALSE(server->Encrypt(GenerateRandomData(CompactMaxServerPayloadBytes + 1)).has_value());

        const auto decS2C = Must(client->Decrypt(s2cFrame));
        CHECK(SameData(s2cPayload, decS2C));
    }

    TEST_CASE("Server Decrypt fails on tampered frame") {
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);
        auto server = Must(Server::Create(serverSeed));
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        auto frame = Must(client->Encrypt(GenerateRandomData(400)));
        frame.back() ^= 0x5A;
        CHECK_FALSE(server->Decrypt(frame).has_value());
    }

    TEST_CASE("Server Decrypt fails on truncated frame") {
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);
        auto server = Must(Server::Create(serverSeed));

        Stream tooShort(PacketOverheadBytes, 0);
        CHECK_FALSE(server->Decrypt(tooShort).has_value());
    }

    TEST_CASE("Server Decrypt accepts replayed packet (no replay protection by design)") {
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);
        auto server = Must(Server::Create(serverSeed));
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const auto payload = GenerateRandomData(128);
        const auto frame = Must(client->Encrypt(payload));
        // First decryption succeeds and learns the client key.
        const auto dec1 = Must(server->Decrypt(frame));
        CHECK(SameData(payload, dec1));
    // Replaying the exact same packet must still decrypt (CSM has no replay
    // protection by design) — the encrypted payload is unchanged.
    const auto dec2 = Must(server->Decrypt(frame));
    CHECK(SameData(payload, dec2));
    }

    TEST_CASE("Default packets are compact and round trip in both directions") {
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);
        auto server = Must(Server::Create(serverSeed));
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const auto payload = GenerateRandomData(100);
        const auto c2s = Must(client->Encrypt(payload));
        CHECK_EQ(c2s.size(), CompactPacketOverheadBytes + NAION_CSM_CLIENT_PK_BYTES + payload.size());
        CHECK(SameData(payload, Must(server->Decrypt(c2s))));

        const auto s2c = Must(server->Encrypt(payload));
        CHECK_EQ(s2c.size(), CompactPacketOverheadBytes + payload.size());
        CHECK(SameData(payload, Must(client->Decrypt(s2c))));
    }

    TEST_CASE("Random nonce mode round trip keeps the legacy sizes and budget") {
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);
        auto server = Must(Server::Create(serverSeed));
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const auto payload = GenerateRandomData(100);
        const auto c2s = Must(client->Encrypt(payload, NAION_CSM_NONCE_RANDOM));
        CHECK_EQ(c2s.size(), PacketOverheadBytes + NAION_CSM_CLIENT_PK_BYTES + payload.size());
        CHECK(SameData(payload, Must(server->Decrypt(c2s, NAION_CSM_NONCE_RANDOM))));

        const auto s2c = Must(server->Encrypt(payload, NAION_CSM_NONCE_RANDOM));
        CHECK_EQ(s2c.size(), PacketOverheadBytes + payload.size());
        CHECK(SameData(payload, Must(client->Decrypt(s2c, NAION_CSM_NONCE_RANDOM))));

        CHECK_FALSE(client->Encrypt(GenerateRandomData(MaxClientPayloadBytes + 1),
                                    NAION_CSM_NONCE_RANDOM).has_value());
        const auto c2sMax = Must(client->Encrypt(GenerateRandomData(MaxClientPayloadBytes),
                                                 NAION_CSM_NONCE_RANDOM));
        CHECK_EQ(c2sMax.size(), MaxUDPDatagramBytes);
    }

    TEST_CASE("Sender and receiver must use the same nonce mode") {
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);
        auto server = Must(Server::Create(serverSeed));
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const auto payload = GenerateRandomData(80);
        const auto compact = Must(client->Encrypt(payload));
        const auto random = Must(client->Encrypt(payload, NAION_CSM_NONCE_RANDOM));
        // A mismatched mode must fail, and it must not teach the server the client key.
        CHECK_FALSE(server->Decrypt(compact, NAION_CSM_NONCE_RANDOM).has_value());
        CHECK_FALSE(server->Decrypt(random).has_value());
        CHECK_FALSE(server->IsClientKeyInitialized());

        CHECK(SameData(payload, Must(server->Decrypt(compact))));
        CHECK(server->IsClientKeyInitialized());

        // The server to client direction behaves in the same way.
        const auto replyCompact = Must(server->Encrypt(payload));
        const auto replyRandom = Must(server->Encrypt(payload, NAION_CSM_NONCE_RANDOM));
        CHECK_FALSE(client->Decrypt(replyCompact, NAION_CSM_NONCE_RANDOM).has_value());
        CHECK_FALSE(client->Decrypt(replyRandom).has_value());
        CHECK(SameData(payload, Must(client->Decrypt(replyCompact))));
    }

    TEST_CASE("Compact packets reject tampering in every field") {
        const auto serverSeed = GenerateRandomSeed();
        const auto serverPk = ServerPublicKeyFromSeed(serverSeed);
        auto server = Must(Server::Create(serverSeed));
        auto client = Must(Client::Create(GenerateRandomSeed(), serverPk));

        const auto frame = Must(client->Encrypt(GenerateRandomData(64)));
        // signature[0:64] | session_x25519_public_key[64:96] | mac[96:112] | ciphertext[112:]
        const size_t offsets[] = {0, 63, 64, 95, 96, 111, 112, frame.size() - 1};
        for (const size_t offset : offsets) {
            auto tampered = frame;
            tampered[offset] ^= 0x01;
            CHECK_FALSE(server->Decrypt(tampered).has_value());
        }
        CHECK_FALSE(server->IsClientKeyInitialized());
    }

    TEST_CASE("Fixed seeds and a fixed RNG reproduce the cross-language vectors") {
        // Same inputs as PROTOCOL.md: seeds 0x01/0x02, random provider fills 0x5A.
        const auto fromHex = [](const char *hex) {
            Stream out;
            const auto nib = [](const char c) {
                return static_cast<uint8_t>(c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10);
            };
            for (const char *p = hex; p[0] != '\0' && p[1] != '\0'; p += 2) {
                out.push_back(static_cast<uint8_t>((nib(p[0]) << 4) | nib(p[1])));
            }
            return out;
        };
        struct ProviderGuard {
            ~ProviderGuard() { naion_set_random_provider(nullptr); }
        } providerGuard;
        naion_set_random_provider([](void *buf, const size_t size) { std::memset(buf, 0x5A, size); });

        ESD serverSeed{};
        ESD clientSeed{};
        serverSeed.fill(0x02);
        clientSeed.fill(0x01);
        auto server = Must(Server::Create(serverSeed));
        auto client = Must(Client::Create(clientSeed, server->GetPublicKey()));
        CHECK(SameData(Stream(server->GetPublicKey().begin(), server->GetPublicKey().end()),
                       fromHex("8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394")));
        CHECK(SameData(Stream(client->GetPublicKey().begin(), client->GetPublicKey().end()),
                       fromHex("8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c")));

        Stream payload(16);
        for (size_t i = 0; i < payload.size(); ++i) {
            payload[i] = static_cast<uint8_t>(i);
        }
        const auto c2sCompact = Must(client->Encrypt(payload));
        CHECK(SameData(c2sCompact, fromHex(kC2sCompact)));
        CHECK(SameData(payload, Must(server->Decrypt(c2sCompact))));
        const auto s2cCompact = Must(server->Encrypt(payload));
        CHECK(SameData(s2cCompact, fromHex(kS2cCompact)));

        const auto c2sRandom = Must(client->Encrypt(payload, NAION_CSM_NONCE_RANDOM));
        CHECK(SameData(c2sRandom, fromHex(kC2sRandom)));
        CHECK(SameData(payload, Must(server->Decrypt(c2sRandom, NAION_CSM_NONCE_RANDOM))));
        const auto s2cRandom = Must(server->Encrypt(payload, NAION_CSM_NONCE_RANDOM));
        CHECK(SameData(s2cRandom, fromHex(kS2cRandom)));
    }
}
