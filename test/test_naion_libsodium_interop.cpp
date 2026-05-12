#include "../vendor/doctest/doctest.hpp"
#define SODIUM_STATIC
#include "../vendor/jedisct1/libsodium/sodium.h"
#if defined(NAION_TEST_SINGLE_HEADER)
#ifndef NAION_IMPLEMENTATION
#define NAION_IMPLEMENTATION
#endif
#endif
#include "../naion/naion.h"
#include <array>
#include <vector>
#include <cstring>
#include <iostream>
#include <iomanip>
#include <random>

namespace {
    template <size_t N>
    std::array<unsigned char, N> FixedSeed(const unsigned char base) {
        std::array<unsigned char, N> out{};
        for (size_t i = 0; i < N; ++i) {
            out[i] = static_cast<unsigned char>(base + i);
        }
        return out;
    }

    void DumpHex(const char *label, const unsigned char *buf, size_t len) {
        std::cout << "[interop] " << (label ? label : "buf") << " len=" << len << ": ";
        for (size_t i = 0; i < len; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(buf[i]);
        }
        std::cout << std::dec << std::setfill(' ') << "\n";
    }

    void FillRandom(std::vector<unsigned char> &buf, std::mt19937_64 &rng) {
        std::uniform_int_distribution<unsigned int> dist(0, 255);
        for (auto &b: buf) {
            b = static_cast<unsigned char>(dist(rng));
        }
    }

    struct NaionBoxModeGuard {
        int old_mode{0};
        explicit NaionBoxModeGuard(const int mode) {
            old_mode = naion_get_use_xchacha20();
            naion_set_use_xchacha20(mode);
        }
        ~NaionBoxModeGuard() {
            naion_set_use_xchacha20(old_mode);
        }
    };
}

TEST_SUITE("NAION Libsodium Interop") {
    TEST_CASE("Generichash one-shot and streaming are compatible") {
        const std::vector<unsigned char> msg{
            'i', 'n', 't', 'e', 'r', 'o', 'p', '-', 'g', 'e', 'n', 'e', 'r', 'i', 'c', 'h', 'a', 's', 'h'
        };
        const auto key = FixedSeed<crypto_generichash_KEYBYTES>(0x31);

        // one-shot, unkeyed
        {
            std::array<unsigned char, crypto_generichash_BYTES> l_out{};
            std::array<unsigned char, naion_generichash_BYTES> n_out{};
            CHECK_EQ(crypto_generichash(l_out.data(), l_out.size(), msg.data(), msg.size(), nullptr, 0), 0);
            CHECK_EQ(naion_generichash(n_out.data(), n_out.size(), msg.data(), msg.size(), nullptr, 0), 0);
            CHECK(std::memcmp(l_out.data(), n_out.data(), l_out.size()) == 0);
        }

        // one-shot, keyed + custom outlen
        {
            constexpr size_t outlen = 32;
            std::array<unsigned char, outlen> l_out{};
            std::array<unsigned char, outlen> n_out{};
            CHECK_EQ(crypto_generichash(l_out.data(), outlen, msg.data(), msg.size(), key.data(), key.size()), 0);
            CHECK_EQ(naion_generichash(n_out.data(), outlen, msg.data(), msg.size(), key.data(), key.size()), 0);
            CHECK(std::memcmp(l_out.data(), n_out.data(), outlen) == 0);
        }

        // streaming, keyed
        {
            constexpr size_t outlen = 48;
            std::array<unsigned char, outlen> l_out{};
            std::array<unsigned char, outlen> n_out{};
            crypto_generichash_state ls{};
            naion_generichash_state ns{};
            const size_t split = 7;

            CHECK_EQ(crypto_generichash_init(&ls, key.data(), key.size(), outlen), 0);
            CHECK_EQ(naion_generichash_init(&ns, key.data(), key.size(), outlen), 0);
            CHECK_EQ(crypto_generichash_update(&ls, msg.data(), split), 0);
            CHECK_EQ(naion_generichash_update(&ns, msg.data(), split), 0);
            CHECK_EQ(crypto_generichash_update(&ls, msg.data() + split, msg.size() - split), 0);
            CHECK_EQ(naion_generichash_update(&ns, msg.data() + split, msg.size() - split), 0);
            CHECK_EQ(crypto_generichash_final(&ls, l_out.data(), outlen), 0);
            CHECK_EQ(naion_generichash_final(&ns, n_out.data(), outlen), 0);
            CHECK(std::memcmp(l_out.data(), n_out.data(), outlen) == 0);
        }
    }

    TEST_CASE("Ed25519 keypair and curve25519 conversion are compatible") {
        const auto seed = FixedSeed<32>(0x11);

        std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> l_pk{};
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES> l_sk{};
        std::array<unsigned char, naion_sign_ed25519_PUBLICKEYBYTES> n_pk{};
        std::array<unsigned char, naion_sign_ed25519_SECRETKEYBYTES> n_sk{};

        CHECK_EQ(crypto_sign_seed_keypair(l_pk.data(), l_sk.data(), seed.data()), 0);
        CHECK_EQ(naion_sign_ed25519_seed_keypair(n_pk.data(), n_sk.data(), seed.data()), 0);
        CHECK(std::memcmp(l_pk.data(), n_pk.data(), l_pk.size()) == 0);
        CHECK(std::memcmp(l_sk.data(), n_sk.data(), l_sk.size()) == 0);

        std::array<unsigned char, crypto_box_PUBLICKEYBYTES> l_xpk{};
        std::array<unsigned char, crypto_box_SECRETKEYBYTES> l_xsk{};
        std::array<unsigned char, naion_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES> n_xpk{};
        std::array<unsigned char, naion_box_curve25519xsalsa20poly1305_SECRETKEYBYTES> n_xsk{};

        CHECK_EQ(crypto_sign_ed25519_pk_to_curve25519(l_xpk.data(), l_pk.data()), 0);
        CHECK_EQ(crypto_sign_ed25519_sk_to_curve25519(l_xsk.data(), l_sk.data()), 0);
        CHECK_EQ(naion_sign_ed25519_pk_to_curve25519(n_xpk.data(), n_pk.data()), 0);
        CHECK_EQ(naion_sign_ed25519_sk_to_curve25519(n_xsk.data(), n_sk.data()), 0);
        CHECK(std::memcmp(l_xpk.data(), n_xpk.data(), l_xpk.size()) == 0);
        CHECK(std::memcmp(l_xsk.data(), n_xsk.data(), l_xsk.size()) == 0);
    }

    TEST_CASE("crypto_box_easy cross decrypt works both directions") {
        const auto seed_a = FixedSeed<32>(0x21);
        const auto seed_b = FixedSeed<32>(0x41);

        std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> a_edpk{};
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES> a_edsk{};
        std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> b_edpk{};
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES> b_edsk{};
        CHECK_EQ(crypto_sign_seed_keypair(a_edpk.data(), a_edsk.data(), seed_a.data()), 0);
        CHECK_EQ(crypto_sign_seed_keypair(b_edpk.data(), b_edsk.data(), seed_b.data()), 0);

        std::array<unsigned char, crypto_box_PUBLICKEYBYTES> a_xpk{};
        std::array<unsigned char, crypto_box_SECRETKEYBYTES> a_xsk{};
        std::array<unsigned char, crypto_box_PUBLICKEYBYTES> b_xpk{};
        std::array<unsigned char, crypto_box_SECRETKEYBYTES> b_xsk{};
        CHECK_EQ(crypto_sign_ed25519_pk_to_curve25519(a_xpk.data(), a_edpk.data()), 0);
        CHECK_EQ(crypto_sign_ed25519_sk_to_curve25519(a_xsk.data(), a_edsk.data()), 0);
        CHECK_EQ(crypto_sign_ed25519_pk_to_curve25519(b_xpk.data(), b_edpk.data()), 0);
        CHECK_EQ(crypto_sign_ed25519_sk_to_curve25519(b_xsk.data(), b_edsk.data()), 0);

        std::array<unsigned char, crypto_box_NONCEBYTES> nonce{};
        for (size_t i = 0; i < nonce.size(); ++i) {
            nonce[i] = static_cast<unsigned char>(0x80 + i);
        }
        const std::vector<unsigned char> msg{
            'i', 'n', 't', 'e', 'r', 'o', 'p', '-', 'b', 'o', 'x'
        };
        std::vector<unsigned char> c(msg.size() + crypto_box_MACBYTES);
        std::vector<unsigned char> out(msg.size());
        std::array<unsigned char, crypto_box_BEFORENMBYTES> lk{};
        std::array<unsigned char, naion_box_curve25519xsalsa20poly1305_BEFORENMBYTES> nk{};

        // baseline: libsodium encrypt -> libsodium decrypt
        std::fill(c.begin(), c.end(), 0);
        std::fill(out.begin(), out.end(), 0);
        CHECK_EQ(crypto_box_beforenm(lk.data(), b_xpk.data(), a_xsk.data()), 0);
        CHECK_EQ(naion_box_curve25519xsalsa20poly1305_beforenm(nk.data(), b_xpk.data(), a_xsk.data()), 0);
        DumpHex("ls.k_nm", lk.data(), lk.size());
        DumpHex("na.k_nm", nk.data(), nk.size());
        DumpHex("nonce", nonce.data(), nonce.size());
        CHECK_EQ(
            crypto_box_easy(
                c.data(), msg.data(), msg.size(), nonce.data(), b_xpk.data(), a_xsk.data()
            ),
            0
        );
        DumpHex("ls.c(mac|cipher)", c.data(), c.size());
        {
            std::vector<unsigned char> ls_box_afternm(c.size());
            std::vector<unsigned char> ls_secretbox_easy(c.size());
            CHECK_EQ(
                crypto_box_easy_afternm(
                    ls_box_afternm.data(), msg.data(), msg.size(), nonce.data(), lk.data()
                ),
                0
            );
            CHECK_EQ(
                crypto_secretbox_easy(
                    ls_secretbox_easy.data(), msg.data(), msg.size(), nonce.data(), lk.data()
                ),
                0
            );
            DumpHex("ls.box_afternm.c", ls_box_afternm.data(), ls_box_afternm.size());
            DumpHex("ls.secretbox_easy.c", ls_secretbox_easy.data(), ls_secretbox_easy.size());
        }
        CHECK_EQ(
            crypto_box_open_easy(
                out.data(), c.data(), c.size(), nonce.data(), a_xpk.data(), b_xsk.data()
            ),
            0
        );
        CHECK(out == msg);

        // baseline: naion encrypt -> naion decrypt
        std::fill(c.begin(), c.end(), 0);
        std::fill(out.begin(), out.end(), 0);
        CHECK_EQ(
            naion_box_curve25519xsalsa20poly1305_easy(
                c.data(), msg.data(), msg.size(), nonce.data(), b_xpk.data(), a_xsk.data()
            ),
            0
        );
        DumpHex("na.c(mac|cipher)", c.data(), c.size());
        CHECK_EQ(
            naion_box_curve25519xsalsa20poly1305_open_easy(
                out.data(), c.data(), c.size(), nonce.data(), a_xpk.data(), b_xsk.data()
            ),
            0
        );
        CHECK(out == msg);

        // libsodium encrypt -> naion decrypt
        CHECK_EQ(
            crypto_box_easy(
                c.data(), msg.data(), msg.size(), nonce.data(), b_xpk.data(), a_xsk.data()
            ),
            0
        );
        DumpHex("ls->na.c", c.data(), c.size());
        CHECK_EQ(
            naion_box_curve25519xsalsa20poly1305_open_easy(
                out.data(), c.data(), c.size(), nonce.data(), a_xpk.data(), b_xsk.data()
            ),
            0
        );
        CHECK(out == msg);

        // naion encrypt -> libsodium decrypt
        std::fill(c.begin(), c.end(), 0);
        std::fill(out.begin(), out.end(), 0);
        CHECK_EQ(
            naion_box_curve25519xsalsa20poly1305_easy(
                c.data(), msg.data(), msg.size(), nonce.data(), b_xpk.data(), a_xsk.data()
            ),
            0
        );
        DumpHex("na->ls.c", c.data(), c.size());
        CHECK_EQ(crypto_box_open_easy(out.data(), c.data(), c.size(), nonce.data(), a_xpk.data(), b_xsk.data()), 0);
        CHECK(out == msg);
    }

    TEST_CASE("naion_box default dispatch matches libsodium family by gUseXChaCha20") {
        const auto seed_a = FixedSeed<32>(0x12);
        const auto seed_b = FixedSeed<32>(0x34);

        std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> a_edpk{};
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES> a_edsk{};
        std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> b_edpk{};
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES> b_edsk{};
        CHECK_EQ(crypto_sign_seed_keypair(a_edpk.data(), a_edsk.data(), seed_a.data()), 0);
        CHECK_EQ(crypto_sign_seed_keypair(b_edpk.data(), b_edsk.data(), seed_b.data()), 0);

        std::array<unsigned char, naion_box_PUBLICKEYBYTES_MAX> a_xpk{};
        std::array<unsigned char, naion_box_SECRETKEYBYTES_MAX> a_xsk{};
        std::array<unsigned char, naion_box_PUBLICKEYBYTES_MAX> b_xpk{};
        std::array<unsigned char, naion_box_SECRETKEYBYTES_MAX> b_xsk{};
        CHECK_EQ(naion_sign_ed25519_pk_to_curve25519(a_xpk.data(), a_edpk.data()), 0);
        CHECK_EQ(naion_sign_ed25519_sk_to_curve25519(a_xsk.data(), a_edsk.data()), 0);
        CHECK_EQ(naion_sign_ed25519_pk_to_curve25519(b_xpk.data(), b_edpk.data()), 0);
        CHECK_EQ(naion_sign_ed25519_sk_to_curve25519(b_xsk.data(), b_edsk.data()), 0);

        std::array<unsigned char, naion_box_NONCEBYTES_MAX> nonce{};
        for (size_t i = 0; i < nonce.size(); ++i) {
            nonce[i] = static_cast<unsigned char>(0xa0 + i);
        }
        const std::vector<unsigned char> msg{
            'a', 'l', 'i', 'a', 's', '-', 'b', 'o', 'x'
        };
        std::vector<unsigned char> c1(msg.size() + naion_box_MACBYTES_MAX);
        std::vector<unsigned char> c2(msg.size() + naion_box_MACBYTES_MAX);
        std::vector<unsigned char> out(msg.size());

        for (const int mode: {0, 1}) {
            NaionBoxModeGuard guard(mode);
            CHECK_EQ(naion_get_use_xchacha20(), mode);
            CHECK_EQ(naion_box_get_use_xchacha20(), mode);
            CHECK_EQ(naion_box_publickeybytes(), static_cast<size_t>(crypto_box_PUBLICKEYBYTES));
            CHECK_EQ(naion_box_secretkeybytes(), static_cast<size_t>(crypto_box_SECRETKEYBYTES));
            CHECK_EQ(naion_box_noncebytes(), static_cast<size_t>(crypto_box_NONCEBYTES));
            CHECK_EQ(naion_box_macbytes(), static_cast<size_t>(crypto_box_MACBYTES));

            std::fill(c1.begin(), c1.end(), 0);
            std::fill(c2.begin(), c2.end(), 0);
            std::fill(out.begin(), out.end(), 0);

            // (1) same input -> naion_box_* output must match corresponding libsodium family
            CHECK_EQ(
                naion_box_easy(c1.data(), msg.data(), msg.size(), nonce.data(), b_xpk.data(), a_xsk.data()),
                0
            );
            if (mode == 0) {
                CHECK_EQ(
                    crypto_box_easy(
                        c2.data(), msg.data(), msg.size(), nonce.data(), b_xpk.data(), a_xsk.data()
                    ),
                    0
                );
            } else {
                CHECK_EQ(
                    crypto_box_curve25519xchacha20poly1305_easy(
                        c2.data(), msg.data(), msg.size(), nonce.data(), b_xpk.data(), a_xsk.data()
                    ),
                    0
                );
            }
            CHECK(c1 == c2);

            // (2) libsodium encrypt -> naion_box_open_easy decrypt
            std::fill(out.begin(), out.end(), 0);
            if (mode == 0) {
                CHECK_EQ(
                    crypto_box_easy(
                        c2.data(), msg.data(), msg.size(), nonce.data(), b_xpk.data(), a_xsk.data()
                    ),
                    0
                );
            } else {
                CHECK_EQ(
                    crypto_box_curve25519xchacha20poly1305_easy(
                        c2.data(), msg.data(), msg.size(), nonce.data(), b_xpk.data(), a_xsk.data()
                    ),
                    0
                );
            }
            CHECK_EQ(
                naion_box_open_easy(out.data(), c2.data(), c2.size(), nonce.data(), a_xpk.data(), b_xsk.data()),
                0
            );
            CHECK(out == msg);

            // (3) naion_box_easy encrypt -> libsodium corresponding family decrypt
            std::fill(c1.begin(), c1.end(), 0);
            std::fill(out.begin(), out.end(), 0);
            CHECK_EQ(
                naion_box_easy(c1.data(), msg.data(), msg.size(), nonce.data(), b_xpk.data(), a_xsk.data()),
                0
            );
            if (mode == 0) {
                CHECK_EQ(
                    crypto_box_open_easy(out.data(), c1.data(), c1.size(), nonce.data(), a_xpk.data(), b_xsk.data()),
                    0
                );
            } else {
                CHECK_EQ(
                    crypto_box_curve25519xchacha20poly1305_open_easy(
                        out.data(), c1.data(), c1.size(), nonce.data(), a_xpk.data(), b_xsk.data()
                    ),
                    0
                );
            }
            CHECK(out == msg);
        }
    }

    TEST_CASE("aead_xchacha20poly1305_ietf combined interop matches libsodium") {
        const auto key = FixedSeed<crypto_aead_xchacha20poly1305_ietf_KEYBYTES>(0x61);
        std::array<unsigned char, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES> nonce{};
        for (size_t i = 0; i < nonce.size(); ++i) {
            nonce[i] = static_cast<unsigned char>(0xb0 + i);
        }
        const std::vector<unsigned char> msg{
            'a','e','a','d','-','x','c','h','a','c','h','a','2','0'
        };
        const std::vector<unsigned char> ad{
            'h','d','r','-','d','a','t','a'
        };
        std::vector<unsigned char> ls(msg.size() + crypto_aead_xchacha20poly1305_ietf_ABYTES);
        std::vector<unsigned char> na(msg.size() + naion_aead_xchacha20poly1305_ietf_ABYTES);
        std::vector<unsigned char> out(msg.size());
        unsigned long long clen = 0;
        unsigned long long mlen = 0;

        CHECK_EQ(
            crypto_aead_xchacha20poly1305_ietf_encrypt(
                ls.data(), &clen, msg.data(), msg.size(), ad.data(), ad.size(), nullptr, nonce.data(), key.data()
            ),
            0
        );
        REQUIRE(clen == ls.size());

        CHECK_EQ(
            naion_aead_xchacha20poly1305_ietf_encrypt(
                na.data(), &clen, msg.data(), msg.size(), ad.data(), ad.size(), nullptr, nonce.data(), key.data()
            ),
            0
        );
        REQUIRE(clen == na.size());
        if (na != ls) {
            DumpHex("ls.aead", ls.data(), ls.size());
            DumpHex("na.aead", na.data(), na.size());
        }
        CHECK(na == ls);

        CHECK_EQ(
            naion_aead_xchacha20poly1305_ietf_decrypt(
                out.data(), &mlen, nullptr, ls.data(), ls.size(), ad.data(), ad.size(), nonce.data(), key.data()
            ),
            0
        );
        REQUIRE(mlen == msg.size());
        CHECK(out == msg);

        std::fill(out.begin(), out.end(), 0);
        CHECK_EQ(
            crypto_aead_xchacha20poly1305_ietf_decrypt(
                out.data(), &mlen, nullptr, na.data(), na.size(), ad.data(), ad.size(), nonce.data(), key.data()
            ),
            0
        );
        REQUIRE(mlen == msg.size());
        CHECK(out == msg);
    }
    TEST_CASE("secretbox_xsalsa20poly1305 interop works both directions") {
        const auto key = FixedSeed<crypto_secretbox_KEYBYTES>(0x71);
        std::array<unsigned char, crypto_secretbox_NONCEBYTES> nonce{};
        for (size_t i = 0; i < nonce.size(); ++i) {
            nonce[i] = static_cast<unsigned char>(0x90 + i);
        }
        const std::vector<unsigned char> msg{
            's', 'e', 'c', 'r', 'e', 't', 'b', 'o', 'x', '-', 'i', 'n', 't', 'e', 'r', 'o', 'p'
        };
        std::vector<unsigned char> c(msg.size() + crypto_secretbox_MACBYTES);
        std::vector<unsigned char> out(msg.size());

        // libsodium easy -> naion open_easy
        std::fill(c.begin(), c.end(), 0);
        std::fill(out.begin(), out.end(), 0);
        CHECK_EQ(
            crypto_secretbox_easy(
                c.data(), msg.data(), msg.size(), nonce.data(), key.data()
            ),
            0
        );
        CHECK_EQ(
            naion_secretbox_xsalsa20poly1305_open_easy(
                out.data(), c.data(), c.size(), nonce.data(), key.data()
            ),
            0
        );
        CHECK(out == msg);

        // naion easy -> libsodium open_easy
        std::fill(c.begin(), c.end(), 0);
        std::fill(out.begin(), out.end(), 0);
        CHECK_EQ(
            naion_secretbox_xsalsa20poly1305_easy(
                c.data(), msg.data(), msg.size(), nonce.data(), key.data()
            ),
            0
        );
        CHECK_EQ(
            crypto_secretbox_open_easy(
                out.data(), c.data(), c.size(), nonce.data(), key.data()
            ),
            0
        );
        CHECK(out == msg);

        // libsodium detached -> naion open_detached
        {
            std::vector<unsigned char> cipher(msg.size());
            std::array<unsigned char, crypto_secretbox_MACBYTES> mac{};
            std::fill(out.begin(), out.end(), 0);
            CHECK_EQ(
                crypto_secretbox_detached(
                    cipher.data(), mac.data(), msg.data(), msg.size(), nonce.data(), key.data()
                ),
                0
            );
            CHECK_EQ(
                naion_secretbox_xsalsa20poly1305_open_detached(
                    out.data(), cipher.data(), mac.data(), cipher.size(), nonce.data(), key.data()
                ),
                0
            );
            CHECK(out == msg);
        }

        // naion detached -> libsodium open_detached
        {
            std::vector<unsigned char> cipher(msg.size());
            std::array<unsigned char, crypto_secretbox_MACBYTES> mac{};
            std::fill(out.begin(), out.end(), 0);
            CHECK_EQ(
                naion_secretbox_xsalsa20poly1305_detached(
                    cipher.data(), mac.data(), msg.data(), msg.size(), nonce.data(), key.data()
                ),
                0
            );
            CHECK_EQ(
                crypto_secretbox_open_detached(
                    out.data(), cipher.data(), mac.data(), cipher.size(), nonce.data(), key.data()
                ),
                0
            );
            CHECK(out == msg);
        }
    }

    TEST_CASE("Randomized variable-size interop for hash and encryption") {
        std::mt19937_64 rng(0x6e61696f6eULL);
        const std::array<size_t, 6> sizes{0, 1, 31, 32, 97, 257};

        // keys for secretbox / box
        const auto secretbox_key = FixedSeed<crypto_secretbox_KEYBYTES>(0x51);
        std::array<unsigned char, crypto_secretbox_NONCEBYTES> sb_nonce{};
        for (auto &b: sb_nonce) {
            b = static_cast<unsigned char>(rng() & 0xffU);
        }

        const auto seed_a = FixedSeed<32>(0x22);
        const auto seed_b = FixedSeed<32>(0x42);
        std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> a_edpk{};
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES> a_edsk{};
        std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> b_edpk{};
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES> b_edsk{};
        CHECK_EQ(crypto_sign_seed_keypair(a_edpk.data(), a_edsk.data(), seed_a.data()), 0);
        CHECK_EQ(crypto_sign_seed_keypair(b_edpk.data(), b_edsk.data(), seed_b.data()), 0);
        std::array<unsigned char, crypto_box_PUBLICKEYBYTES> a_xpk{};
        std::array<unsigned char, crypto_box_SECRETKEYBYTES> a_xsk{};
        std::array<unsigned char, crypto_box_PUBLICKEYBYTES> b_xpk{};
        std::array<unsigned char, crypto_box_SECRETKEYBYTES> b_xsk{};
        CHECK_EQ(crypto_sign_ed25519_pk_to_curve25519(a_xpk.data(), a_edpk.data()), 0);
        CHECK_EQ(crypto_sign_ed25519_sk_to_curve25519(a_xsk.data(), a_edsk.data()), 0);
        CHECK_EQ(crypto_sign_ed25519_pk_to_curve25519(b_xpk.data(), b_edpk.data()), 0);
        CHECK_EQ(crypto_sign_ed25519_sk_to_curve25519(b_xsk.data(), b_edsk.data()), 0);
        std::array<unsigned char, crypto_box_NONCEBYTES> box_nonce{};
        for (auto &b: box_nonce) {
            b = static_cast<unsigned char>(rng() & 0xffU);
        }

        for (const auto mlen: sizes) {
            std::vector<unsigned char> msg(mlen);
            FillRandom(msg, rng);

            // generichash one-shot and streaming
            {
                std::array<unsigned char, crypto_generichash_BYTES> l_one{};
                std::array<unsigned char, naion_generichash_BYTES> n_one{};
                CHECK_EQ(
                    crypto_generichash(l_one.data(), l_one.size(), msg.data(), msg.size(), nullptr, 0),
                    0
                );
                CHECK_EQ(
                    naion_generichash(n_one.data(), n_one.size(), msg.data(), msg.size(), nullptr, 0),
                    0
                );
                CHECK(std::memcmp(l_one.data(), n_one.data(), l_one.size()) == 0);

                constexpr size_t outlen = 48;
                std::array<unsigned char, outlen> l_stream{};
                std::array<unsigned char, outlen> n_stream{};
                const auto hash_key = FixedSeed<crypto_generichash_KEYBYTES>(0x33);
                crypto_generichash_state ls{};
                naion_generichash_state ns{};
                const size_t split = mlen / 2;
                CHECK_EQ(crypto_generichash_init(&ls, hash_key.data(), hash_key.size(), outlen), 0);
                CHECK_EQ(naion_generichash_init(&ns, hash_key.data(), hash_key.size(), outlen), 0);
                CHECK_EQ(crypto_generichash_update(&ls, msg.data(), split), 0);
                CHECK_EQ(naion_generichash_update(&ns, msg.data(), split), 0);
                CHECK_EQ(crypto_generichash_update(&ls, msg.data() + split, msg.size() - split), 0);
                CHECK_EQ(naion_generichash_update(&ns, msg.data() + split, msg.size() - split), 0);
                CHECK_EQ(crypto_generichash_final(&ls, l_stream.data(), outlen), 0);
                CHECK_EQ(naion_generichash_final(&ns, n_stream.data(), outlen), 0);
                CHECK(std::memcmp(l_stream.data(), n_stream.data(), outlen) == 0);
            }

            // secretbox easy cross-open
            {
                std::vector<unsigned char> c(msg.size() + crypto_secretbox_MACBYTES);
                std::vector<unsigned char> out(msg.size());
                unsigned char out_dummy = 0U;
                unsigned char *out_ptr = out.empty() ? &out_dummy : out.data();
                CHECK_EQ(
                    crypto_secretbox_easy(
                        c.data(), msg.data(), msg.size(), sb_nonce.data(), secretbox_key.data()
                    ),
                    0
                );
                CHECK_EQ(
                    naion_secretbox_xsalsa20poly1305_open_easy(
                        out_ptr, c.data(), c.size(), sb_nonce.data(), secretbox_key.data()
                    ),
                    0
                );
                CHECK(out == msg);

                CHECK_EQ(
                    naion_secretbox_xsalsa20poly1305_easy(
                        c.data(), msg.data(), msg.size(), sb_nonce.data(), secretbox_key.data()
                    ),
                    0
                );
                CHECK_EQ(
                    crypto_secretbox_open_easy(
                        out_ptr, c.data(), c.size(), sb_nonce.data(), secretbox_key.data()
                    ),
                    0
                );
                CHECK(out == msg);
            }

            // box easy cross-open
            {
                std::vector<unsigned char> c(msg.size() + crypto_box_MACBYTES);
                std::vector<unsigned char> out(msg.size());
                unsigned char out_dummy = 0U;
                unsigned char *out_ptr = out.empty() ? &out_dummy : out.data();
                CHECK_EQ(
                    crypto_box_easy(
                        c.data(), msg.data(), msg.size(), box_nonce.data(), b_xpk.data(), a_xsk.data()
                    ),
                    0
                );
                CHECK_EQ(
                    naion_box_curve25519xsalsa20poly1305_open_easy(
                        out_ptr, c.data(), c.size(), box_nonce.data(), a_xpk.data(), b_xsk.data()
                    ),
                    0
                );
                CHECK(out == msg);

                CHECK_EQ(
                    naion_box_curve25519xsalsa20poly1305_easy(
                        c.data(), msg.data(), msg.size(), box_nonce.data(), b_xpk.data(), a_xsk.data()
                    ),
                    0
                );
                CHECK_EQ(
                    crypto_box_open_easy(
                        out_ptr, c.data(), c.size(), box_nonce.data(), a_xpk.data(), b_xsk.data()
                    ),
                    0
                );
                CHECK(out == msg);
            }
        }
    }

    TEST_CASE("Detached signature verify works both directions") {
        const auto seed = FixedSeed<32>(0x61);
        std::array<unsigned char, crypto_sign_PUBLICKEYBYTES> pk{};
        std::array<unsigned char, crypto_sign_SECRETKEYBYTES> sk{};
        CHECK_EQ(crypto_sign_seed_keypair(pk.data(), sk.data(), seed.data()), 0);

        const std::vector<unsigned char> msg{
            'i', 'n', 't', 'e', 'r', 'o', 'p', '-', 's', 'i', 'g', 'n'
        };
        std::array<unsigned char, crypto_sign_BYTES> sig{};
        unsigned long long siglen = 0ULL;

        // libsodium sign -> naion verify
        CHECK_EQ(crypto_sign_detached(sig.data(), &siglen, msg.data(), msg.size(), sk.data()), 0);
        CHECK_EQ(siglen, static_cast<unsigned long long>(crypto_sign_BYTES));
        CHECK_EQ(naion_sign_ed25519_verify_detached(sig.data(), msg.data(), msg.size(), pk.data()), 0);

        // naion sign -> libsodium verify
        sig.fill(0);
        siglen = 0ULL;
        CHECK_EQ(naion_sign_ed25519_detached(sig.data(), &siglen, msg.data(), msg.size(), sk.data()), 0);
        CHECK_EQ(siglen, static_cast<unsigned long long>(crypto_sign_BYTES));
        CHECK_EQ(crypto_sign_verify_detached(sig.data(), msg.data(), msg.size(), pk.data()), 0);
    }
}
