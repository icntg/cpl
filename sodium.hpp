#ifndef CPL_SODIUM_HPP_INTRICATE_ELEPHANT_SPONTANEOUS_GOVERNMENT_TECHNICAL_CURRENCY_CALCULATE_POSITION
#define CPL_SODIUM_HPP_INTRICATE_ELEPHANT_SPONTANEOUS_GOVERNMENT_TECHNICAL_CURRENCY_CALCULATE_POSITION

#include <array>
#include <cerrno>
#include <cstring>
#include <memory>

#include "base.hpp"
#include "strings.hpp"
#include "crypto.hpp"
#define SODIUM_STATIC
#include "vendor/jedisct1/libsodium/sodium.h"

namespace cpl {
    namespace sodium {
        class Errors final {
        public:
            static constexpr int64_t base = static_cast<int64_t>(3) << 32;
            static constexpr cpl::Error::CodeDef CryptoBoxEasy = {base | 1};
            static constexpr cpl::Error::CodeDef CryptoBoxOpenEasy = {base | 2};
            static constexpr cpl::Error::CodeDef CryptoSignDetached = {base | 3};
            static constexpr cpl::Error::CodeDef CryptoSignVerifyDetached = {base | 4};
            static constexpr cpl::Error::CodeDef CryptoSignSeedKeypair = {base | 5};
            static constexpr cpl::Error::CodeDef CryptoSignED25519PKtoCurve25519 = {base | 6};
            static constexpr cpl::Error::CodeDef CryptoSignED25519SKtoCurve25519 = {base | 7};
            static constexpr cpl::Error::CodeDef CryptoBoxKeypair = {base | 8};
            static constexpr cpl::Error::CodeDef InvalidFormat = {base | 9};
        };

        // ed25519
        using ESK = std::array<uint8_t, crypto_sign_SECRETKEYBYTES>;
        using ESD = std::array<uint8_t, crypto_sign_SEEDBYTES>;
        using EPK = std::array<uint8_t, crypto_sign_PUBLICKEYBYTES>;

        // x25519 / curve25519
        using XSK = std::array<uint8_t, crypto_box_SECRETKEYBYTES>;
        using XPK = std::array<uint8_t, crypto_box_PUBLICKEYBYTES>;

        class Utility final {
        public:
            static Result<Stream> Seal(
                _In_ const Stream &plaintext,
                _In_ const XPK &publicKeyBob,
                _In_ const XSK &secretKeyAlice
            ) {
                if (plaintext.empty()) {
                    return Err(cpl::Error(cpl::Error::NoData, "[X] Seal plaintext is empty" CPL_FILE_AND_LINE));
                }

                Stream encrypted;
                encrypted.resize(crypto_box_NONCEBYTES + plaintext.size() + crypto_box_MACBYTES);

                uint8_t nonce[crypto_box_NONCEBYTES]{};
                randombytes_buf(nonce, sizeof(nonce));

                const auto r00 = crypto_box_easy(
                    encrypted.data() + crypto_box_NONCEBYTES,
                    plaintext.data(),
                    plaintext.size(),
                    nonce,
                    publicKeyBob.data(),
                    secretKeyAlice.data()
                );
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Seal crypto_box_easy failed [%d]" CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoBoxEasy, es.value<>());
                }
                std::memmove(encrypted.data(), nonce, sizeof(nonce));
                return encrypted;
            }

            static Result<Stream> Open(
                _In_ const Stream &ciphertext,
                _In_ const XPK &publicKeyAlice,
                _In_ const XSK &secretKeyBob
            ) {
                if (ciphertext.size() <= crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
                    const auto es = strings::Format(
                        "[X] Open ciphertext size [%lu] is too short" CPL_FILE_AND_LINE,
                        static_cast<uint32_t>(ciphertext.size())
                    ).value_or("[X] format failed" CPL_FILE_AND_LINE);
                    return Err(cpl::Error(cpl::Error::OutOfRange, es.c_str()));
                }

                const auto plaintextSize = ciphertext.size() - crypto_box_NONCEBYTES - crypto_box_MACBYTES;
                Stream plaintext;
                plaintext.resize(plaintextSize);

                const auto nonce = ciphertext.data();
                const auto trueCiphertext = ciphertext.data() + crypto_box_NONCEBYTES;
                const auto r00 = crypto_box_open_easy(
                    plaintext.data(),
                    trueCiphertext,
                    plaintextSize + crypto_box_MACBYTES,
                    nonce,
                    publicKeyAlice.data(),
                    secretKeyBob.data()
                );
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Open crypto_box_open_easy failed [%d]" CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoBoxOpenEasy, es.value<>());
                }
                return plaintext;
            }

            static Result<Stream> Sign(
                _In_ const Stream &buffer,
                _In_ const ESK &edSecKey
            ) {
                Stream signature;
                signature.resize(crypto_sign_BYTES);

                unsigned long long signature_len = 0;
                const auto r00 = crypto_sign_detached(
                    signature.data(),
                    &signature_len,
                    buffer.data(),
                    buffer.size(),
                    edSecKey.data()
                );
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Sign crypto_sign_detached failed [%d]" CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignDetached, es.value<>());
                }
                if (signature_len != crypto_sign_BYTES) {
                    return MakeErr(Errors::CryptoSignDetached,
                                   "[X] Unexpected signature length" CPL_FILE_AND_LINE);
                }
                return signature;
            }

            static Result<bool> Verify(
                _In_ const Stream &signature,
                _In_ const Stream &buffer,
                _In_ const EPK &edPubKey
            ) {
                if (signature.size() != crypto_sign_BYTES) {
                    return Err(cpl::Error(cpl::Error::InvalidArgument,
                                          "[X] Verify signature length invalid" CPL_FILE_AND_LINE));
                }
                const auto r00 = crypto_sign_verify_detached(
                    signature.data(),
                    buffer.data(),
                    buffer.size(),
                    edPubKey.data()
                );
                return r00 == 0;
            }
        };

        class Client final : public cpl::crypto::stl::ISync {
            ESD edSeedC{};
            ESK edSecKeyC{};
            EPK edPubKeyC{};
            EPK edPubKeyS{};

            Client() = default;

        public:
            static Result<std::unique_ptr<Client> > Create(
                _In_ const ESD &edSeedClient,
                _In_ const EPK &edPubKeyServer
            ) {
                auto instance = std::unique_ptr<Client>(new Client());

                instance->edSeedC = edSeedClient;
                instance->edPubKeyS = edPubKeyServer;

                const auto r00 = crypto_sign_seed_keypair(
                    instance->edPubKeyC.data(),
                    instance->edSecKeyC.data(),
                    instance->edSeedC.data()
                );
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Client Create crypto_sign_seed_keypair failed [%d]" CPL_FILE_AND_LINE,
                        r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignSeedKeypair, es.value<>());
                }

                return instance;
            }

            ~Client() override = default;

            Result<Stream> Encrypt(const Stream &in) override {
                if (in.empty()) {
                    return Err(cpl::Error(cpl::Error::NoData, "[X] Client Encrypt empty data" CPL_FILE_AND_LINE));
                }

                XPK serverXpk{};
                XSK ssk{};
                XPK spk{};

                const auto r00 = crypto_sign_ed25519_pk_to_curve25519(serverXpk.data(), this->edPubKeyS.data());
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Client Encrypt crypto_sign_ed25519_pk_to_curve25519 failed [%d]"
                        CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignED25519PKtoCurve25519, es.value<>());
                }

                const auto r01 = crypto_box_keypair(spk.data(), ssk.data());
                if (r01 != 0) {
                    auto es = strings::Format(
                        "[X] Client Encrypt crypto_box_keypair failed [%d]" CPL_FILE_AND_LINE, r01
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoBoxKeypair, es.value<>());
                }

                Stream payload;
                payload.insert(payload.end(), this->edPubKeyC.begin(), this->edPubKeyC.end());
                payload.insert(payload.end(), in.begin(), in.end());

                auto sealed = Utility::Seal(payload, serverXpk, ssk);
                if (!sealed) {
                    return Err(sealed.error());
                }

                Stream sessionCipher = sealed.value();
                sessionCipher.insert(sessionCipher.begin(), spk.begin(), spk.end());

                auto sig = Utility::Sign(sessionCipher, this->edSecKeyC);
                if (!sig) {
                    return Err(sig.error());
                }

                Stream out = sig.value();
                out.insert(out.end(), sessionCipher.begin(), sessionCipher.end());
                return out;
            }

            Result<Stream> Decrypt(const Stream &in) override {
                static constexpr size_t MIN_SIZE =
                        crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES + crypto_box_MACBYTES;
                if (in.size() <= MIN_SIZE) {
                    const auto es = strings::Format(
                        "[X] Client Decrypt stream (%lu) <= MIN_SIZE (%lu)" CPL_FILE_AND_LINE,
                        static_cast<uint32_t>(in.size()),
                        static_cast<uint32_t>(MIN_SIZE)
                    ).value_or("[X] format failed" CPL_FILE_AND_LINE);
                    return Err(cpl::Error(cpl::Error::OutOfRange, es.c_str()));
                }

                const Stream signature{in.data(), in.data() + crypto_sign_BYTES};
                const Stream toVerify{in.data() + crypto_sign_BYTES, in.data() + in.size()};
                const auto vr = Utility::Verify(signature, toVerify, this->edPubKeyS);
                if (!vr) {
                    return Err(vr.error());
                }
                if (!vr.value()) {
                    return Err(cpl::Error(Errors::CryptoSignVerifyDetached,
                                          "[X] Client Decrypt signature verify failed" CPL_FILE_AND_LINE));
                }

                XSK clientXsk{};
                const auto r00 = crypto_sign_ed25519_sk_to_curve25519(clientXsk.data(), this->edSecKeyC.data());
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Client Decrypt crypto_sign_ed25519_sk_to_curve25519 failed [%d]"
                        CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignED25519SKtoCurve25519, es.value<>());
                }

                XPK spk{};
                std::memmove(spk.data(), in.data() + crypto_sign_BYTES, crypto_box_PUBLICKEYBYTES);
                const Stream ciphertext{
                    in.data() + crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES,
                    in.data() + in.size()
                };
                return Utility::Open(ciphertext, spk, clientXsk);
            }
        };

        class Server final : public cpl::crypto::stl::ISync {
            ESD edSeedS{};
            ESK edSecKeyS{};
            EPK edPubKeyS{};
            EPK edPubKeyC{};
            bool ed25519PublicKeyClientInitialized{false};

            Server() = default;

        public:
            static Result<std::unique_ptr<Server> > Create(_In_ const ESD &edSeedS) {
                auto instance = std::unique_ptr<Server>(new Server());
                instance->edSeedS = edSeedS;

                const auto r00 = crypto_sign_seed_keypair(
                    instance->edPubKeyS.data(),
                    instance->edSecKeyS.data(),
                    instance->edSeedS.data()
                );
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Server Create crypto_sign_seed_keypair failed [%d]" CPL_FILE_AND_LINE,
                        r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignSeedKeypair, es.value<>());
                }
                return instance;
            }

            ~Server() override = default;

            Result<Stream> Decrypt(const Stream &in) override {
                static constexpr size_t MIN_SIZE =
                        crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES + crypto_box_NONCEBYTES +
                        crypto_sign_PUBLICKEYBYTES + crypto_box_MACBYTES;
                if (in.size() <= MIN_SIZE) {
                    const auto es = strings::Format(
                        "[X] Server Decrypt stream (%lu) <= MIN_SIZE (%lu)" CPL_FILE_AND_LINE,
                        static_cast<uint32_t>(in.size()),
                        static_cast<uint32_t>(MIN_SIZE)
                    ).value_or("[X] format failed" CPL_FILE_AND_LINE);
                    return Err(cpl::Error(cpl::Error::OutOfRange, es.c_str()));
                }

                XSK serverX25519SK{};
                const auto r00 = crypto_sign_ed25519_sk_to_curve25519(serverX25519SK.data(), this->edSecKeyS.data());
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Server Decrypt crypto_sign_ed25519_sk_to_curve25519 failed [%d]"
                        CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignED25519SKtoCurve25519, es.value<>());
                }

                XPK sessionX25519PK{};
                std::memmove(sessionX25519PK.data(), in.data() + crypto_sign_BYTES, crypto_box_PUBLICKEYBYTES);

                const Stream ciphertext{
                    in.data() + crypto_sign_BYTES + crypto_box_PUBLICKEYBYTES,
                    in.data() + in.size()
                };
                auto openRet = Utility::Open(ciphertext, sessionX25519PK, serverX25519SK);
                if (!openRet) {
                    return Err(openRet.error());
                }

                const auto &clientKeyAndPayload = openRet.value();
                if (clientKeyAndPayload.size() < crypto_sign_PUBLICKEYBYTES) {
                    return Err(cpl::Error(Errors::InvalidFormat,
                                          "[X] Server Decrypt payload too short" CPL_FILE_AND_LINE));
                }

                std::memmove(this->edPubKeyC.data(), clientKeyAndPayload.data(), crypto_sign_PUBLICKEYBYTES);
                this->ed25519PublicKeyClientInitialized = true;

                const Stream signature{in.data(), in.data() + crypto_sign_BYTES};
                const Stream toVerify{in.data() + crypto_sign_BYTES, in.data() + in.size()};
                const auto vr = Utility::Verify(signature, toVerify, this->edPubKeyC);
                if (!vr) {
                    return Err(vr.error());
                }
                if (!vr.value()) {
                    return Err(cpl::Error(Errors::CryptoSignVerifyDetached,
                                          "[X] Server Decrypt signature verify failed" CPL_FILE_AND_LINE));
                }

                Stream plaintext;
                plaintext.insert(
                    plaintext.end(),
                    clientKeyAndPayload.begin() + crypto_sign_PUBLICKEYBYTES,
                    clientKeyAndPayload.end()
                );
                return plaintext;
            }

            Result<Stream> Encrypt(const Stream &in) override {
                if (in.empty()) {
                    return Err(cpl::Error(cpl::Error::NoData, "[X] Server Encrypt empty data" CPL_FILE_AND_LINE));
                }
                if (!this->ed25519PublicKeyClientInitialized) {
                    return Err(cpl::Error(cpl::Error::NoData,
                                          "[X] Server Encrypt client public key is not initialized" CPL_FILE_AND_LINE));
                }

                XPK clientXpk{};
                const auto r00 = crypto_sign_ed25519_pk_to_curve25519(clientXpk.data(), this->edPubKeyC.data());
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Server Encrypt crypto_sign_ed25519_pk_to_curve25519 failed [%d]"
                        CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignED25519PKtoCurve25519, es.value<>());
                }

                XSK ssk{};
                XPK spk{};
                const auto r01 = crypto_box_keypair(spk.data(), ssk.data());
                if (r01 != 0) {
                    auto es = strings::Format(
                        "[X] Server Encrypt crypto_box_keypair failed [%d]" CPL_FILE_AND_LINE, r01
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoBoxKeypair, es.value<>());
                }

                auto sealed = Utility::Seal(in, clientXpk, ssk);
                if (!sealed) {
                    return Err(sealed.error());
                }
                Stream sessionCipher = sealed.value();
                sessionCipher.insert(sessionCipher.begin(), spk.begin(), spk.end());

                auto sig = Utility::Sign(sessionCipher, this->edSecKeyS);
                if (!sig) {
                    return Err(sig.error());
                }

                Stream out = sig.value();
                out.insert(out.end(), sessionCipher.begin(), sessionCipher.end());
                return out;
            }
        };
    }
}

#endif // CPL_SODIUM_HPP_INTRICATE_ELEPHANT_SPONTANEOUS_GOVERNMENT_TECHNICAL_CURRENCY_CALCULATE_POSITION
