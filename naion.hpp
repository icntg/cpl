#ifndef CPL_NAION_HPP_SUBSTITUTE_SODIUM_COMPATIBLE_WRAPPER
#define CPL_NAION_HPP_SUBSTITUTE_SODIUM_COMPATIBLE_WRAPPER

#include <array>
#include <chrono>
#include <memory>

#include "base.hpp"
#include "strings.hpp"
#include "crypto.hpp"
#include "naion/naion.h"
#include "naion/csm.h"

namespace cpl {
    namespace naion {
        inline Int32Result RandomBytesBuf(void *const buf, const size_t size) {
            if (buf == nullptr || size == 0U) {
                return Err(Error::NullPointer, "[X] RandomBytesBuf" CPL_FILE_AND_LINE);
            }
            const auto provider = naion_get_random_provider();
            if (provider) {
                provider(buf, size);
            }
            return 0;
        }

        class Errors final {
        public:
            static constexpr int64_t base = static_cast<int64_t>(4) << 32;
            static constexpr cpl::Error::CodeDef CryptoBoxEasy = {base | 1};
            static constexpr cpl::Error::CodeDef CryptoBoxOpenEasy = {base | 2};
            static constexpr cpl::Error::CodeDef CryptoSignDetached = {base | 3};
            static constexpr cpl::Error::CodeDef CryptoSignVerifyDetached = {base | 4};
            static constexpr cpl::Error::CodeDef CryptoSignSeedKeypair = {base | 5};
            static constexpr cpl::Error::CodeDef CryptoSignED25519PKtoCurve25519 = {base | 6};
            static constexpr cpl::Error::CodeDef CryptoSignED25519SKtoCurve25519 = {base | 7};
            static constexpr cpl::Error::CodeDef CryptoBoxKeypair = {base | 8};
            static constexpr cpl::Error::CodeDef CryptoGenericHash = {base | 9};
            static constexpr cpl::Error::CodeDef InvalidFormat = {base | 11};
            static constexpr cpl::Error::CodeDef CsmClientCreate = {base | 12};
            static constexpr cpl::Error::CodeDef CsmClientEncrypt = {base | 13};
        };

        // ed25519
        using ESK = std::array<uint8_t, naion_sign_ed25519_SECRETKEYBYTES>;
        using ESD = std::array<uint8_t, naion_sign_ed25519_SEEDBYTES>;
        using EPK = std::array<uint8_t, naion_sign_ed25519_PUBLICKEYBYTES>;

        // x25519 / curve25519
        using XSK = std::array<uint8_t, naion_box_SECRETKEYBYTES_MAX>;
        using XPK = std::array<uint8_t, naion_box_PUBLICKEYBYTES_MAX>;

#pragma pack(push, 1)
        struct PacketMeta final {
            std::array<uint8_t, 4> magic{{'I', 'F', 'W', '1'}};
            uint8_t protocolVersion{1};
            uint8_t reserved{0};
            uint16_t flags{0};
            uint64_t timestampMs{0};
        };
#pragma pack(pop)

        static_assert(sizeof(PacketMeta) == 16, "PacketMeta must remain compact");

        static constexpr size_t MaxUDPDatagramBytes = 1024;
        static constexpr uint8_t PacketProtocolVersion = 1;
        static constexpr size_t PacketFixedOverheadBytes =
                naion_sign_ed25519_BYTES + naion_box_PUBLICKEYBYTES_MAX +
                naion_box_NONCEBYTES_MAX + naion_box_MACBYTES_MAX;
        static constexpr size_t ClientPacketFixedBytes =
                PacketFixedOverheadBytes + sizeof(PacketMeta) + naion_sign_ed25519_PUBLICKEYBYTES;
        static constexpr size_t ServerPacketFixedBytes =
                PacketFixedOverheadBytes + sizeof(PacketMeta);
        static constexpr size_t MaxClientPayloadBytes = MaxUDPDatagramBytes - ClientPacketFixedBytes;
        static constexpr size_t MaxServerPayloadBytes = MaxUDPDatagramBytes - ServerPacketFixedBytes;

        class Utility final {
        public:
            static uint64_t CurrentTimestampMs() {
                const auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now()
                );
                return static_cast<uint64_t>(now.time_since_epoch().count());
            }

            static PacketMeta CreatePacketMeta() {
                PacketMeta meta{};
                meta.protocolVersion = PacketProtocolVersion;
                meta.timestampMs = CurrentTimestampMs();
                return meta;
            }

            static Result<size_t> ParsePacketMeta(
                _In_ const Stream &buffer,
                _Out_ PacketMeta &outMeta
            ) {
                if (buffer.size() < sizeof(PacketMeta)) {
                    return Err(cpl::Error(Errors::InvalidFormat, "[X] PacketMeta buffer too short" CPL_FILE_AND_LINE));
                }

                std::memmove(&outMeta, buffer.data(), sizeof(PacketMeta));
                if (outMeta.magic != PacketMeta{}.magic) {
                    return Err(cpl::Error(Errors::InvalidFormat, "[X] PacketMeta magic invalid" CPL_FILE_AND_LINE));
                }
                if (outMeta.protocolVersion != PacketProtocolVersion) {
                    return Err(cpl::Error(Errors::InvalidFormat, "[X] PacketMeta version invalid" CPL_FILE_AND_LINE));
                }
                return sizeof(PacketMeta);
            }
            static Result<Stream> Seal(
                _In_ const Stream &plaintext,
                _In_ const XPK &publicKeyBob,
                _In_ const XSK &secretKeyAlice
            ) {
                if (plaintext.empty()) {
                    return Err(cpl::Error(cpl::Error::NoData, "[X] Seal plaintext is empty" CPL_FILE_AND_LINE));
                }

                Stream encrypted;
                encrypted.resize(naion_box_NONCEBYTES_MAX + plaintext.size() + naion_box_MACBYTES_MAX);

                uint8_t nonce[naion_box_NONCEBYTES_MAX]{};
                RandomBytesBuf(nonce, sizeof(nonce));

                const auto r00 = naion_box_easy(
                    encrypted.data() + naion_box_NONCEBYTES_MAX,
                    plaintext.data(),
                    plaintext.size(),
                    nonce,
                    publicKeyBob.data(),
                    secretKeyAlice.data()
                );
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Seal naion_box_easy failed [%d]" CPL_FILE_AND_LINE, r00
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
                if (ciphertext.size() <= naion_box_NONCEBYTES_MAX + naion_box_MACBYTES_MAX) {
                    auto es = strings::Format(
                        "[X] Open ciphertext size [%lu] is too short" CPL_FILE_AND_LINE,
                        static_cast<uint32_t>(ciphertext.size())
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Error::OutOfRange, es.value<>());
                }

                const auto plaintextSize = ciphertext.size() - naion_box_NONCEBYTES_MAX - naion_box_MACBYTES_MAX;
                Stream plaintext;
                plaintext.resize(plaintextSize);

                const auto nonce = ciphertext.data();
                const auto trueCiphertext = ciphertext.data() + naion_box_NONCEBYTES_MAX;
                const auto r00 = naion_box_open_easy(
                    plaintext.data(),
                    trueCiphertext,
                    plaintextSize + naion_box_MACBYTES_MAX,
                    nonce,
                    publicKeyAlice.data(),
                    secretKeyBob.data()
                );
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Open naion_box_open_easy failed [%d]" CPL_FILE_AND_LINE, r00
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
                signature.resize(naion_sign_ed25519_BYTES);

                unsigned long long signature_len = 0;
                const auto r00 = naion_sign_ed25519_detached(
                    signature.data(),
                    &signature_len,
                    buffer.data(),
                    buffer.size(),
                    edSecKey.data()
                );
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Sign naion_sign_ed25519_detached failed [%d]" CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignDetached, es.value<>());
                }
                if (signature_len != naion_sign_ed25519_BYTES) {
                    return Err(cpl::Error(Errors::CryptoSignDetached,
                                          "[X] Unexpected signature length" CPL_FILE_AND_LINE));
                }
                return signature;
            }

            static Result<bool> Verify(
                _In_ const Stream &signature,
                _In_ const Stream &buffer,
                _In_ const EPK &edPubKey
            ) {
                if (signature.size() != naion_sign_ed25519_BYTES) {
                    return Err(cpl::Error(cpl::Error::InvalidArgument,
                                          "[X] Verify signature length invalid" CPL_FILE_AND_LINE));
                }
                const auto r00 = naion_sign_ed25519_verify_detached(
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
            csm_client csmClient{};

            Client() = default;

        public:
            static Result<std::unique_ptr<Client> > Create(
                _In_ const ESD &edSeedClient,
                _In_ const EPK &edPubKeyServer
            ) {
                auto instance = std::unique_ptr<Client>(new Client());

                instance->edSeedC = edSeedClient;
                instance->edPubKeyS = edPubKeyServer;

                const auto r00 = csm_init();
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Client Create csm_init failed [%d]"
                        CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmClientCreate, es.value<>());
                }

                const auto r01 = csm_client_create(
                    &instance->csmClient,
                    instance->edSeedC.data(),
                    instance->edPubKeyS.data()
                );
                if (r01 != CSM_OK) {
                    auto es = strings::Format(
                        "[X] Client Create csm_client_create failed [%d]"
                        CPL_FILE_AND_LINE, r01
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmClientCreate, es.value<>());
                }

                std::memmove(instance->edPubKeyC.data(), instance->csmClient.ed_public_key,
                             instance->edPubKeyC.size());
                std::memmove(instance->edSecKeyC.data(), instance->csmClient.ed_secret_key,
                             instance->edSecKeyC.size());

                return instance;
            }

            ~Client() override {
                csm_client_wipe(&this->csmClient);
            }

            Result<Stream> Encrypt(const Stream &in) override {
                if (in.empty()) {
                    return Err(cpl::Error(cpl::Error::NoData, "[X] Client Encrypt empty data" CPL_FILE_AND_LINE));
                }
                if (in.size() > MaxClientPayloadBytes) {
                    return Err(cpl::Error(Error::OutOfRange, "[X] Client Encrypt payload too large" CPL_FILE_AND_LINE));
                }

                Stream out(csm_client_encrypt_size(in.size()));
                size_t outSize = 0;
                const auto r00 = csm_client_encrypt(
                    &this->csmClient,
                    in.data(),
                    in.size(),
                    out.data(),
                    out.size(),
                    &outSize
                );
                if (r00 != CSM_OK) {
                    auto es = strings::Format(
                        "[X] Client Encrypt csm_client_encrypt failed [%d]" CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmClientEncrypt, es.value<>());
                }
                out.resize(outSize);
                return out;
            }

            Result<Stream> Decrypt(const Stream &in) override {
                static constexpr size_t MIN_SIZE =
                        naion_sign_ed25519_BYTES + naion_box_PUBLICKEYBYTES_MAX +
                        naion_box_NONCEBYTES_MAX + naion_box_MACBYTES_MAX + sizeof(PacketMeta);
                if (in.size() <= MIN_SIZE) {
                    auto es = strings::Format(
                        "[X] Client Decrypt stream (%lu) <= MIN_SIZE (%lu)" CPL_FILE_AND_LINE,
                        static_cast<uint32_t>(in.size()),
                        static_cast<uint32_t>(MIN_SIZE)
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Error::OutOfRange, es.value<>());
                }

                const Stream signature{in.data(), in.data() + naion_sign_ed25519_BYTES};
                const Stream toVerify{in.data() + naion_sign_ed25519_BYTES, in.data() + in.size()};
                const auto vr = Utility::Verify(signature, toVerify, this->edPubKeyS);
                if (!vr) {
                    return Err(vr.error());
                }
                if (!vr.value()) {
                    return Err(cpl::Error(Errors::CryptoSignVerifyDetached,
                                          "[X] Client Decrypt signature verify failed" CPL_FILE_AND_LINE));
                }

                XSK clientXsk{};
                const auto r00 = naion_sign_ed25519_sk_to_curve25519(clientXsk.data(), this->edSecKeyC.data());
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Client Decrypt naion_sign_ed25519_sk_to_curve25519 failed [%d]"
                        CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignED25519SKtoCurve25519, es.value<>());
                }

                XPK spk{};
                std::memmove(spk.data(), in.data() + naion_sign_ed25519_BYTES, naion_box_PUBLICKEYBYTES_MAX);
                const Stream ciphertext{
                    in.data() + naion_sign_ed25519_BYTES + naion_box_PUBLICKEYBYTES_MAX,
                    in.data() + in.size()
                };
                auto openRet = Utility::Open(ciphertext, spk, clientXsk);
                if (!openRet) {
                    return Err(openRet.error());
                }

                PacketMeta meta{};
                const auto metaRet = Utility::ParsePacketMeta(openRet.value(), meta);
                if (!metaRet) {
                    return Err(metaRet.error());
                }
                const auto &plaintextWithMeta = openRet.value();
                if (plaintextWithMeta.size() <= metaRet.value()) {
                    return Err(cpl::Error(Errors::InvalidFormat, "[X] Client Decrypt payload missing" CPL_FILE_AND_LINE));
                }

                Stream plaintext;
                plaintext.insert(
                    plaintext.end(),
                    plaintextWithMeta.begin() + static_cast<std::ptrdiff_t>(metaRet.value()),
                    plaintextWithMeta.end()
                );
                return plaintext;
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

                const auto r00 = naion_sign_ed25519_seed_keypair(
                    instance->edPubKeyS.data(),
                    instance->edSecKeyS.data(),
                    instance->edSeedS.data()
                );
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Server Create naion_sign_ed25519_seed_keypair failed [%d]"
                        CPL_FILE_AND_LINE, r00
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
                        naion_sign_ed25519_BYTES + naion_box_PUBLICKEYBYTES_MAX +
                        naion_box_NONCEBYTES_MAX + sizeof(PacketMeta) + naion_sign_ed25519_PUBLICKEYBYTES +
                        naion_box_MACBYTES_MAX;
                if (in.size() <= MIN_SIZE) {
                    auto es = strings::Format(
                        "[X] Server Decrypt stream (%lu) <= MIN_SIZE (%lu)" CPL_FILE_AND_LINE,
                        static_cast<uint32_t>(in.size()),
                        static_cast<uint32_t>(MIN_SIZE)
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Error::OutOfRange, es.value<>());
                }

                XSK serverX25519SK{};
                const auto r00 = naion_sign_ed25519_sk_to_curve25519(serverX25519SK.data(), this->edSecKeyS.data());
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Server Decrypt naion_sign_ed25519_sk_to_curve25519 failed [%d]"
                        CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignED25519SKtoCurve25519, es.value<>());
                }

                XPK sessionX25519PK{};
                std::memmove(sessionX25519PK.data(), in.data() + naion_sign_ed25519_BYTES,
                             naion_box_PUBLICKEYBYTES_MAX);

                const Stream ciphertext{
                    in.data() + naion_sign_ed25519_BYTES + naion_box_PUBLICKEYBYTES_MAX,
                    in.data() + in.size()
                };
                auto openRet = Utility::Open(ciphertext, sessionX25519PK, serverX25519SK);
                if (!openRet) {
                    return Err(openRet.error());
                }

                const auto &plaintextWithMeta = openRet.value();
                PacketMeta meta{};
                const auto metaRet = Utility::ParsePacketMeta(plaintextWithMeta, meta);
                if (!metaRet) {
                    return Err(metaRet.error());
                }

                if (plaintextWithMeta.size() < metaRet.value() + naion_sign_ed25519_PUBLICKEYBYTES + 1) {
                    return Err(cpl::Error(Errors::InvalidFormat,
                                          "[X] Server Decrypt payload too short" CPL_FILE_AND_LINE));
                }

                EPK clientPubKey{};
                std::memmove(
                    clientPubKey.data(),
                    plaintextWithMeta.data() + metaRet.value(),
                    naion_sign_ed25519_PUBLICKEYBYTES
                );

                const Stream signature{in.data(), in.data() + naion_sign_ed25519_BYTES};
                const Stream toVerify{in.data() + naion_sign_ed25519_BYTES, in.data() + in.size()};
                const auto vr = Utility::Verify(signature, toVerify, clientPubKey);
                if (!vr) {
                    return Err(vr.error());
                }
                if (!vr.value()) {
                    return Err(cpl::Error(Errors::CryptoSignVerifyDetached,
                                          "[X] Server Decrypt signature verify failed" CPL_FILE_AND_LINE));
                }

                this->edPubKeyC = clientPubKey;
                this->ed25519PublicKeyClientInitialized = true;

                Stream plaintext;
                plaintext.insert(
                    plaintext.end(),
                    plaintextWithMeta.begin() + static_cast<std::ptrdiff_t>(metaRet.value() + naion_sign_ed25519_PUBLICKEYBYTES),
                    plaintextWithMeta.end()
                );
                return plaintext;
            }

            Result<Stream> Encrypt(const Stream &in) override {
                if (in.empty()) {
                    return Err(cpl::Error(cpl::Error::NoData, "[X] Server Encrypt empty data" CPL_FILE_AND_LINE));
                }
                if (in.size() > MaxServerPayloadBytes) {
                    return Err(cpl::Error(Error::OutOfRange, "[X] Server Encrypt payload too large" CPL_FILE_AND_LINE));
                }
                if (!this->ed25519PublicKeyClientInitialized) {
                    return Err(cpl::Error(cpl::Error::NoData,
                                          "[X] Server Encrypt client public key is not initialized" CPL_FILE_AND_LINE));
                }

                XPK clientXpk{};
                const auto r00 = naion_sign_ed25519_pk_to_curve25519(clientXpk.data(), this->edPubKeyC.data());
                if (r00 != 0) {
                    auto es = strings::Format(
                        "[X] Server Encrypt naion_sign_ed25519_pk_to_curve25519 failed [%d]"
                        CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoSignED25519PKtoCurve25519, es.value<>());
                }

                XSK ssk{};
                XPK spk{};
                const auto r01 = naion_box_keypair(spk.data(), ssk.data());
                if (r01 != 0) {
                    auto es = strings::Format(
                        "[X] Server Encrypt naion_box_keypair failed [%d]" CPL_FILE_AND_LINE, r01
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CryptoBoxKeypair, es.value<>());
                }

                Stream payload;
                const auto meta = Utility::CreatePacketMeta();
                payload.insert(
                    payload.end(),
                    reinterpret_cast<const uint8_t *>(&meta),
                    reinterpret_cast<const uint8_t *>(&meta) + sizeof(meta)
                );
                payload.insert(payload.end(), in.begin(), in.end());

                auto sealed = Utility::Seal(payload, clientXpk, ssk);
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

#endif // CPL_NAION_HPP_SUBSTITUTE_SODIUM_COMPATIBLE_WRAPPER
