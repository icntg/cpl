#ifndef CPL_NAION_HPP_SUBSTITUTE_SODIUM_COMPATIBLE_WRAPPER
#define CPL_NAION_HPP_SUBSTITUTE_SODIUM_COMPATIBLE_WRAPPER

#include <array>
#include <chrono>
#include <cstring>
#include <memory>

#include "base.hpp"
#include "strings.hpp"
#include "crypto.hpp"
#include "naion/naion.h"

namespace cpl {
    namespace naion {
        // One-time library initialisation. Idempotent; safe to call repeatedly.
        inline Int32Result Init() {
            return naion_init();
        }

        inline Int32Result RandomBytesBuf(void *const buf, const size_t size) {
            if (buf == nullptr || size == 0U) {
                return Err(Error::NullPointer(), "[X] RandomBytesBuf" CPL_FILE_AND_LINE);
            }
            // naion_get_random_provider() returns the built-in system provider
            // (CryptGenRandom on Windows, getrandom/urandom on POSIX) when no
            // custom provider has been installed, so this always yields real entropy.
            const auto provider = naion_get_random_provider();
            if (provider) {
                provider(buf, size);
                return 0;
            }
            return Err(Error::UnavailableAPI(), "[X] RandomBytesBuf no provider" CPL_FILE_AND_LINE);
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
            static constexpr cpl::Error::CodeDef CsmInit = {base | 12};
            static constexpr cpl::Error::CodeDef CsmClientCreate = {base | 13};
            static constexpr cpl::Error::CodeDef CsmClientEncrypt = {base | 14};
            static constexpr cpl::Error::CodeDef CsmClientDecrypt = {base | 15};
            static constexpr cpl::Error::CodeDef CsmServerCreate = {base | 16};
            static constexpr cpl::Error::CodeDef CsmServerEncrypt = {base | 17};
            static constexpr cpl::Error::CodeDef CsmServerDecrypt = {base | 18};
        };

        // ed25519
        using ESK = std::array<uint8_t, naion_sign_ed25519_SECRETKEYBYTES>;
        using ESD = std::array<uint8_t, naion_sign_ed25519_SEEDBYTES>;
        using EPK = std::array<uint8_t, naion_sign_ed25519_PUBLICKEYBYTES>;

        // x25519 / curve25519
        using XSK = std::array<uint8_t, naion_box_SECRETKEYBYTES_MAX>;
        using XPK = std::array<uint8_t, naion_box_PUBLICKEYBYTES_MAX>;

        // UDP datagram budget (protocol constant, mirrors NAION_CSM_* in naion.h).
        static constexpr size_t MaxUDPDatagramBytes = NAION_CSM_MAX_UDP_DATAGRAM_BYTES;
        static constexpr size_t MaxClientPayloadBytes = NAION_CSM_MAX_CLIENT_PAYLOAD_BYTES;
        static constexpr size_t MaxServerPayloadBytes = NAION_CSM_MAX_SERVER_PAYLOAD_BYTES;
        static constexpr size_t PacketOverheadBytes = NAION_CSM_PACKET_OVERHEAD;

        class Utility final {
        public:
            static uint64_t CurrentTimestampMs() {
                const auto now = std::chrono::time_point_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now()
                );
                return static_cast<uint64_t>(now.time_since_epoch().count());
            }

            static Result<Stream> Seal(
                _In_ const Stream &plaintext,
                _In_ const XPK &publicKeyBob,
                _In_ const XSK &secretKeyAlice
            ) {
                if (plaintext.empty()) {
                    return Err(cpl::Error(cpl::Error::NoData(), "[X] Seal plaintext is empty" CPL_FILE_AND_LINE));
                }

                Stream encrypted;
                encrypted.resize(naion_box_NONCEBYTES_MAX + plaintext.size() + naion_box_MACBYTES_MAX);

                uint8_t nonce[naion_box_NONCEBYTES_MAX]{};
                const auto r0 = RandomBytesBuf(nonce, sizeof(nonce));
                if (r0 != 0) {
                    return Err(cpl::Error(Errors::CryptoBoxEasy, "[X] Seal random nonce failed" CPL_FILE_AND_LINE));
                }

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
                    return MakeErr(Errors::CryptoBoxEasy, es.value());
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
                    return MakeErr(Error::OutOfRange(), es.value());
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
                    return MakeErr(Errors::CryptoBoxOpenEasy, es.value());
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
                    return MakeErr(Errors::CryptoSignDetached, es.value());
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
                    return Err(cpl::Error(cpl::Error::InvalidArgument(),
                                          "[X] Verify signature length invalid" CPL_FILE_AND_LINE));
                }
                const auto r00 = naion_sign_ed25519_verify_detached(
                    signature.data(),
                    buffer.data(),
                    static_cast<unsigned long long>(buffer.size()),
                    edPubKey.data()
                );
                return r00 == 0;
            }
        };

        // Helper: translate a naion_csm_* return code into a cpl::Error.
        inline cpl::Error CsmError(const cpl::Error::CodeDef code, const int r) {
            return cpl::Error(code, "[X] CSM failure" CPL_FILE_AND_LINE);
        }

        // CSM Client. Delegates the wire format to naion_csm_client_* so the C++
        // side stays byte-level compatible with the Go/Python CSM peers.
        class Client final : public cpl::crypto::stl::ISync {
            ESD edSeedC{};
            ESK edSecKeyC{};
            EPK edPubKeyC{};
            EPK edPubKeyS{};
            naion_csm_client csmClient{};

            Client() = default;

        public:
            static Result<std::unique_ptr<Client> > Create(
                _In_ const ESD &edSeedClient,
                _In_ const EPK &edPubKeyServer
            ) {
                auto instance = std::unique_ptr<Client>(new Client());

                instance->edSeedC = edSeedClient;
                instance->edPubKeyS = edPubKeyServer;

                const auto r00 = naion_csm_init();
                if (r00 != NAION_CSM_OK) {
                    auto es = strings::Format(
                        "[X] Client Create naion_csm_init failed [%d]"
                        CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmInit, es.value());
                }

                const auto r01 = naion_csm_client_create(
                    &instance->csmClient,
                    instance->edSeedC.data(),
                    instance->edPubKeyS.data()
                );
                if (r01 != NAION_CSM_OK) {
                    auto es = strings::Format(
                        "[X] Client Create naion_csm_client_create failed [%d]"
                        CPL_FILE_AND_LINE, r01
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmClientCreate, es.value());
                }

                std::memmove(instance->edPubKeyC.data(), instance->csmClient.ed_public_key,
                             instance->edPubKeyC.size());
                std::memmove(instance->edSecKeyC.data(), instance->csmClient.ed_secret_key,
                             instance->edSecKeyC.size());

                return instance;
            }

            ~Client() override {
                naion_csm_client_wipe(&this->csmClient);
            }

            const EPK &GetPublicKey() const { return this->edPubKeyC; }

            Result<Stream> Encrypt(const Stream &in) override {
                if (in.empty()) {
                    return Err(cpl::Error(cpl::Error::NoData(), "[X] Client Encrypt empty data" CPL_FILE_AND_LINE));
                }
                if (in.size() > MaxClientPayloadBytes) {
                    return Err(cpl::Error(Error::OutOfRange(), "[X] Client Encrypt payload too large" CPL_FILE_AND_LINE));
                }

                Stream out(naion_csm_client_encrypt_size(in.size()));
                size_t outSize = 0;
                const auto r00 = naion_csm_client_encrypt(
                    &this->csmClient,
                    in.data(),
                    in.size(),
                    out.data(),
                    out.size(),
                    &outSize
                );
                if (r00 != NAION_CSM_OK) {
                    auto es = strings::Format(
                        "[X] Client Encrypt naion_csm_client_encrypt failed [%d]" CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmClientEncrypt, es.value());
                }
                out.resize(outSize);
                return out;
            }

            Result<Stream> Decrypt(const Stream &in) override {
                const size_t maxPlain = naion_csm_client_decrypt_max_plaintext_size(in.size());
                Stream out(maxPlain);
                size_t outSize = 0;
                const auto r00 = naion_csm_client_decrypt(
                    &this->csmClient,
                    in.data(),
                    in.size(),
                    out.data(),
                    out.size(),
                    &outSize
                );
                if (r00 != NAION_CSM_OK) {
                    auto es = strings::Format(
                        "[X] Client Decrypt naion_csm_client_decrypt failed [%d]" CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmClientDecrypt, es.value());
                }
                out.resize(outSize);
                return out;
            }
        };

        // CSM Server. Learns the client's Ed25519 public key from the first
        // successfully decrypted client→server packet, then may encrypt back.
        class Server final : public cpl::crypto::stl::ISync {
            ESD edSeedS{};
            ESK edSecKeyS{};
            EPK edPubKeyS{};
            EPK edPubKeyC{};
            bool ed25519PublicKeyClientInitialized{false};
            naion_csm_server csmServer{};

            Server() = default;

        public:
            static Result<std::unique_ptr<Server> > Create(_In_ const ESD &edSeedS) {
                auto instance = std::unique_ptr<Server>(new Server());
                instance->edSeedS = edSeedS;

                const auto r00 = naion_csm_init();
                if (r00 != NAION_CSM_OK) {
                    auto es = strings::Format(
                        "[X] Server Create naion_csm_init failed [%d]"
                        CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmInit, es.value());
                }

                const auto r01 = naion_csm_server_create(
                    &instance->csmServer,
                    instance->edSeedS.data()
                );
                if (r01 != NAION_CSM_OK) {
                    auto es = strings::Format(
                        "[X] Server Create naion_csm_server_create failed [%d]"
                        CPL_FILE_AND_LINE, r01
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmServerCreate, es.value());
                }

                std::memmove(instance->edPubKeyS.data(), instance->csmServer.ed_public_key,
                             instance->edPubKeyS.size());
                std::memmove(instance->edSecKeyS.data(), instance->csmServer.ed_secret_key,
                             instance->edSecKeyS.size());

                return instance;
            }

            ~Server() override {
                naion_csm_server_wipe(&this->csmServer);
            }

            const EPK &GetPublicKey() const { return this->edPubKeyS; }
            bool IsClientKeyInitialized() const { return this->ed25519PublicKeyClientInitialized; }

            Result<Stream> Decrypt(const Stream &in) override {
                const size_t maxPlain = naion_csm_server_decrypt_max_plaintext_size(in.size());
                Stream out(maxPlain);
                size_t outSize = 0;
                const auto r00 = naion_csm_server_decrypt(
                    &this->csmServer,
                    in.data(),
                    in.size(),
                    out.data(),
                    out.size(),
                    &outSize
                );
                if (r00 != NAION_CSM_OK) {
                    auto es = strings::Format(
                        "[X] Server Decrypt naion_csm_server_decrypt failed [%d]" CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmServerDecrypt, es.value());
                }
                out.resize(outSize);
                this->ed25519PublicKeyClientInitialized = this->csmServer.client_public_key_initialized != 0;
                if (this->ed25519PublicKeyClientInitialized) {
                    std::memmove(this->edPubKeyC.data(), this->csmServer.client_ed_public_key,
                                 this->edPubKeyC.size());
                }
                return out;
            }

            Result<Stream> Encrypt(const Stream &in) override {
                if (in.empty()) {
                    return Err(cpl::Error(cpl::Error::NoData(), "[X] Server Encrypt empty data" CPL_FILE_AND_LINE));
                }
                if (in.size() > MaxServerPayloadBytes) {
                    return Err(cpl::Error(Error::OutOfRange(), "[X] Server Encrypt payload too large" CPL_FILE_AND_LINE));
                }
                if (!this->csmServer.client_public_key_initialized) {
                    return Err(cpl::Error(cpl::Error::NoData(),
                                          "[X] Server Encrypt client public key is not initialized" CPL_FILE_AND_LINE));
                }

                Stream out(naion_csm_server_encrypt_size(in.size()));
                size_t outSize = 0;
                const auto r00 = naion_csm_server_encrypt(
                    &this->csmServer,
                    in.data(),
                    in.size(),
                    out.data(),
                    out.size(),
                    &outSize
                );
                if (r00 != NAION_CSM_OK) {
                    auto es = strings::Format(
                        "[X] Server Encrypt naion_csm_server_encrypt failed [%d]" CPL_FILE_AND_LINE, r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CsmServerEncrypt, es.value());
                }
                out.resize(outSize);
                return out;
            }
        };
    }
}

#endif //CPL_NAION_HPP_SUBSTITUTE_SODIUM_COMPATIBLE_WRAPPER
