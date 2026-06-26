#ifndef CPL_CRYPTO_HPP_SUPPORTER_VEHICLE_STRONG_GLIDER_MOTION_PATIENT_JOURNEY
#define CPL_CRYPTO_HPP_SUPPORTER_VEHICLE_STRONG_GLIDER_MOTION_PATIENT_JOURNEY

#include <cstdint>
#include <process.h>
#include <string>

using namespace std;

namespace cpl {
    namespace crypto {
        typedef int32_t (*FuncRandomBuffer)(void *buffer, uint32_t size);

        class UnsafeRandom final : public base::crypto::IRandom {
        public:
            INT32 Rand(_In_ const LPCVOID buffer, _In_ const size_t size) override {
                // 涉及参数：时间、栈地址、堆地址、PID
                {
                    static uint8_t *staticPointer = nullptr;
                    const auto now = time(nullptr);
                    const auto stackAddress = &now;
                    const auto globalAddress = &staticPointer;
                    staticPointer = new(nothrow) uint8_t();
                    if (nullptr == staticPointer) {
                        return ERROR_NOT_ENOUGH_MEMORY;
                    }
                    const auto heapAddress = staticPointer;
                    delete staticPointer;
                    uint64_t antiStackAddress{}, reverseGlobalAddress{};
                    memmove(&antiStackAddress, &stackAddress, sizeof(stackAddress));
                    memmove(&reverseGlobalAddress, &globalAddress, sizeof(globalAddress));
                    antiStackAddress = ~antiStackAddress;
                    // reverse 反转
                    {
                        const auto *ps = reinterpret_cast<uint8_t *>(globalAddress);
                        auto *pd = reinterpret_cast<uint8_t *>(&reverseGlobalAddress);
                        if (sizeof(globalAddress) == 8) {
                            for (auto i = 0; i < 4; i++) {
                                const auto b0 = *(ps + i);
                                const auto b1 = *(ps + i + 4);
                                *(pd + 4 - i) = b0 ^ b1;
                            }
                        }
                        if (sizeof(globalAddress) == 4) {
                            for (auto i = 0; i < 4; i++) {
                                const auto b0 = *(ps + i);
                                *(pd + 4 - i) = b0;
                            }
                        } else {
                            for (auto i = 0; i < sizeof(globalAddress); i++) {
                                const auto j = 4 - i % 4 - 1;
                                *(pd + j) ^= *(ps + i);
                            }
                        }
                    }
                    const auto pid = static_cast<uint32_t>(_getpid());
                    const uint32_t seed = static_cast<uint32_t>(now) ^ antiStackAddress ^ reverseGlobalAddress ^ pid;
                    srand(seed);
                }
                uint8_t *p = nullptr;
                memmove(&p, &buffer, sizeof(LPCVOID));
                for (auto i = 0; i < size; i++) {
                    const auto r = rand();
                    *(p + i) = static_cast<uint8_t>(r & 0xff);
                }
                return ERROR_SUCCESS;
            }
        };

        class RC4 final : public base::crypto::ISync {
        protected:
            uint8_t sBox[256]{};

        public:
            explicit RC4(const vector<uint8_t> &key) {
                for (auto i = 0; i < 256; i++) {
                    sBox[i] = i;
                }
                size_t j = 0;
                for (auto i = 0; i < 256; i++) {
                    j = (j + sBox[i] + key[i % key.size()]) % 256;
                    const auto b = sBox[i];
                    sBox[i] = sBox[j];
                    sBox[j] = b;
                }
            }

            INT32 Encrypt(vector<BYTE> &out, const vector<BYTE> &cleared) override {
                size_t i = 0, j = 0;
                for (auto c: cleared) {
                    i = (i + 1) % 256;
                    j = (j + sBox[i]) % 256;
                    const auto t = sBox[i];
                    sBox[i] = sBox[j];
                    sBox[j] = t;
                    const auto k = sBox[(sBox[i] + sBox[j]) % 256];
                    out.push_back(c ^ k);
                }
            }

            INT32 Decrypt(vector<BYTE> &out, const vector<BYTE> &encrypted) override {
                return Encrypt(out, encrypted);
            }
        };


        class RC4Crypto final : public base::crypto::ICrypto {
        public:
            constexpr auto HMAC_SIZE = 16;
            constexpr auto IV_SIZE = 8;

        protected:
            vector<BYTE> key;
            base::crypto::ICryptoFactory &hmacFactory;
            base::crypto::ICryptoFactory &syncFactory;
            base::crypto::IRandom &randomProvider;

        public:
            explicit RC4Crypto(
                const vector<BYTE> &key,
                base::crypto::ICryptoFactory &hmacFactory,
                base::crypto::ICryptoFactory &syncFactory,
                base::crypto::IRandom &randomProvider
            ): hmacFactory(hmacFactory), syncFactory(syncFactory), randomProvider(randomProvider) {
                this->key = key;
            }

            INT32 Encrypt(vector<BYTE> &out, const vector<BYTE> &cleared) override {
                INT32 retCode = ERROR_SUCCESS;
                base::crypto::IHash *hmacEncProvider{}, *hmacKeyEncProvider{}, *hmacKeyMacProvider{};
                //
                try {
                    BYTE iv[IV_SIZE]{};
                    vector<BYTE> encKey{};
                    vector<BYTE> macKey{};
                    vector<BYTE> buffer{};
                    // 初始化IV
                    {
                        const auto r00 = this->randomProvider.Rand(iv, IV_SIZE);
                        if (r00 != ERROR_SUCCESS) {
                            retCode = r00;
                            throw exception("[x] randomProvider.Rand failed");
                        }
                    }
                    // 初始化encKey与macKey
                    {
                        const auto iv0 = vector<BYTE>(iv, iv + IV_SIZE);
                        const auto r00 = this->hmacFactory.CreateHMACProvider(iv0, hmacKeyEncProvider);
                        if (r00 != ERROR_SUCCESS) {
                            retCode = r00;
                            throw exception("[x] hmacFactory.CreateHMACProvider failed");
                        }
                        const auto r01 = hmacKeyEncProvider->Update(key);
                        if (r01 != ERROR_SUCCESS) {
                            retCode = r01;
                            throw exception("[x] hmacKeyEncProvider->Update failed");
                        }
                        const auto r02 = hmacKeyEncProvider->Summary(encKey);
                        if (r02 != ERROR_SUCCESS) {
                            retCode = r02;
                            throw exception("[x] hmacKeyEncProvider->Summary failed");
                        }
                        const auto r03 = this->hmacFactory.CreateHMACProvider(key, hmacKeyMacProvider);
                        if (r03 != ERROR_SUCCESS) {
                            retCode = r03;
                            throw exception("[x] hmacFactory.CreateHMACProvider failed");
                        }
                        const auto r04 = hmacKeyMacProvider->Update(iv0);
                        if (r04 != ERROR_SUCCESS) {
                            retCode = r04;
                            throw exception("[x] hmacKeyMacProvider->Update failed");
                        }
                        const auto r05 = hmacKeyMacProvider->Summary(macKey);
                        if (r05 != ERROR_SUCCESS) {
                            retCode = r05;
                            throw exception("[x] hmacKeyMacProvider->Summary failed");
                        }
                        const auto r06 = this->hmacFactory.CreateHMACProvider(key, hmacEncProvider);
                        if (r06 != ERROR_SUCCESS) {
                            retCode = r06;
                            throw exception("[x] hmacFactory.CreateHMACProvider failed");
                        }
                    }
                    // 加密
                    {
                        auto rc4 = RC4(encKey);
                        const auto r00 = rc4.Encrypt(buffer, cleared);

                    }
                } catch (exception &e) {
                    LOG_F(ERROR, "[x] %s", e.what());
                }
                delete hmacEncProvider;
                delete hmacKeyEncProvider;
                delete hmacKeyMacProvider;
                return retCode;
            }

            INT32 Decrypt(vector<BYTE> &out, const vector<BYTE> &encrypted) override {
                return Encrypt(out, encrypted);
            }

            string RandomBuffer(const uint32_t size) const {
                string buffer{};
                buffer.reserve(size + 16);
                const auto pc = buffer.data() + 8;
                char *p{};
                memmove(&p, &pc, sizeof(void *));

                if (nullptr != this->trueFuncRandomBuffer) {
                    this->trueFuncRandomBuffer(p, size);
                } else {
                    Crypto$$$RandomBufferInsecure(p, size);
                }

                buffer.append(p, size);
                return buffer;
            }

            int32_t Encrypt(
                _In_ const string &key,
                _In_ const string &plain,
                _Out_ string &encrypted,
                _In_opt_ const char nonce[SIZE_NONCE] = nullptr
            ) const {
                int32_t retCode = 0;
                uint8_t iv[SIZE_NONCE]{};
                uint8_t hash[SIZE_HMAC16]{};

                size_t nBytes{};
                const char *pc_hash{}, *pc_iv{}, *pc_enc{};
                char *p_hash{}, *p_enc{};
                void *pv_hash{}, *pv_iv{};

                encrypted.clear();
                const auto reserved_length = plain.size() + SIZE_NONCE + SIZE_HMAC16 + 16;
                encrypted.reserve(reserved_length);

                pc_hash = encrypted.data();
                memmove(&p_hash, &pc_hash, sizeof(void *));
                memset(p_hash, 0, reserved_length);

                if (nullptr == nonce) {
                    const string _iv = this->RandomBuffer(SIZE_NONCE);
                    memmove(iv, _iv.data(), SIZE_NONCE);
                } else {
                    memmove(iv, nonce, SIZE_NONCE);
                }

                // 这里增加一个是为了保证后面合并时不被string自动添加的\x00覆盖。
                pc_enc = encrypted.data() + SIZE_HMAC16 + SIZE_NONCE + 1;
                memmove(&p_enc, &pc_enc, sizeof(char *));

                retCode = Crypto$$$Encrypt(
                    key.data(), key.size(), iv,
                    plain.data(), plain.size(),
                    hash, p_enc, &nBytes
                );
                if (0 != retCode) {
                    log_trace("[x] Crypto$$$Encrypt failed %ld", retCode);
                    goto __ERROR__;
                }
                pv_hash = &hash;
                memmove(&pc_hash, &pv_hash, sizeof(char *));
                encrypted.append(pc_hash, SIZE_HMAC16);
                pv_iv = &iv;
                memmove(&pc_iv, &pv_iv, sizeof(char *));
                encrypted.append(pc_iv, SIZE_NONCE);
                for (auto i = 0; i < nBytes; i++) {
                    const auto ch = p_enc[i];
                    encrypted.push_back(ch);
                }
                goto __FREE__;
            __ERROR__:
                PASS;
            __FREE__:
                return retCode;
            }
        };

        static int32_t Decrypt(_In_ const string &key, _In_ const string &encrypted, _Out_ string &plain) {
            plain.reserve(encrypted.size());
            int32_t retCode = 0;
            const char *pc = plain.data();
            char *p = nullptr;
            memmove(&p, &pc, sizeof(char *));
            size_t nBytes = 0;
            retCode = Crypto$$$DecryptStream(key.data(), key.size(), encrypted.data(), p, &nBytes);
            if (0 != retCode) {
                log_trace("[x] Crypto$$$DecryptStream failed %ld", retCode);
                goto __ERROR__;
            }
            plain.append(p, nBytes);
            goto __FREE__;
        __ERROR__:
            PASS;
        __FREE__:
            return retCode;
        }
    }
}

#endif //CPL_CRYPTO_HPP_SUPPORTER_VEHICLE_STRONG_GLIDER_MOTION_PATIENT_JOURNEY
