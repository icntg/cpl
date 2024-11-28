#ifndef CPL_CRYPTO_HPP_SUPPORTER_VEHICLE_STRONG_GLIDER_MOTION_PATIENT_JOURNEY
#define CPL_CRYPTO_HPP_SUPPORTER_VEHICLE_STRONG_GLIDER_MOTION_PATIENT_JOURNEY

#include <cstdint>
#include <string>

#include "../../ccl/utility/crypto/crypto.h"
#include "../../ccl/vendor/logger/log.h"

using namespace std;

namespace cpl {
    namespace crypto {
        typedef int32_t (*FuncRandomBuffer)(void *buffer, uint32_t size);

        class Crypto {
        protected:
            FuncRandomBuffer trueFuncRandomBuffer{};

        public:
            explicit Crypto(const FuncRandomBuffer true_func_random_buffer = nullptr) {
                this->trueFuncRandomBuffer = true_func_random_buffer;
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
