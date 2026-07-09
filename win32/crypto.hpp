#ifndef CPL_WIN32_CRYPTO_HPP_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE
#define CPL_WIN32_CRYPTO_HPP_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE

#include <windows.h>
// #include <wincrypt.h>
#include <cstdint>
#include <vector>
#include "api.hpp"
#include "../crypto.hpp"
#include "../vendor/emilk/loguru/loguru.hpp"

#ifndef ALG_SID_SHA_256
#define ALG_SID_SHA_256                 12
#endif
#ifndef CALG_SHA_256
#define CALG_SHA_256            (ALG_CLASS_HASH | ALG_TYPE_ANY | ALG_SID_SHA_256)
#endif

namespace cpl {
    namespace win32 {
        namespace crypto {
            inline int32_t RandomBuffer(_Inout_ void *buffer, _In_ const uint32_t size) {
                if (nullptr == buffer || size <= 0) {
                    return ERROR_INVALID_DATA;
                }
                const auto &api = api::GetInstance();
                int32_t retCode = ERROR_SUCCESS;
                HCRYPTPROV hCryptProv{};
                BOOL bContext = FALSE;
                BOOL bRet = FALSE;

                if (nullptr == api->WinCrypt.CryptGenRandom
                    || nullptr == api->WinCrypt.CryptAcquireContextA
                    || nullptr == api->WinCrypt.CryptReleaseContext
                ) {
                    retCode = ERROR_API_UNAVAILABLE;
                    goto __ERROR__;
                }

                bRet = api->WinCrypt.CryptAcquireContextA(
                    &hCryptProv, // handle to the CSP
                    nullptr, // container name
                    nullptr, // use the default provider
                    PROV_RSA_FULL, // provider type
                    CRYPT_NEWKEYSET);
                if (!bRet) {
                    const DWORD e = GetLastError();
                    retCode = static_cast<int32_t>(e);
                    goto __ERROR__;
                }
                bContext = TRUE;
                bRet = api->WinCrypt.CryptGenRandom(
                    hCryptProv,
                    size,
                    static_cast<BYTE *>(buffer)
                );
                if (!bRet) {
                    const DWORD e = GetLastError();
                    retCode = static_cast<int32_t>(e);
                    goto __ERROR__;
                }
                goto __FREE__;
            __ERROR__:
                PASS;
            __FREE__:
                if (bContext) {
                    bRet = api->WinCrypt.CryptReleaseContext(hCryptProv, 0);
                    if (!bRet) {
                        const DWORD e = GetLastError();
                        retCode = static_cast<int32_t>(e);
                    }
                    bzero(&hCryptProv, sizeof(HCRYPTPROV));
                }
                return retCode;
            }

            inline vector<uint8_t> Random(_In_ const uint32_t size) {
                vector<uint8_t> out{};
                out.resize(size);
                RandomBuffer(out.data(), size);
                return out;
            }

            inline string UrlSafeBase64Encode(LPCVOID buffer, const size_t length) {
                const auto &api = api::GetInstance();
                if (nullptr == api->WinCrypt.CryptBinaryToStringA) {
                    LOG_F(ERROR, "[X] api->WinCrypt.CryptBinaryToStringA is null");
                    return "";
                }
                DWORD dwNeed = 0;
                string ret{};
                const BYTE *_buf{};
                const auto *p = buffer;
                memmove(&_buf, &p, sizeof(LPCVOID));

                // 计算所需内存大小
                api->WinCrypt.CryptBinaryToStringA(_buf, length, CRYPT_STRING_BASE64, nullptr, &dwNeed);

                if (dwNeed > 0) {
                    vector<BYTE> stream{};
                    stream.reserve(dwNeed + 16);
                    stream.resize(dwNeed + 16);
                    // 执行编码
                    const auto r00 = api->WinCrypt.CryptBinaryToStringA(_buf, length, CRYPT_STRING_BASE64,
                                                                        (char *) stream.data(),
                                                                        &dwNeed);
                    if (!r00) {
                        const auto e = GetLastError();
                        LOG_F(ERROR, "[X] CryptBinaryToStringA failed: %lu", e);
                        return "";
                    }
                    stream.resize(dwNeed - 1);

                    for (unsigned char ch: stream) {
                        char c{};
                        if (ch == '\r' || ch == '\n') {
                            continue;
                        }
                        if (ch == '+') {
                            c = '-';
                        } else if (ch == '/') {
                            c = '_';
                        } else {
                            c = static_cast<char>(ch);
                        }
                        ret.push_back(c);
                    }
                }
                return ret;
            }

            inline string UrlSafeBase64Encode(const vector<BYTE> &in) {
                return UrlSafeBase64Encode(in.data(), in.size());
            }

            inline INT32 UrlSafeBase64Decode(vector<BYTE> &out, const string &in) {
                // todo
                return 0;
            }

            inline string Hexlify(LPCVOID buffer, const SIZE_T length) {
                string s{};
                const auto *p = static_cast<const char *>(buffer);
                for (auto i = 0; i < length; i++) {
                    const auto ch = p[i];
                    BYTE b[2]{static_cast<BYTE>((ch >> 4) & 0xf), static_cast<BYTE>(ch & 0xf)};
                    for (BYTE c: b) {
                        if (c < 10) {
                            s.push_back(static_cast<char>(c + '0'));
                        } else {
                            s.push_back(static_cast<char>(c - 10 + 'a'));
                        }
                    }
                }
                return s;
            }

            inline string Hexlify(const vector<BYTE> &in) {
                return Hexlify(in.data(), in.size());
            }

            inline INT32 Unhexlify(vector<BYTE> &out, const string &in) {
                // todo
                return 0;
            }

#if 0
            // ----------------------------------------------------------------------
            // The legacy SHA256 / HMAC256 / AES256CBC / AES256CTR classes below
            // depend on cpl::base::crypto::{IHash,ISync}, which was removed when
            // base.hpp was consolidated to a single authoritative header. They
            // are retained here as reference for a future port to the new Result
            // API (cpl::crypto::{IHash,ISync} in the top-level crypto.hpp) but
            // are disabled until that port happens. No current consumer compiles
            // them.
            // ----------------------------------------------------------------------
            class SHA256 final : public cpl::base::crypto::IHash {
            public:
                static constexpr int DIGEST_BITS_LENGTH = 256;
                static constexpr int DIGEST_BYTES_LENGTH = DIGEST_BITS_LENGTH / 8;

            protected:
                HCRYPTPROV hProv{};
                HCRYPTHASH hHash{};

            public:
                explicit SHA256() {
                    const auto &api = api::GetInstance();
                    try {
                        // 检测API
                        {
                            if (nullptr == api->WinCrypt.CryptAcquireContextA) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptAcquireContextA is null");
                                throw exception("api->WinCrypt.CryptAcquireContextA is null");
                            }
                            if (nullptr == api->WinCrypt.CryptCreateHash) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptCreateHash is null");
                                throw exception("api->WinCrypt.CryptCreateHash is null");
                            }
                            if (nullptr == api->WinCrypt.CryptDestroyHash) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptDestroyHash is null");
                                throw exception("api->WinCrypt.CryptDestroyHash is null");
                            }
                            if (nullptr == api->WinCrypt.CryptReleaseContext) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptReleaseContext is null");
                                throw exception("api->WinCrypt.CryptReleaseContext is null");
                            }
                            // CryptHashData
                            if (nullptr == api->WinCrypt.CryptHashData) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptHashData is null");
                                throw exception("api->WinCrypt.CryptHashData is null");
                            }
                            // CryptGetHashParam
                            if (nullptr == api->WinCrypt.CryptGetHashParam) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptGetHashParam is null");
                                throw exception("api->WinCrypt.CryptGetHashParam is null");
                            }
                        }
                        //
                        {
                            const auto r00 = api->WinCrypt.CryptAcquireContextA(
                                &this->hProv,
                                nullptr,
                                nullptr,
                                PROV_RSA_AES,
                                CRYPT_VERIFYCONTEXT
                            );
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptAcquireContextA error: %lu", e);
                                throw exception("CryptAcquireContextA error", e);
                            }
                            //LOG_F(ERROR, "[#] hProv = 0x%lx", this->hProv);
                        }
                        // 1. 创建哈希对象（使用CALG_SHA_256算法）
                        {
                            const auto r00 = api->WinCrypt.CryptCreateHash(
                                this->hProv,
                                CALG_SHA_256, // 算法标识
                                0, // 父哈希句柄
                                0, // 标志
                                &this->hHash
                            );
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptCreateHash error: %lu", e);
                                throw exception("CryptCreateHash error", e);
                            }
                            //LOG_F(ERROR, "[#] hHash = 0x%lx", this->hHash);
                        }
                    } catch (exception &e) {
                        api->WinCrypt.CryptDestroyHash(this->hHash);
                        this->hHash = 0;
                        api->WinCrypt.CryptReleaseContext(this->hProv, 0);
                        this->hProv = 0;
                        throw e;
                    }
                }

                ~SHA256() override {
                    const auto &api = api::GetInstance();
                    api->WinCrypt.CryptDestroyHash(this->hHash);
                    api->WinCrypt.CryptReleaseContext(this->hProv, 0);
                }

                INT32 Update(_In_ const vector<BYTE> &data) override {
                    const auto &api = api::GetInstance();
                    INT32 retCode = ERROR_SUCCESS;
                    // 2. 更新哈希数据
                    const auto r00 = api->WinCrypt.CryptHashData(
                        this->hHash, // 哈希句柄
                        data.data(), // 输入数据
                        data.size(), // 数据长度
                        0
                    );
                    if (!r00) {
                        const auto e = GetLastError();
                        LOG_F(ERROR, "[X] CryptHashData error: %lu", e);
                        retCode = static_cast<INT32>(e);
                    }
                    return retCode;
                }

                INT32 Summary(_Out_ vector<BYTE> &out) override {
                    const auto &api = api::GetInstance();
                    // 3. 获取哈希值
                    out.reserve(DIGEST_BYTES_LENGTH + 1);
                    out.resize(DIGEST_BYTES_LENGTH + 1);
                    DWORD hashSize = DIGEST_BYTES_LENGTH;
                    const auto r00 = api->WinCrypt.CryptGetHashParam(
                        hHash, // 哈希句柄
                        HP_HASHVAL, // 获取哈希值
                        out.data(), // 输出缓冲区
                        &hashSize, // 缓冲区大小
                        0
                    );
                    if (!r00) {
                        const auto e = GetLastError();
                        LOG_F(ERROR, "[X] CryptGetHashParam error: %lu", e);
                        return static_cast<INT32>(e);
                    }
                    out.resize(hashSize);
                    return ERROR_SUCCESS;
                }
            };

            class HMAC256 final : public cpl::base::crypto::IHash {
            public:
                static constexpr int DIGEST_BITS_LENGTH = 256;
                static constexpr int DIGEST_BYTES_LENGTH = DIGEST_BITS_LENGTH / 8;

            protected:
                HCRYPTPROV hProv{};
                HCRYPTKEY hKey{};
                HCRYPTHASH hHmacHash{};
                HMAC_INFO hmacInfo{};

            public:
                explicit HMAC256(_In_ const vector<BYTE> &key, INT32 *pRetCode = nullptr) {
                    const auto &api = api::GetInstance();
                    try {
                        // 检测API
                        {
                            if (nullptr == api->WinCrypt.CryptAcquireContextA) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptAcquireContextA is null");
                                throw exception("api->WinCrypt.CryptAcquireContextA is null");
                            }
                            if (nullptr == api->WinCrypt.CryptImportKey) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptImportKey is null");
                                throw exception("api->WinCrypt.CryptImportKey is null");
                            }
                            if (nullptr == api->WinCrypt.CryptCreateHash) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptCreateHash is null");
                                throw exception("api->WinCrypt.CryptCreateHash is null");
                            }
                            if (nullptr == api->WinCrypt.CryptSetHashParam) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptSetHashParam is null");
                                throw exception("api->WinCrypt.CryptSetHashParam is null");
                            }
                            if (nullptr == api->WinCrypt.CryptDestroyKey) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptDestroyKey is null");
                                throw exception("api->WinCrypt.CryptDestroyKey is null");
                            }
                            if (nullptr == api->WinCrypt.CryptDestroyHash) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptDestroyHash is null");
                                throw exception("api->WinCrypt.CryptDestroyHash is null");
                            }
                            if (nullptr == api->WinCrypt.CryptReleaseContext) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptReleaseContext is null");
                                throw exception("api->WinCrypt.CryptReleaseContext is null");
                            }
                            // CryptHashData
                            if (nullptr == api->WinCrypt.CryptHashData) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptHashData is null");
                                throw exception("api->WinCrypt.CryptHashData is null");
                            }
                            // CryptGetHashParam
                            if (nullptr == api->WinCrypt.CryptGetHashParam) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptGetHashParam is null");
                                throw exception("api->WinCrypt.CryptGetHashParam is null");
                            }
                        }
                        //
                        {
                            const auto r00 = api->WinCrypt.CryptAcquireContextA(
                                &this->hProv,
                                nullptr,
                                nullptr,
                                PROV_RSA_AES,
                                CRYPT_VERIFYCONTEXT
                            );
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptAcquireContextA error: %lu", e);
                                throw exception("CryptAcquireContextA", e);
                            }
                            //LOG_F(MAX, "[#] hProv = 0x%lx", this->hProv);
                        }
                        // 导入KEY
                        {
                            // 步骤 2: 将原始密钥导入CSP
                            // 我们需要构建一个 PLAINTEXTKEYBLOB 结构
                            struct stKeyBlob {
                                BLOBHEADER blobheader;
                                DWORD keySize;
                                BYTE keyData[]; // 长度不定
                            };

                            vector<BYTE> keyBlobBuf{};
                            keyBlobBuf.resize(sizeof(struct stKeyBlob) + key.size() + 4);
                            auto *keyBlob = (struct stKeyBlob *) keyBlobBuf.data();
                            keyBlob->blobheader.bType = PLAINTEXTKEYBLOB;
                            keyBlob->blobheader.bVersion = CUR_BLOB_VERSION;
                            keyBlob->blobheader.reserved = 0;
                            keyBlob->blobheader.aiKeyAlg = CALG_RC2; // 对于HMAC导入，此算法无关紧要，但必须设置
                            keyBlob->keySize = static_cast<DWORD>(key.size());
                            memmove(keyBlob->keyData, key.data(), key.size());

                            const auto r00 = api->WinCrypt.CryptImportKey(
                                hProv,
                                keyBlobBuf.data(),
                                sizeof(BLOBHEADER) +
                                sizeof(DWORD) + (DWORD) key.size(),
                                0,
                                CRYPT_IPSEC_HMAC_KEY,
                                &hKey
                            );
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptImportKey failed: %lu", e);
                                throw exception("CryptImportKey failed", e);
                            }
                            //LOG_F(MAX, "[#] hKey = 0x%lx", this->hKey);
                        }
                        // 步骤 3: 创建一个HMAC哈希对象
                        {
                            this->hmacInfo.HashAlgid = CALG_SHA_256; // 指定内部哈希算法为SHA-256
                            const auto r00 = api->WinCrypt.CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHmacHash);
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptCreateHash failed: %lu", e);
                                throw exception("CryptCreateHash failed", e);
                            }
                        }

                        // 步骤 4: 设置HMAC参数
                        {
                            const auto r00 = api->WinCrypt.CryptSetHashParam(
                                hHmacHash, HP_HMAC_INFO, (BYTE *) &hmacInfo, 0);
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptSetHashParam failed: %lu", e);
                                throw exception("CryptSetHashParam failed", e);
                            }
                        }
                    } catch (exception &e) {
                        ZeroMemory(&hmacInfo, sizeof(HMAC_INFO));
                        if (hKey) { api->WinCrypt.CryptDestroyKey(hKey); }
                        if (hHmacHash) { api->WinCrypt.CryptDestroyHash(hHmacHash); }
                        if (hProv) { api->WinCrypt.CryptReleaseContext(hProv, 0); }
                        throw e;
                    }
                }

                ~HMAC256() override {
                    const auto &api = api::GetInstance();
                    ZeroMemory(&hmacInfo, sizeof(HMAC_INFO));
                    if (hKey) { api->WinCrypt.CryptDestroyKey(hKey); }
                    if (hHmacHash) { api->WinCrypt.CryptDestroyHash(hHmacHash); }
                    if (hProv) { api->WinCrypt.CryptReleaseContext(hProv, 0); }
                }

                INT32 Update(_In_ const vector<BYTE> &data) override {
                    const auto &api = api::GetInstance();
                    const auto r00 = api->WinCrypt.CryptHashData(hHmacHash, data.data(), (DWORD) data.size(), 0);
                    if (!r00) {
                        const auto e = GetLastError();
                        LOG_F(ERROR, "[X] CryptHashData failed: %lu", e);
                        return (INT32) e;
                    }
                    return ERROR_SUCCESS;
                }

                INT32 Summary(_Out_ vector<BYTE> &out) override {
                    const auto &api = api::GetInstance();
                    INT32 retCode = ERROR_SUCCESS;
                    DWORD hashSize = 0;
                    DWORD dwSize = sizeof(DWORD);

                    // 先获取哈希值的长度 (对于SHA256, 应该是32字节)
                    const auto r00 = api->WinCrypt.CryptGetHashParam(hHmacHash, HP_HASHSIZE, (BYTE *) &hashSize,
                                                                     &dwSize, 0);
                    if (!r00) {
                        const auto e = GetLastError();
                        LOG_F(ERROR, "[X] CryptGetHashParam HP_HASHSIZE failed: %lu", e);
                        retCode = (INT32) e;
                        return retCode;
                    }
                    out.resize(hashSize);
                    const auto r01 = api->WinCrypt.CryptGetHashParam(hHmacHash, HP_HASHVAL, out.data(), &hashSize, 0);
                    if (!r01) {
                        const auto e = GetLastError();
                        LOG_F(ERROR, "[X] CryptGetHashParam HP_HASHVAL failed: %lu", e);
                    }
                    return retCode;
                }
            };

            class AES256CBC final : public base::crypto::ISync {
            protected:
                vector<BYTE> &iv;
                HCRYPTPROV hProv{};
                HCRYPTKEY hKey{};
                DWORD MODE = CRYPT_MODE_CBC;
                DWORD PADDING = PKCS5_PADDING;
                vector<BYTE> key{};

            public:
                explicit AES256CBC(
                    _In_ const vector<BYTE> &key,
                    _Inout_ vector<BYTE> &iv
                ): iv(iv) {
                    const auto &api = api::GetInstance();
                    try {
                        // 检测所用API
                        {
                            // CryptAcquireContextA
                            if (nullptr == api->WinCrypt.CryptAcquireContextA) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptAcquireContextA is null");
                                throw exception("api->WinCrypt.CryptAcquireContextA is null");
                            }
                            // CryptReleaseContext
                            if (nullptr == api->WinCrypt.CryptReleaseContext) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptReleaseContext is null");
                                throw exception("api->WinCrypt.CryptReleaseContext is null");
                            }
                            // CryptImportKey
                            if (nullptr == api->WinCrypt.CryptImportKey) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptImportKey is null");
                                throw exception("api->WinCrypt.CryptImportKey is null");
                            }
                            // CryptDestroyKey
                            if (nullptr == api->WinCrypt.CryptDestroyKey) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptDestroyKey is null");
                                throw exception("api->WinCrypt.CryptDestroyKey is null");
                            }
                            // CryptSetKeyParam
                            if (nullptr == api->WinCrypt.CryptSetKeyParam) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptSetKeyParam is null");
                                throw exception("api->WinCrypt.CryptSetKeyParam is null");
                            }
                            // CryptEncrypt
                            if (nullptr == api->WinCrypt.CryptEncrypt) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptEncrypt is null");
                                throw exception("api->WinCrypt.CryptEncrypt is null");
                            }
                            // CryptDecrypt
                            if (nullptr == api->WinCrypt.CryptDecrypt) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptDecrypt is null");
                                throw exception("api->WinCrypt.CryptDecrypt is null");
                            }
                        }
                        // 检测key长度
                        {
                            this->key = key;
                            if (this->key.size() != 32 && this->key.size() != 24 && this->key.size() != 16) {
                                LOG_F(ERROR, "[X] AES_CBC key size error: %lu", this->key.size());
                                throw length_error("AES_CBC key size error");
                            }
                        }
                        // 检测IV或初始化
                        {
                            this->iv = iv;
                            if (
                                this->iv.empty()
                                || (this->iv.size() != 16)
                                || (this->iv.size() == 16 && memcmp(this->iv.data(),
                                                                    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
                                                                    16) == 0)) {
                                this->iv.resize(16);
                                const auto r00 = RandomBuffer(this->iv.data(), this->iv.size());
                                if (r00 != ERROR_SUCCESS) {
                                    LOG_F(ERROR, "[#] AES_CBC Random IV failed: %lu", r00);
                                    throw exception("Random IV failed", r00);
                                }
                            } else {
                                LOG_F(INFO, "[#] AES_CBC use custom IV");
                            }
                        }
                        // 获取加密服务提供程序 (CSP) 的句柄
                        {
                            const auto r00 = api->WinCrypt.CryptAcquireContextA(
                                &hProv,
                                nullptr,
                                //MS_ENH_RSA_AES_PROV, // 使用支持AES的Provider
                                nullptr,
                                PROV_RSA_AES,
                                CRYPT_VERIFYCONTEXT);
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptAcquireContext CRYPT_VERIFYCONTEXT failed: %lu", e);
                                //retCode = (INT32)e;
                                // 另一种尝试
                                const auto r01 = api->WinCrypt.CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, 0);
                                if (!r01) {
                                    const auto e0 = GetLastError();
                                    LOG_F(ERROR, "[X] CryptAcquireContext 0 failed: %lu", e0);
                                    throw exception("CryptAcquireContext failed", static_cast<INT>(e0));
                                }
                            }
                        }
                        // 导入密钥以获取句柄
                        {
                            // 步骤 2: 将原始密钥导入CSP
                            // 我们需要构建一个 PLAINTEXTKEYBLOB 结构
                            struct {
                                BLOBHEADER blobHeader;
                                DWORD keySize;
                                BYTE keyData[32]; // 假设密钥长度不超过32字节
                            } keyBlob{};

                            keyBlob.blobHeader.bType = PLAINTEXTKEYBLOB;
                            keyBlob.blobHeader.bVersion = CUR_BLOB_VERSION;
                            keyBlob.blobHeader.reserved = 0;
                            keyBlob.blobHeader.aiKeyAlg = CALG_AES_256; // 指定这是AES-256的密钥
                            keyBlob.keySize = static_cast<DWORD>(key.size());
                            memmove(keyBlob.keyData, key.data(), key.size());

                            const auto r00 = api->WinCrypt.CryptImportKey(
                                hProv,
                                reinterpret_cast<BYTE *>(&keyBlob),
                                sizeof(BLOBHEADER) +
                                sizeof(DWORD) + static_cast<DWORD>(key.size()),
                                0,
                                CRYPT_IPSEC_HMAC_KEY,
                                &hKey
                            );
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptImportKey failed: %lu", e);
                                throw exception("CryptImportKey failed", static_cast<INT>(e));
                            }
                        }
                        // 5. 设置密钥参数：ECB模式
                        {
                            // 设置CBC模式
                            const auto r00 = api->WinCrypt.CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE *>(&this->MODE), 0);
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptSetKeyParam KP_MODE failed: %lu", e);
                                throw exception("CryptImportKey failed", static_cast<INT>(e));
                            }
                            // CBC设置IV
                            const auto r01 = api->WinCrypt.CryptSetKeyParam(hKey, KP_IV, iv.data(), 0);
                            if (!r01) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptSetKeyParam KP_IV failed: %lu", e);
                                throw exception("CryptImportKey failed", e);
                            }
                            // 无需设置填充模式，默认使用PKCS5_PADDING
                            // 设置填充模式，使用NO_PADDING
                            // const auto r01 = CryptSetKeyParam(hKey, KP_PADDING,
                            //                                   reinterpret_cast<BYTE *>(&this->PADDING), 0);
                            // if (!r01) {
                            //     const auto e = GetLastError();
                            //     LOG_F(ERROR, "[X] CryptSetKeyParam KP_MODE failed: %lu", e);
                            //     throw exception("CryptImportKey failed", static_cast<INT>(e));
                            // }
                        }
                    } catch (exception &_) {
                        if (hKey) {
                            api->WinCrypt.CryptDestroyKey(hKey);
                            hKey = 0;
                        }
                        if (hProv) {
                            api->WinCrypt.CryptReleaseContext(hProv, 0);
                            hProv = 0;
                        }
                    }
                }

                ~AES256CBC() override {
                    const auto &api = api::GetInstance();
                    if (hKey) {
                        api->WinCrypt.CryptDestroyKey(hKey);
                        hKey = 0;
                    }
                    if (hProv) {
                        api->WinCrypt.CryptReleaseContext(hProv, 0);
                        hProv = 0;
                    }
                }

                INT32 Encrypt(
                    _Out_ vector<BYTE> &out,
                    _In_ const vector<BYTE> &cleared
                ) override {
                    const auto &api = api::GetInstance();
                    INT32 retCode = ERROR_SUCCESS;
                    auto encrypted = cleared; // 复制数据以进行原地加密
                    DWORD dataLen = (DWORD) encrypted.size();
                    DWORD bufferLen = dataLen; // 初始缓冲区大小
                    // CryptEncrypt 需要额外的空间用于填充 (Padding)
                    // AES块大小为16字节，因此最多需要额外15字节的填充
                    encrypted.resize(dataLen + 16);
                    const auto r00 = api->WinCrypt.CryptEncrypt(hKey, 0, TRUE, 0, encrypted.data(), &dataLen, encrypted.size());
                    if (!r00) {
                        const auto e = GetLastError();
                        LOG_F(ERROR, "[X] CryptEncrypt failed: %lu", e);
                        retCode = static_cast<INT32>(e);
                        goto __ERROR__;
                    }
                    // 调整大小为实际加密后的大小
                    encrypted.resize(dataLen);
                    out = encrypted;
                    goto __FREE__;
                __ERROR__:
                    do {
                    } while (false);
                __FREE__:
                    return retCode;
                }

                INT32 Decrypt(
                    _Out_ vector<BYTE> &out,
                    _In_ const vector<BYTE> &encrypted
                ) override {
                    const auto &api = api::GetInstance();
                    INT32 retCode = ERROR_SUCCESS;
                    out = encrypted; // 复制数据以进行原地加密
                    DWORD dataLen = encrypted.size();
                    // CryptEncrypt 需要额外的空间用于填充 (Padding)
                    // AES块大小为16字节，因此最多需要额外15字节的填充
                    const auto r00 = api->WinCrypt.CryptDecrypt(hKey, 0, TRUE, 0, out.data(), &dataLen);
                    if (!r00) {
                        const auto e = GetLastError();
                        LOG_F(ERROR, "[X] CryptEncrypt failed: %lu", e);
                        retCode = static_cast<INT32>(e);
                        goto __ERROR__;
                    }
                    // 调整大小为实际加密后的大小
                    out.resize(dataLen);
                    goto __FREE__;
                __ERROR__:
                    PASS;
                __FREE__:
                    return retCode;
                }
            };

            class AES256CTR final : public base::crypto::ISync {
            protected:
                UINT64 &nonce;
                HCRYPTPROV hProv{};
                HCRYPTKEY hKey{};
                DWORD MODE = CRYPT_MODE_ECB;
                DWORD PADDING = ZERO_PADDING;
                vector<BYTE> key{};

            public:
                explicit AES256CTR(
                    _In_ const vector<BYTE> &key,
                    _Inout_ const UINT64 &nonce
                ): nonce() {
                    const auto &api = api::GetInstance();
                    try {
                        // 检测所用API
                        {
                            // CryptAcquireContextA
                            if (nullptr == api->WinCrypt.CryptAcquireContextA) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptAcquireContextA is null");
                                throw exception("api->WinCrypt.CryptAcquireContextA is null");
                            }
                            // CryptReleaseContext
                            if (nullptr == api->WinCrypt.CryptReleaseContext) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptReleaseContext is null");
                                throw exception("api->WinCrypt.CryptReleaseContext is null");
                            }
                            // CryptImportKey
                            if (nullptr == api->WinCrypt.CryptImportKey) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptImportKey is null");
                                throw exception("api->WinCrypt.CryptImportKey is null");
                            }
                            // CryptDestroyKey
                            if (nullptr == api->WinCrypt.CryptDestroyKey) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptDestroyKey is null");
                                throw exception("api->WinCrypt.CryptDestroyKey is null");
                            }
                            // CryptSetKeyParam
                            if (nullptr == api->WinCrypt.CryptSetKeyParam) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptSetKeyParam is null");
                                throw exception("api->WinCrypt.CryptSetKeyParam is null");
                            }
                            // CryptEncrypt
                            if (nullptr == api->WinCrypt.CryptEncrypt) {
                                LOG_F(ERROR, "[X] api->WinCrypt.CryptEncrypt is null");
                                throw exception("api->WinCrypt.CryptEncrypt is null");
                            }
                        }
                        // 检测key长度
                        {
                            this->key = key;
                            if (this->key.size() != 32 && this->key.size() != 24 && this->key.size() != 16) {
                                LOG_F(ERROR, "[X] AES_CBC key size error: %lu", this->key.size());
                                throw length_error("AES_CBC key size error");
                            }
                        }
                        // 检测nonce，如果为0则初始化。
                        {
                            this->nonce = nonce;
                            if (this->nonce == 0) {
                                auto *p0 = &this->nonce;
                                const auto r00 = RandomBuffer(p0, sizeof(UINT64));
                                if (r00 != ERROR_SUCCESS) {
                                    throw exception("[X] RandomBuffer failed: %lu", r00);
                                }
                            }
                        }
                        // 获取加密服务提供程序 (CSP) 的句柄
                        {
                            const auto r00 = api->WinCrypt.CryptAcquireContextA(
                                &hProv,
                                nullptr,
                                //MS_ENH_RSA_AES_PROV, // 使用支持AES的Provider
                                nullptr,
                                PROV_RSA_AES,
                                CRYPT_VERIFYCONTEXT);
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptAcquireContext CRYPT_VERIFYCONTEXT failed: %lu", e);
                                //retCode = (INT32)e;
                                // 另一种尝试
                                const auto r01 = api->WinCrypt.CryptAcquireContextA(&hProv, nullptr, nullptr, PROV_RSA_AES, 0);
                                if (!r01) {
                                    const auto e0 = GetLastError();
                                    LOG_F(ERROR, "[X] CryptAcquireContext 0 failed: %lu", e0);
                                    throw exception("CryptAcquireContext failed", static_cast<INT>(e0));
                                }
                            }
                        }
                        // 导入密钥以获取句柄
                        {
                            // 步骤 2: 将原始密钥导入CSP
                            // 我们需要构建一个 PLAINTEXTKEYBLOB 结构
                            struct {
                                BLOBHEADER blobHeader;
                                DWORD keySize;
                                BYTE keyData[32]; // 假设密钥长度不超过32字节
                            } keyBlob{};

                            keyBlob.blobHeader.bType = PLAINTEXTKEYBLOB;
                            keyBlob.blobHeader.bVersion = CUR_BLOB_VERSION;
                            keyBlob.blobHeader.reserved = 0;
                            keyBlob.blobHeader.aiKeyAlg = CALG_AES_256; // 指定这是AES-256的密钥
                            keyBlob.keySize = static_cast<DWORD>(key.size());
                            memmove(keyBlob.keyData, key.data(), key.size());

                            const auto r00 = api->WinCrypt.CryptImportKey(
                                hProv,
                                reinterpret_cast<BYTE *>(&keyBlob),
                                sizeof(BLOBHEADER) +
                                sizeof(DWORD) + static_cast<DWORD>(key.size()),
                                0,
                                CRYPT_IPSEC_HMAC_KEY,
                                &hKey
                            );
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptImportKey failed: %lu", e);
                                throw exception("CryptImportKey failed", static_cast<INT>(e));
                            }
                        }
                        // 5. 设置密钥参数：ECB模式
                        {
                            // 设置CBC模式
                            const auto r00 = api->WinCrypt.CryptSetKeyParam(hKey, KP_MODE, reinterpret_cast<BYTE *>(&this->MODE), 0);
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptSetKeyParam KP_MODE failed: %lu", e);
                                throw exception("CryptImportKey failed", static_cast<INT>(e));
                            }
                            // ECB无需设置IV
                            // const auto r01 = CryptSetKeyParam(hKey, KP_IV, (BYTE*)iv.data(), 0);
                            // if (!r01) {
                            //     const auto e = GetLastError();
                            //     LOG_F(ERROR, "[X] CryptSetKeyParam KP_IV failed: %lu", e);
                            //     throw exception("CryptImportKey failed", e);
                            // }
                            // 无需设置填充模式，默认使用PKCS5_PADDING
                            // 设置填充模式，使用NO_PADDING
                            const auto r01 = api->WinCrypt.CryptSetKeyParam(hKey, KP_PADDING,
                                                              reinterpret_cast<BYTE *>(&this->PADDING), 0);
                            if (!r01) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptSetKeyParam KP_MODE failed: %lu", e);
                                throw exception("CryptImportKey failed", static_cast<INT>(e));
                            }
                        }
                    } catch (exception &_) {
                        if (hKey) {
                            api->WinCrypt.CryptDestroyKey(hKey);
                            hKey = 0;
                        }
                        if (hProv) {
                            api->WinCrypt.CryptReleaseContext(hProv, 0);
                            hProv = 0;
                        }
                    }
                }

                ~AES256CTR() override {
                    const auto &api = api::GetInstance();
                    if (hKey) {
                        api->WinCrypt.CryptDestroyKey(hKey);
                        hKey = 0;
                    }
                    if (hProv) {
                        api->WinCrypt.CryptReleaseContext(hProv, 0);
                        hProv = 0;
                    }
                }

                INT32 Encrypt(
                    _Out_ vector<BYTE> &out,
                    _In_ const vector<BYTE> &cleared
                ) override {
                    const auto &api = api::GetInstance();
                    INT32 retCode = 0;
                    const bool padding = cleared.size() % 16 != 0;
                    const auto nBlocks = padding ? cleared.size() / 16 + 1 : cleared.size() / 16;
                    for (auto i = 0; i < nBlocks; i++) {
                        UINT64 ctr = (i + 1) & 0xffffffffffffffff;
                        BYTE xBlock[32];
                        // 加密块
                        {
                            memmove(xBlock, &this->nonce, sizeof(UINT64));
                            const BYTE *p = reinterpret_cast<BYTE *>(&ctr);
                            for (auto j = 0; j < sizeof(UINT64); j++) {
                                xBlock[8 + j] = p[7 - j];
                            }
                            DWORD dataLen = sizeof(xBlock);
                            const auto r00 = api->WinCrypt.CryptEncrypt(hKey, 0, TRUE, 0, xBlock, &dataLen, dataLen);
                            if (!r00) {
                                const auto e = GetLastError();
                                LOG_F(ERROR, "[X] CryptEncrypt failed: %lu", e);
                                retCode = static_cast<INT32>(e);
                                goto __ERROR__;
                            }
                        }
                        // 与数据进行异或
                        {
                            const auto p0 = i * 16;
                            auto p1 = p0 + 16;
                            if (p1 > cleared.size()) {
                                p1 = cleared.size();
                            }
                            for (auto j = p0, k = 0; j < p1; j++, k++) {
                                const auto b = static_cast<BYTE>(cleared[j] ^ xBlock[k]);
                                out.push_back(b);
                            }
                        }
                    }
                    goto __FREE__;
                __ERROR__:
                    PASS;
                __FREE__:
                    return retCode;
                }

                INT32 Decrypt(
                    _Out_ vector<BYTE> &out,
                    _In_ const vector<BYTE> &encrypted
                ) override {
                    // CTR模式加密即为解密
                    return Encrypt(out, encrypted);
                }
            };

            auto Win32Crypto = cpl::crypto::Crypto(RandomBuffer);
#endif // 0 (legacy base::crypto classes disabled)
        }
    }

    // ========================================================================
    // cpl::sys::crypto — Win32 CSPRNG providers (new Result API)
    //
    // Four IRandom implementations backed by the Windows native RNG, each
    // following the fallback chain decided at construction time by the caller
    // (BCrypt → RtlGenRandom → CryptGenRandom). Every provider degrades
    // internally: if its primary API pointer is null or fails, it transparently
    // falls through to the next available mechanism so a single provider is
    // robust on its own. All four implement cpl::crypto::IRandom so they can be
    // held via unique_ptr<cpl::crypto::IRandom>.
    //
    // Backends are resolved through the NEW api system: cpl::sys::api::API
    // (api.hpp:2696), reached via API::Instance() (base::ISingleton<API>).
    // The bcrypt/AdvAPI32 function pointers there are loaded optionally, so
    // null checks are mandatory.
    // ========================================================================
#ifndef CPL_BCRYPT_USE_SYSTEM_PREFERRED_RNG
#define CPL_BCRYPT_USE_SYSTEM_PREFERRED_RNG 0x00000002UL
#endif
    namespace sys {
        namespace crypto {

            // ---- shared helper: CryptGenRandom path (AdvAPI32) ---------------
            // Used both by CryptRandomProvider and as the internal fallback for
            // BCrypt/Rtl providers. Returns Win32 error code (0 == success).
            inline int32_t CryptGenRandomFill(_Inout_ void *buffer, _In_ size_t size) {
                if (nullptr == buffer || size == 0U) {
                    return ERROR_INVALID_PARAMETER;
                }
                const auto &api = cpl::sys::api::API::Instance();
                if (nullptr == api.AdvAPI32.CryptAcquireContextA
                    || nullptr == api.AdvAPI32.CryptReleaseContext
                    || nullptr == api.AdvAPI32.CryptGenRandom) {
                    return ERROR_API_UNAVAILABLE;
                }

                HCRYPTPROV hProv{};
                const BOOL rCtx = api.AdvAPI32.CryptAcquireContextA(
                    &hProv, nullptr, nullptr, PROV_RSA_FULL,
                    CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
                if (!rCtx) {
                    return static_cast<int32_t>(GetLastError());
                }

                int32_t retCode = ERROR_SUCCESS;
                size_t off = 0U;
                while (off < size) {
                    const auto chunk = static_cast<DWORD>(
                        (size - off) > 0xFFFFFFFFUL ? 0xFFFFFFFFUL : (size - off));
                    const BOOL rGen = api.AdvAPI32.CryptGenRandom(
                        hProv, chunk, static_cast<BYTE *>(buffer) + off);
                    if (!rGen) {
                        retCode = static_cast<int32_t>(GetLastError());
                        break;
                    }
                    off += chunk;
                }

                (void) api.AdvAPI32.CryptReleaseContext(hProv, 0);
                return retCode;
            }

            // ---- 1. BCryptRandomProvider (Vista+, preferred) -----------------
            class BCryptRandomProvider final : public cpl::crypto::IRandom {
            public:
                Int32Result Rand(_Inout_ void *buffer, _In_ size_t size) override {
                    if (nullptr == buffer || size == 0U) {
                        return Err(cpl::Error(cpl::Error::InvalidArgument(),
                            "[X] BCryptRandomProvider::Rand" CPL_FILE_AND_LINE));
                    }
                    const auto &api = cpl::sys::api::API::Instance();
                    if (api.bcrypt.BCryptGenRandom != nullptr) {
                        size_t off = 0U;
                        bool ok = true;
                        while (off < size) {
                            const auto chunk = static_cast<ULONG>(
                                (size - off) > 0xFFFFFFFFUL ? 0xFFFFFFFFUL : (size - off));
                            // hAlgorithm = NULL + BCRYPT_USE_SYSTEM_PREFERRED_RNG
                            // avoids needing BCryptOpenAlgorithmProvider.
                            const NTSTATUS st = api.bcrypt.BCryptGenRandom(
                                nullptr,
                                static_cast<PUCHAR>(buffer) + off,
                                chunk,
                                CPL_BCRYPT_USE_SYSTEM_PREFERRED_RNG);
                            if (st != 0) {
                                ok = false;
                                break;
                            }
                            off += chunk;
                        }
                        if (ok) {
                            return 0;
                        }
                    }
                    // Internal fallback: CryptGenRandom path.
                    const auto rc = CryptGenRandomFill(buffer, size);
                    if (rc == ERROR_SUCCESS) {
                        return 0;
                    }
                    return Err(cpl::Error(static_cast<int64_t>(rc),
                        "[X] BCryptRandomProvider::Rand fallback failed" CPL_FILE_AND_LINE));
                }
            };

            // ---- 2. RtlRandomProvider (undocumented, XP+) --------------------
            class RtlRandomProvider final : public cpl::crypto::IRandom {
            public:
                Int32Result Rand(_Inout_ void *buffer, _In_ size_t size) override {
                    if (nullptr == buffer || size == 0U) {
                        return Err(cpl::Error(cpl::Error::InvalidArgument(),
                            "[X] RtlRandomProvider::Rand" CPL_FILE_AND_LINE));
                    }
                    const auto &api = cpl::sys::api::API::Instance();
                    if (api.AdvAPI32.RtlGenRandom != nullptr) {
                        size_t off = 0U;
                        bool ok = true;
                        while (off < size) {
                            const auto chunk = static_cast<ULONG>(
                                (size - off) > 0xFFFFFFFFUL ? 0xFFFFFFFFUL : (size - off));
                            const BOOLEAN r = api.AdvAPI32.RtlGenRandom(
                                static_cast<PVOID>(static_cast<BYTE *>(buffer) + off),
                                chunk);
                            if (!r) {
                                ok = false;
                                break;
                            }
                            off += chunk;
                        }
                        if (ok) {
                            return 0;
                        }
                    }
                    // Internal fallback: CryptGenRandom path.
                    const auto rc = CryptGenRandomFill(buffer, size);
                    if (rc == ERROR_SUCCESS) {
                        return 0;
                    }
                    return Err(cpl::Error(static_cast<int64_t>(rc),
                        "[X] RtlRandomProvider::Rand fallback failed" CPL_FILE_AND_LINE));
                }
            };

            // ---- 3. CryptRandomProvider (legacy CryptoAPI, XP+) --------------
            class CryptRandomProvider final : public cpl::crypto::IRandom {
            public:
                Int32Result Rand(_Inout_ void *buffer, _In_ size_t size) override {
                    if (nullptr == buffer || size == 0U) {
                        return Err(cpl::Error(cpl::Error::InvalidArgument(),
                            "[X] CryptRandomProvider::Rand" CPL_FILE_AND_LINE));
                    }
                    const auto rc = CryptGenRandomFill(buffer, size);
                    if (rc == ERROR_SUCCESS) {
                        return 0;
                    }
                    return Err(cpl::Error(static_cast<int64_t>(rc),
                        "[X] CryptRandomProvider::Rand failed" CPL_FILE_AND_LINE));
                }
            };

            // ---- 4. UnsafeRandomProvider (non-cryptographic, last resort) ----
            // Thin wrapper over cpl::crypto::impl::GetUnsafeRandomProvider()
            // so callers can keep a single namespace (cpl::sys::crypto) for the
            // whole provider ladder. NOT for cryptographic use.
            class UnsafeRandomProvider final : public cpl::crypto::IRandom {
            public:
                Int32Result Rand(_Inout_ void *buffer, _In_ size_t size) override {
                    if (nullptr == buffer || size == 0U) {
                        return Err(cpl::Error(cpl::Error::InvalidArgument(),
                            "[X] UnsafeRandomProvider::Rand" CPL_FILE_AND_LINE));
                    }
                    return cpl::crypto::impl::GetUnsafeRandomProvider().Rand(buffer, size);
                }
            };

        } // namespace crypto
    } // namespace sys
}

#endif //CPL_WIN32_CRYPTO_HPP_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE
