// todo
#ifndef CRYPTO_H_JUSTICE_TENSION_STRONGER_MOISTURE_BLAZING_ENCHANTED_VICTORY_GALLERY
#define CRYPTO_H_JUSTICE_TENSION_STRONGER_MOISTURE_BLAZING_ENCHANTED_VICTORY_GALLERY

#include <string>
#include <cstdint>
#include <cerrno>

using namespace std;

namespace crypto {
    constexpr auto SZ_HASH16 = 16;
    constexpr auto SZ_HASH8 = 8;
    constexpr auto SZ_HASH32 = 32;
    constexpr auto SZ_N_ONCE = 8;
    constexpr auto SZ_HMAC16 = 16;

    inline int32_t RandomBuffer(
        void *buffer,
        size_t size,
        int32_t (* true_random_func)(void *, size_t) = nullptr
    ) {
        if (nullptr == buffer || size <= 0) {
            return EADDRNOTAVAIL;
        }

        int32_t retCode = 0;

        if (true_random_func != nullptr) {

        }
        HCRYPTPROV hCryptProv{};
        BOOL bContext = FALSE;
        BOOL bRet = FALSE;

        if (nullptr == api.Crypto.CryptGenRandom || nullptr == api.Crypto.CryptGenRandom || nullptr == api.Crypto.
            CryptReleaseContext) {
            // use insecure method
            goto __ERROR__;
        }

        bRet = api.Crypto.CryptAcquireContextA(
            &hCryptProv, // handle to the CSP
            "Administrator", // container name
            "Microsoft Base Cryptographic Provider v1.0", // use the default provider
            PROV_RSA_FULL, // provider type
            CRYPT_VERIFYCONTEXT);
        if (!bRet) {
            const DWORD e = GetLastError();
            log_error("CryptAcquireContext failed [0x%lx]: %s", e, FormatError(e).data());
            goto __ERROR__;
        }
        bContext = TRUE;
        bRet = api.Crypto.CryptGenRandom(
            hCryptProv,
            size,
            static_cast<BYTE *>(buffer)
        );
        if (!bRet) {
            const DWORD e = GetLastError();
            log_error("CryptAcquireContext failed [0x%lx]: %s", e, FormatError(e).data());
            goto __ERROR__;
        }
        goto __FREE__;
    __ERROR__:
        retCode = Crypto$$$RandomBufferInsecure(buffer, size);
    __FREE__:
        if (bContext) {
            bRet = CryptReleaseContext(hCryptProv, 0);
            if (!bRet) {
                const DWORD e = GetLastError();
                log_error("CryptReleaseContext failed [0x%lx]: %s", e, FormatError(e).data());
            }
            bzero(&hCryptProv, sizeof(HCRYPTPROV));
        }
        return retCode;
    }

    inline INT32 Encrypt(_In_ const string &key, _In_ const string &plain, _Out_ string &encrypted,
                         _In_opt_ const TCHAR nonce[SIZE_NONCE] = nullptr) {


        INT32 retCode = ERROR_SUCCESS;
        uint8_t iv[SIZE_NONCE]{};
        bzero(iv, SIZE_NONCE);
        uint8_t hash[SIZE_HMAC16]{};

        size_t nBytes{};
        const char *pc_hash{}, *pc_iv{}, *pc_enc{};
        char *p_hash{}, *p_iv{}, *p_enc{};
        void *pv_hash{}, *pv_iv{};

        encrypted.clear();
        const auto reserved_length = plain.size() + SIZE_NONCE + SIZE_HMAC16 + 16;
        encrypted.reserve(reserved_length);

        pc_hash = encrypted.data();
        memmove(&p_hash, &pc_hash, sizeof(void *));
        bzero(p_hash, reserved_length);

        if (nullptr == nonce) {
            retCode = RandomBuffer(iv, SIZE_NONCE);
            if (ERROR_SUCCESS != retCode) {
                log_error("RandomBuffer failed %ld", retCode);
                goto __ERROR__;
            }
        }

        // 这里增加一个是为了保证后面合并时不被string自动添加的\x00覆盖。
        pc_enc = encrypted.data() + SIZE_HMAC16 + SIZE_NONCE + 1;
        memmove(&p_enc, &pc_enc, sizeof(char *));

        retCode = Crypto$$$Encrypt(
                key.data(), key.size(), iv,
                plain.data(), plain.size(),
                hash, p_enc, &nBytes
        );
        if (ERROR_SUCCESS != retCode) {
            log_error("Crypto$$$Encrypt failed %ld", retCode);
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

    inline INT32 Decrypt(_In_ const string &key, _In_ const string &encrypted, _Out_ string &plain) {
        plain.reserve(encrypted.size());
        INT32 retCode = ERROR_SUCCESS;
        const char *pc = plain.data();
        char *p = nullptr;
        memmove(&p, &pc, sizeof(char *));
        size_t nBytes = 0;
        retCode = Crypto$$$DecryptStream(key.data(), key.size(), encrypted.data(), p, &nBytes);
        if (ERROR_SUCCESS != retCode) {
            log_error("Crypto$$$DecryptStream failed %ld", retCode);
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

#endif // CRYPTO_H_JUSTICE_TENSION_STRONGER_MOISTURE_BLAZING_ENCHANTED_VICTORY_GALLERY