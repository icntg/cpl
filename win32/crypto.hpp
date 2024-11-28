#ifndef CPL_WIN32_CRYPTO_HPP_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE
#define CPL_WIN32_CRYPTO_HPP_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE

#include <cstdint>
#include "api.hpp"
#include "../utility/crypto.hpp"

namespace cpl {
    namespace win32 {
        namespace crypto {
            inline int32_t Win32RandomBuffer(_Inout_ void *buffer, _In_ const uint32_t size) {
                if (nullptr == buffer || size <= 0) {
                    return ERROR_INVALID_DATA;
                }
                const auto &api = api::API::Instance();
                int32_t retCode = ERROR_SUCCESS;
                HCRYPTPROV hCryptProv{};
                BOOL bContext = FALSE;
                BOOL bRet = FALSE;

                if (nullptr == api.Crypto.CryptGenRandom || nullptr == api.Crypto.CryptGenRandom || nullptr == api.Crypto.
                    CryptReleaseContext) {
                    retCode = ERROR_API_UNAVAILABLE;
                    goto __ERROR__;
                    }

                bRet = api.Crypto.CryptAcquireContextA(
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
                bRet = api.Crypto.CryptGenRandom(
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
                        bRet = CryptReleaseContext(hCryptProv, 0);
                        if (!bRet) {
                            const DWORD e = GetLastError();
                            retCode = static_cast<int32_t>(e);
                        }
                        bzero(&hCryptProv, sizeof(HCRYPTPROV));
                    }
                return retCode;
            }

            auto Win32Crypto = cpl::crypto::Crypto(Win32RandomBuffer);
        }
    }
}

#endif //CPL_WIN32_CRYPTO_HPP_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE
