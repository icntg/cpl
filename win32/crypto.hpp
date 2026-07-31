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
                        return Err(cpl::Error(cpl::Error::InvalidArgument,
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
                        return Err(cpl::Error(cpl::Error::InvalidArgument,
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
                        return Err(cpl::Error(cpl::Error::InvalidArgument,
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
                        return Err(cpl::Error(cpl::Error::InvalidArgument,
                            "[X] UnsafeRandomProvider::Rand" CPL_FILE_AND_LINE));
                    }
                    return cpl::crypto::impl::GetUnsafeRandomProvider().Rand(buffer, size);
                }
            };

        } // namespace crypto
    } // namespace sys
}

#endif //CPL_WIN32_CRYPTO_HPP_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE
