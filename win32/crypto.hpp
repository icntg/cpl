#ifndef CPL_CRYPTO_WIN32_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE
#define CPL_CRYPTO_WIN32_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE

#include "api.hpp"
#include "../crypto.hpp"

namespace cpl {
    namespace sys {
        namespace crypto {
            class Errors final {
            public:
                static constexpr int64_t base = static_cast<int64_t>(0x30) << 32;
                static constexpr cpl::Error::CodeDef BCryptGenRandom = {base | 1};
                static constexpr cpl::Error::CodeDef RtlGenRandom = {base | 2};
                static constexpr cpl::Error::CodeDef CryptGenRandom = {base | 3};
                static constexpr cpl::Error::CodeDef CryptAcquireContextA = {base | 4};
                static constexpr cpl::Error::CodeDef APIUnavailable = {base | 5};
            };

            class BCryptRandomProvider final : public cpl::crypto::IRandom {
            public:
                BCryptRandomProvider() = default;

                ~BCryptRandomProvider() override = default;

                Int32Result Rand(void *buffer, const size_t size) override {
                    if (!buffer || size == 0) {
                        return Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
                    }
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (!api || !api->bcrypt.BCryptGenRandom) {
                        return Err(cpl::Error(Errors::APIUnavailable, "api->bcrypt.BCryptGenRandom" CPL_FILE_AND_LINE));
                    }
                    const auto r00 = api->bcrypt.BCryptGenRandom(
                        nullptr,
                        static_cast<PUCHAR>(buffer),
                        static_cast<ULONG>(size),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG
                    );
                    if (!NT_SUCCESS(r00)) {
                        const auto e = GetLastError();
                        return Win32Error(
                            Errors::BCryptGenRandom,
                            "[X] api->bcrypt.BCryptGenRandom failed [%lu][%s]" CPL_FILE_AND_LINE, e
                        );
                    }
                    return 0;
                }
            };

            class RtlRandomProvider final : public cpl::crypto::IRandom {
            public:
                RtlRandomProvider() = default;

                ~RtlRandomProvider() override = default;

                Int32Result Rand(void *buffer, size_t size) override {
                    if (!buffer || size == 0) {
                        return Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
                    }
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (!api || !api->AdvAPI32.RtlGenRandom) {
                        return Err(cpl::Error(Errors::APIUnavailable, "api->AdvAPI32.RtlGenRandom" CPL_FILE_AND_LINE));
                    }
                    const auto r00 = api->AdvAPI32.RtlGenRandom(buffer, size);
                    if (!r00) {
                        const auto e = GetLastError();
                        return Win32Error(
                            Errors::RtlGenRandom,
                            "[X] api->AdvAPI32.RtlGenRandom failed [%lu][%s]" CPL_FILE_AND_LINE, e
                        );
                    }
                    return 0;
                }
            };

            class CryptRandomProvider final : public cpl::crypto::IRandom {
                HCRYPTPROV hCryptProv{};

            public:
                CryptRandomProvider() = default;

                ~CryptRandomProvider() override {
                    if (this->hCryptProv) {
                        const auto *api = &cpl::sys::api::API::Instance();
                        if (api && api->AdvAPI32.CryptReleaseContext) {
                            api->AdvAPI32.CryptReleaseContext(hCryptProv, 0);
                        }
                        this->hCryptProv = 0;
                    }
                }

                Int32Result Rand(void *buffer, size_t size) override {
                    if (!buffer || size == 0) {
                        return Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
                    }
                    const auto *api = &cpl::sys::api::API::Instance();
                    if (!api
                        || nullptr == api->AdvAPI32.CryptAcquireContextA
                        || nullptr == api->AdvAPI32.CryptReleaseContext
                        || nullptr == api->AdvAPI32.CryptGenRandom) {
                        return Err(cpl::Error(Errors::APIUnavailable,
                                              "api->AdvAPI32.CryptGenRandom" CPL_FILE_AND_LINE));
                    }

                    if (0 == this->hCryptProv) {
                        const auto r00 = api->AdvAPI32.CryptAcquireContextA(
                            &this->hCryptProv,
                            nullptr,
                            nullptr,
                            PROV_RSA_FULL,
                            CRYPT_VERIFYCONTEXT
                        );
                        if (!r00) {
                            const auto e = GetLastError();
                            return Win32Error(
                                Errors::CryptAcquireContextA,
                                "[X] api->advapi32.CryptAcquireContextA failed [%lu][%s]" CPL_FILE_AND_LINE, e
                            );
                        }
                    }

                    const auto r01 = api->AdvAPI32.CryptGenRandom(
                        hCryptProv,
                        static_cast<DWORD>(size),
                        static_cast<BYTE *>(buffer)
                    );
                    if (!r01) {
                        const auto e = GetLastError();
                        return Win32Error(
                            Errors::CryptGenRandom,
                            "[X] api->advapi32.CryptGenRandom failed [%lu][%s]" CPL_FILE_AND_LINE, e
                        );
                    }
                    return 0;
                }
            };
        }
    }
}

#endif // CPL_CRYPTO_WIN32_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE
