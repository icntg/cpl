#ifndef CPL_CRYPTO_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE
#define CPL_CRYPTO_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE

#include <string>
#include <vector>
#include <thread>
#include <cstdlib>
#include <array>
#include <memory>
#include <cstring>
#include <ctime>

#include "strings.hpp"

#ifdef _WIN32
#include <process.h>
#else
#include <unistd.h>
#endif
#include "base.hpp"

#ifdef _MSC_VER
#   pragma warning(push)
#   pragma warning(disable: 4996) // rand() is deprecated, but required for compatibility
#endif

namespace cpl {
    namespace crypto {
        class Errors final {
        public:
            // C++11 note: static constexpr data members that are ODR-used (passed
            // by value to Error below) require an out-of-class definition, which
            // is problematic for a header-only lib. Exposing them as constexpr
            // accessor functions avoids the ODR issue entirely while preserving
            // compile-time evaluation. Usage unchanged: Errors::SHA256_() etc.
            static constexpr int64_t base = static_cast<int64_t>(2) << 32;
            static constexpr cpl::Error::CodeDef SHA256_() { return cpl::Error::CodeDef{static_cast<int64_t>(base | 1)}; }
            static constexpr cpl::Error::CodeDef HMAC256_() { return cpl::Error::CodeDef{static_cast<int64_t>(base | 2)}; }
            static constexpr cpl::Error::CodeDef LENGTH_ENCODE_() { return cpl::Error::CodeDef{static_cast<int64_t>(base | 3)}; }
            static constexpr cpl::Error::CodeDef CREATE_RC4_() { return cpl::Error::CodeDef{static_cast<int64_t>(base | 0x20)}; }
        };

        class IRandom {
        public:
            virtual ~IRandom() = default;

            virtual Int32Result Rand(_Inout_ void *buffer, _In_ size_t size) = 0;
        };

        class IHash {
        public:
            virtual ~IHash() = default;

            virtual Int32Result Update(_In_ const void *buffer, _In_ size_t size) = 0;

            virtual Int32Result Summary(_Out_ void *buffer, _Out_ size_t &size) = 0;
        };

        class ISync {
        public:
            virtual ~ISync() = default;

            virtual Int32Result Encrypt(
                _Out_ void *outBuffer, _Out_ size_t &outSize,
                _In_ const void *inBuffer, _In_ size_t inSize) = 0;

            virtual Int32Result Decrypt(
                _Out_ void *outBuffer, _Out_ size_t &outSize,
                _In_ const void *inBuffer, _In_ size_t inSize) = 0;
        };

        class IAsync : public ISync {
        public:
            ~IAsync() override = default;

            virtual Int32Result Sign(
                _Out_ void *outBuffer, _Out_ size_t &outSize,
                _In_ void *inBuffer, _In_ size_t inSize) = 0;

            virtual cpl::Result<bool> Verify(
                _In_ void *inBuffer,
                _In_ size_t inSize,
                _In_ void *expected,
                _In_ size_t expSize
            ) = 0;
        };

        namespace impl {
            class UnsafeRandom final : public cpl::crypto::IRandom {
                using B32 = union {
                    uint8_t array[4];
                    uint32_t value;
                };

                using B64 = union {
                    uint8_t array[8];
                    uint64_t value;
                };

                // Random derivation function: derive a uint32_t value from a uint64_t seed.
                /**
                 *
                 * @param seed
                 * @return
                 */
                static uint32_t randDerive(const uint64_t seed) {
                    B32 b32{};
                    B64 b64{};
                    b64.value = seed;
                    for (int i = 0; i < sizeof(uint32_t); i++) {
                        const auto j = sizeof(uint64_t) - i - 1;
                        b32.array[i] = b64.array[i] ^ b64.array[j];
                    }
                    srand(b32.value);
                    uint32_t rn{};
                    for (int i = 0; i < sizeof(uint32_t); i++) {
                        // NOLINTNEXTLINE(cert-msc50-cpp, readability-identifier-naming)
                        rn = (rn << 8) | static_cast<uint32_t>(rand() & 0xff);
                    }
                    return rn;
                }

            public:
                Int32Result Rand(_Inout_ void *buffer, _In_ const size_t size) override {
                    if (!buffer || size <= 0) {
                        return cpl::Err(cpl::Error(cpl::Error::NullPointer(), CPL_FILE_AND_LINE));
                    }
                    // unsafe random generator.
                    // params from
                    // 1. TIME
                    // 2. counter
                    // 3. Global Address
                    // 4. Stack Address
                    // 5. Heap Address ^ Heap Unknown Value (8bytes)
                    // 6. ProcessID
                    // 7. ThreadID
                    // 8. Buffer Unknown Value (1bytes) ^ Size
                    {
                        uint32_t timeParam{};
                        // time
                        {
                            const auto t = time(nullptr);
                            timeParam = randDerive(t);
                        }
                        uint32_t counterParam{};
                        // counter
                        {
                            static uint32_t counter{};
                            counterParam = randDerive(counter);
                            counter += 1;
                        }
                        uint32_t globalParam{};
                        // global address
                        {
                            static uint32_t global{};
                            const auto p = *reinterpret_cast<uint64_t *>(&global);
                            globalParam = randDerive(p);
                        }
                        uint32_t stackParam{};
                        // stack address
                        {
                            uint32_t stack{};
                            const auto p = *reinterpret_cast<uint64_t *>(&stack);
                            stackParam = randDerive(p);
                        }
                        uint32_t heapParam{};
                        // heap
                        {
                            void *heapPointer{};
                            const auto defer = cpl::base::MakeDefer([&]() {
                                if (heapPointer) {
                                    free(heapPointer);
                                    heapPointer = nullptr;
                                }
                            });
                            heapPointer = malloc(sizeof(uint64_t));
                            if (nullptr == heapPointer) {
                                return cpl::Err(cpl::Error(cpl::Error::OutOfMemory(), CPL_FILE_AND_LINE));
                            }
                            uint64_t heapAddress{};
                            uint64_t heapValue{};
                            memcpy(&heapAddress, &heapPointer, sizeof(void *));
                            memcpy(&heapValue, heapPointer, sizeof(uint64_t));
                            heapParam = randDerive(heapAddress) ^ randDerive(heapValue);
                        }
                        uint32_t processIdParam{};
                        // processId
                        {
#ifdef _WIN32
                            const auto pid = static_cast<uint64_t>(_getpid());
#else
                            const auto pid = static_cast<uint64_t>(getpid());
#endif
                            processIdParam = randDerive(pid);
                        }
                        uint32_t threadIdParam{};
                        // threadId
                        {
                            const auto id = std::this_thread::get_id();
                            uint32_t tid{};
                            memcpy(&tid, &id, sizeof(uint32_t));
                            threadIdParam = randDerive(tid);
                        }
                        uint32_t bufferParam{};
                        // buffer
                        {
                            const auto b0 = *reinterpret_cast<uint8_t *>(&bufferParam);
                            bufferParam = randDerive(b0) ^ randDerive(size);
                        }
                        const auto seed = timeParam ^ counterParam
                                          ^ globalParam ^ stackParam ^ heapParam
                                          ^ processIdParam ^ threadIdParam
                                          ^ bufferParam;
                        srand(seed);
                    }
                    auto *p = static_cast<uint8_t *>(buffer);
                    for (size_t i = 0; i < size; i++) {
                        // NOLINTNEXTLINE(cert-msc50-cpp, readability-identifier-naming)
                        const auto r = rand();
                        *(p + i) = static_cast<uint8_t>(r & 0xff);
                    }
                    return {};
                }
            };

            inline UnsafeRandom &GetUnsafeRandomProvider() {
                static UnsafeRandom v;
                return v;
            }

            // auto UnsafeRandomProvider = UnsafeRandom();

            class RC4 final : public cpl::crypto::ISync {
            protected:
                Stream sbox;
                bool initialized{false};

                void KSA(const uint8_t *key, const size_t keyLength) {
                    sbox.resize(256);
                    for (size_t i = 0; i < 256; ++i) {
                        sbox[i] = static_cast<uint8_t>(i);
                    }

                    size_t j = 0;
                    for (size_t i = 0; i < 256; ++i) {
                        j = (j + sbox[i] + key[i % keyLength]) % 256;
                        std::swap(sbox[i], sbox[j]);
                    }
                }

                void PRGA(uint8_t *output, const uint8_t *input, const size_t length) {
                    size_t i = 0;
                    size_t j = 0;
                    for (size_t n = 0; n < length; ++n) {
                        i = (i + 1) % 256;
                        j = (j + sbox[i]) % 256;
                        std::swap(sbox[i], sbox[j]);
                        uint8_t k = sbox[(sbox[i] + sbox[j]) % 256];
                        output[n] = input[n] ^ k;
                    }
                }

                RC4() = default;

            public:
                static Result<RC4> Create(_In_ void *key, const _In_ size_t size) {
                    if (nullptr == key || size == 0) {
                        return cpl::Err(cpl::Error(cpl::Error::NullPointer(), CPL_FILE_AND_LINE));
                    }
                    auto instance = RC4();
                    instance.KSA(static_cast<uint8_t *>(key), size);
                    instance.initialized = true;
                    return instance;
                }

                Int32Result Encrypt(
                    _Out_ void *outBuffer, _Out_ size_t &outSize,
                    _In_ const void *inBuffer, const _In_ size_t inSize) override {
                    if (!outBuffer || !inBuffer || inSize == 0) {
                        return cpl::Err(cpl::Error(cpl::Error::NullPointer(), CPL_FILE_AND_LINE));
                    }
                    if (!initialized) {
                        return cpl::Err(cpl::Error(cpl::Error::InvalidArgument(), "RC4 not initialized"));
                    }
                    outSize = inSize;
                    PRGA(static_cast<uint8_t *>(outBuffer), static_cast<const uint8_t *>(inBuffer), inSize);
                    return {};
                }

                Int32Result Decrypt(
                    _Out_ void *outBuffer, _Out_ size_t &outSize,
                    _In_ const void *inBuffer, const _In_ size_t inSize) override {
                    return this->Encrypt(outBuffer, outSize, inBuffer, inSize);
                }
            };

            // test passed
            class SHA256 final : public cpl::crypto::IHash {
            public:
                static constexpr int SHA256_BYTES = 32;

            private:
                uint8_t mData[64]{};
                uint32_t mBlockLen{};
                uint64_t mBitLen{};
                uint32_t mState[8]{}; //A, B, C, D, E, F, G, H

                // Constants for SHA-256
                const uint32_t K[64] = {
                    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
                    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
                    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
                    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
                    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
                    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
                    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
                    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
                    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
                    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
                    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
                    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
                    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
                    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
                    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
                };

                static uint32_t right_rotate(uint32_t x, uint32_t n) {
                    return (x >> n) | (x << (32 - n));
                }

                static uint32_t choose(uint32_t e, uint32_t f, uint32_t g) {
                    return (e & f) ^ (~e & g);
                }

                static uint32_t majority(uint32_t a, uint32_t b, uint32_t c) {
                    return (a & (b | c)) | (b & c);
                }

                static uint32_t sig0(uint32_t x) {
                    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3);
                }

                static uint32_t sig1(uint32_t x) {
                    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10);
                }

                void transform() {
                    uint32_t maj{}, xorA{}, ch{}, xorE{}, sum{}, newA{}, newE{}, m[64]{};
                    uint32_t state[8]{};

                    for (uint8_t i = 0, j = 0; i < 16; i++, j += 4) {
                        // Split data in 32 bit blocks for the 16 first words
                        m[i] = (mData[j] << 24) | (mData[j + 1] << 16) | (mData[j + 2] << 8) | (mData[j + 3]);
                    }

                    for (uint8_t k = 16; k < 64; k++) {
                        // Remaining 48 blocks
                        m[k] = sig1(m[k - 2]) + m[k - 7] + sig0(m[k - 15]) + m[k - 16];
                    }

                    for (uint8_t i = 0; i < 8; i++) {
                        state[i] = mState[i];
                    }

                    for (uint8_t i = 0; i < 64; i++) {
                        maj = majority(state[0], state[1], state[2]);
                        xorA = right_rotate(state[0], 2) ^ right_rotate(state[0], 13) ^
                               right_rotate(state[0], 22);

                        ch = choose(state[4], state[5], state[6]);

                        xorE = right_rotate(state[4], 6) ^ right_rotate(state[4], 11) ^
                               right_rotate(state[4], 25);

                        sum = m[i] + K[i] + state[7] + ch + xorE;
                        newA = xorA + maj + sum;
                        newE = state[3] + sum;

                        state[7] = state[6];
                        state[6] = state[5];
                        state[5] = state[4];
                        state[4] = newE;
                        state[3] = state[2];
                        state[2] = state[1];
                        state[1] = state[0];
                        state[0] = newA;
                    }

                    for (uint8_t i = 0; i < 8; i++) {
                        this->mState[i] += state[i];
                    }
                }

                void pad() {
                    uint64_t i = this->mBlockLen;
                    const uint8_t end = this->mBlockLen < 56 ? 56 : 64;

                    this->mData[i++] = 0x80; // Append a bit 1
                    while (i < end) {
                        this->mData[i++] = 0x00; // Pad with zeros
                    }

                    if (this->mBlockLen >= 56) {
                        transform();
                        memset(this->mData, 0, 56);
                    }

                    // Append to the padding the total message's length in bits and transform.
                    this->mBitLen += this->mBlockLen * 8;
                    this->mData[63] = this->mBitLen;
                    this->mData[62] = this->mBitLen >> 8;
                    this->mData[61] = this->mBitLen >> 16;
                    this->mData[60] = this->mBitLen >> 24;
                    this->mData[59] = this->mBitLen >> 32;
                    this->mData[58] = this->mBitLen >> 40;
                    this->mData[57] = this->mBitLen >> 48;
                    this->mData[56] = this->mBitLen >> 56;
                    this->transform();
                }

                Int32Result revert(void *hash, const size_t size) const {
                    const auto hash_ = static_cast<uint8_t *>(hash);
                    if (size != SHA256_BYTES) {
                        return cpl::Err(cpl::Error(cpl::Error::OutOfRange(), "[X] hash.size() != 32" CPL_FILE_AND_LINE));
                    }
                    // SHA uses big endian byte ordering
                    // Revert all bytes
                    for (uint8_t i = 0; i < 4; i++) {
                        for (uint8_t j = 0; j < 8; j++) {
                            hash_[i + (j * 4)] = (this->mState[j] >> (24 - i * 8)) & 0x000000ff;
                        }
                    }
                    return 0;
                }

            public:
                SHA256() {
                    Reset();
                }

                void Reset() {
                    this->mState[0] = 0x6a09e667;
                    this->mState[1] = 0xbb67ae85;
                    this->mState[2] = 0x3c6ef372;
                    this->mState[3] = 0xa54ff53a;
                    this->mState[4] = 0x510e527f;
                    this->mState[5] = 0x9b05688c;
                    this->mState[6] = 0x1f83d9ab;
                    this->mState[7] = 0x5be0cd19;
                    this->mBlockLen = 0;
                    this->mBitLen = 0;
                }

                Int32Result Update(_In_ const void *buffer, const _In_ size_t size) override {
                    if (!buffer || size == 0) {
                        return cpl::Err(cpl::Error(cpl::Error::InvalidArgument(), CPL_FILE_AND_LINE));
                    }

                    const auto data = static_cast<const uint8_t *>(buffer);
                    for (size_t i = 0; i < size; i++) {
                        mData[mBlockLen++] = data[i];
                        if (mBlockLen == 64) {
                            transform();

                            // End of the block
                            mBitLen += 512;
                            mBlockLen = 0;
                        }
                    }
                    return {};
                }

                Int32Result Summary(_Out_ void *buffer, _Inout_ size_t &size) override {
                    if (nullptr == buffer) {
                        return cpl::Err(cpl::Error(cpl::Error::NullPointer(), CPL_FILE_AND_LINE));
                    }
                    if (size < SHA256_BYTES) {
                        size = SHA256_BYTES;
                        return cpl::Err(cpl::Error(cpl::Error::OutOfRange(), "Output buffer too small"));
                    }
                    this->pad();
                    auto *data = static_cast<uint8_t *>(buffer);
                    auto rv = this->revert(data, size);
                    if (!rv) {
                        return rv;
                    }
                    this->Reset();
                    size = SHA256_BYTES;
                    return 0;
                }
            };

            inline Int32Result sha256(
                _Out_ void *out,
                _Inout_ size_t &outSize,
                _In_ const void *in,
                _In_ const size_t inSize
            ) {
                auto instance = SHA256();
                auto r = instance.Update(in, inSize);
                if (!r) {
                    return r;
                }
                return instance.Summary(out, outSize);
            }

            // test passed
            class SHA256_HMAC final : public cpl::crypto::IHash {
            public:
                static constexpr int BLOCK_LEN = 64;

            private:
                const uint8_t I_PAD = 0x36;
                const uint8_t O_PAD = 0x5c;

                SHA256 innerSHA256{};
                SHA256 outerSHA256{};
                bool initialized{false};
                bool updated{};
                cpl::Error initError{};

                Int32Result init(const void *key, const size_t keyLen) {
                    if (key == nullptr || keyLen == 0) {
                        return cpl::Err(cpl::Error(cpl::Error::InvalidArgument(), "Invalid HMAC key"));
                    }
                    std::array<uint8_t, BLOCK_LEN> innerKey{};
                    std::array<uint8_t, BLOCK_LEN> outerKey{};

                    if (keyLen > BLOCK_LEN) {
                        std::array<uint8_t, BLOCK_LEN> hashedKey{};
                        size_t outSize = BLOCK_LEN;
                        const auto r00 = sha256(hashedKey.data(), outSize, key, keyLen);
                        if (!r00) {
                            return cpl::Err(cpl::Error(Errors::SHA256_(), CPL_FILE_AND_LINE));
                        }
                        memcpy(innerKey.data(), hashedKey.data(), hashedKey.size());
                        memcpy(outerKey.data(), hashedKey.data(), hashedKey.size());
                    } else {
                        memcpy(innerKey.data(), key, keyLen);
                        memcpy(outerKey.data(), key, keyLen);
                    }
                    // xor
                    for (size_t i = 0; i < BLOCK_LEN; i++) {
                        innerKey[i] ^= I_PAD;
                        outerKey[i] ^= O_PAD;
                    }

                    auto r00 = innerSHA256.Update(innerKey.data(), BLOCK_LEN);
                    if (!r00) {
                        return r00;
                    }
                    auto r01 = outerSHA256.Update(outerKey.data(), BLOCK_LEN);
                    if (!r01) {
                        return r01;
                    }
                    updated = false;
                    return {};
                }

            public:
                explicit SHA256_HMAC(const void *key, const size_t keyLen) {
                    const auto r = init(key, keyLen);
                    if (r) {
                        initialized = true;
                    } else {
                        initError = r.error();
                    }
                }

                Int32Result Update(_In_ const void *buffer, const _In_ size_t size) override {
                    if (!initialized) {
                        return cpl::Err(initError);
                    }
                    if (!buffer || size == 0) {
                        return cpl::Err(cpl::Error(cpl::Error::InvalidArgument(), CPL_FILE_AND_LINE));
                    }
                    auto r = innerSHA256.Update(buffer, size);
                    if (!r) {
                        return r;
                    }
                    updated = true;
                    return {};
                }

                Int32Result Summary(_Out_ void *buffer, _Out_ size_t &size) override {
                    if (!initialized) {
                        return cpl::Err(initError);
                    }
                    if (!buffer) {
                        return cpl::Err(cpl::Error(cpl::Error::NullPointer(), CPL_FILE_AND_LINE));
                    }
                    if (!updated) {
                        return cpl::Err(cpl::Error(cpl::Error::NoData(), CPL_FILE_AND_LINE));
                    }

                    uint8_t inner_hash[32];
                    size_t inner_hash_size = 32;
                    auto r0 = innerSHA256.Summary(inner_hash, inner_hash_size);
                    if (!r0) {
                        return r0;
                    }

                    auto r1 = outerSHA256.Update(inner_hash, inner_hash_size);

                    if (!r1) {
                        return r1;
                    }
                    auto r2 = outerSHA256.Summary(buffer, size);
                    if (!r2) {
                        return r2;
                    }

                    updated = false;
                    return {};
                }
            };

            inline Int32Result hmac256(
                void *out, size_t &outSize,
                const void *key, const size_t keyLen,
                const void *data, const size_t dataLen
            ) {
                auto instance = SHA256_HMAC(key, keyLen);
                auto r = instance.Update(data, dataLen);
                if (!r) {
                    return r;
                }
                return instance.Summary(out, outSize);
            }

            // Not tested yet.
            // Uses RC4 and HMAC-SHA256.
            class Crypto_RC4_HMAC256 final : public cpl::crypto::ISync {
            protected:
                IRandom *randomProvider{};
                Stream key;

            public:
                static constexpr int NONCE_BYTES_LENGTH = 8;
                static constexpr int SIGN_L_BYTES_LENGTH = 8;
                static constexpr int SIGN_E_BYTES_LENGTH = 8;

                explicit Crypto_RC4_HMAC256(const Stream &key, IRandom *randomProvider = nullptr) : key(key) {
                    if (nullptr == randomProvider) {
                        this->randomProvider = &GetUnsafeRandomProvider();
                    } else {
                        this->randomProvider = randomProvider;
                    }
                    this->key = key;
                }

                Int32Result Encrypt(
                    _Out_ void *outBuffer, _Out_ size_t &outSize,
                    _In_ const void *inBuffer, const _In_ size_t inSize
                ) override {
                    if (nullptr == inBuffer || nullptr == outBuffer) {
                        return cpl::Err(cpl::Error(cpl::Error::NullPointer(), CPL_FILE_AND_LINE));
                    }
                    // struct: signE, signL, nonce, length, encrypted
                    Stream encKey{}, signKey{};
                    Stream signL{}; // hmac from nonce to length
                    Stream signE{}; // hmac from signL to end
                    Stream nonce{};
                    Stream length{};
                    Stream encrypted{};
                    // make nonce
                    {
                        nonce.resize(NONCE_BYTES_LENGTH);
                        const auto r = this->randomProvider->Rand(nonce.data(), nonce.size());
                        if (!r) {
                            return r;
                        }
                    }
                    // make keys
                    {
                        size_t size = SHA256::SHA256_BYTES;
                        encKey.resize(size);
                        signKey.resize(size);
                        const auto r00 = cpl::crypto::impl::hmac256(
                            encKey.data(), size,
                            nonce.data(), nonce.size(),
                            key.data(), key.size());
                        if (!r00) {
                            return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                        }
                        encKey.resize(size);
                        size = SHA256::SHA256_BYTES;
                        const auto r01 = cpl::crypto::impl::hmac256(
                            signKey.data(), size,
                            key.data(), key.size(),
                            nonce.data(), nonce.size()
                        );
                        if (!r01) {
                            return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                        }
                        signKey.resize(size);
                    }
                    // calc length
                    {
                        const auto r00 = cpl::codec::Length::Encode(static_cast<int64_t>(inSize));
                        if (!r00) {
                            return cpl::Err(cpl::Error(crypto::Errors::LENGTH_ENCODE_(), CPL_FILE_AND_LINE));
                        }
                        length = r00.value();
                    }
                    // calc signL
                    {
                        auto instance = SHA256_HMAC(signKey.data(), signKey.size());
                        size_t size{SHA256::SHA256_BYTES};
                        signL.resize(size); {
                            const auto r = instance.Update(nonce.data(), nonce.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = instance.Update(length.data(), length.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = instance.Summary(signL.data(), size);
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        }
                        if (size != SHA256::SHA256_BYTES) {
                            return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), "Unexpected HMAC output size"));
                        }
                        // Truncate to the on-wire signature length (matches Decrypt).
                        signL.resize(SIGN_L_BYTES_LENGTH);
                    }
                    // crypt
                    {
                        auto _rc4 = RC4::Create(encKey.data(), encKey.size());
                        if (!_rc4) {
                            return Err(Errors::CREATE_RC4_(), CPL_FILE_AND_LINE);
                        }
                        auto rc4 = _rc4.value();
                        size_t size{};
                        encrypted.resize(inSize); {
                            const auto r = rc4.Encrypt(encrypted.data(), size, inBuffer, inSize);
                            if (!r) {
                                return r;
                            }
                        }
                        encrypted.resize(size);
                    }
                    // calc signE
                    {
                        auto h = SHA256_HMAC(signKey.data(), signKey.size());
                        size_t size{SHA256::SHA256_BYTES};
                        signE.resize(SHA256::SHA256_BYTES); {
                            const auto r = h.Update(signL.data(), signL.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = h.Update(nonce.data(), nonce.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = h.Update(length.data(), length.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = h.Update(encrypted.data(), encrypted.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = h.Summary(signE.data(), size);
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        }
                        if (size != SHA256::SHA256_BYTES) {
                            return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), "Unexpected HMAC output size"));
                        }
                        // Truncate to the on-wire signature length (matches Decrypt).
                        signE.resize(SIGN_E_BYTES_LENGTH);
                    }
                    // output
                    {
                        auto p = static_cast<uint8_t *>(outBuffer);
                        size_t idx{};
                        for (const auto b: signE) {
                            p[idx] = b;
                            idx += 1;
                        }
                        for (const auto b: signL) {
                            p[idx] = b;
                            idx += 1;
                        }
                        for (const auto b: nonce) {
                            p[idx] = b;
                            idx += 1;
                        }
                        for (const auto b: length) {
                            p[idx] = b;
                            idx += 1;
                        }
                        for (const auto b: encrypted) {
                            p[idx] = b;
                            idx += 1;
                        }
                        outSize = idx;
                    }
                    return {};
                }

                // Stream Encrypt(const Stream &in) {
                //     Stream out{};
                //     size_t s{};
                //     out.resize(
                //         (in.size() + NONCE_BYTES_LENGTH + SIGN_L_BYTES_LENGTH + SIGN_E_BYTES_LENGTH + 8) * 2);
                //     Encrypt(out.data(), s, in.data(), in.size());
                //     out.resize(s);
                //     return out;
                // }

                Int32Result Decrypt(
                    _Out_ void *outBuffer, _Out_ size_t &outSize,
                    _In_ const void *inBuffer, const _In_ size_t inSize) override {
                    // 1. Validate arguments
                    if (nullptr == inBuffer || nullptr == outBuffer) {
                        return cpl::Err(cpl::Error(cpl::Error::NullPointer(), CPL_FILE_AND_LINE));
                    }

                    // Check minimum input size
                    constexpr size_t minInputSize = SIGN_E_BYTES_LENGTH + SIGN_L_BYTES_LENGTH +
                                                    NONCE_BYTES_LENGTH;
                    if (inSize < minInputSize) {
                        return cpl::Err(cpl::Error(cpl::Error::InvalidArgument(), "Input data too short"));
                    }

                    // 2. Split input fields
                    const auto *p = static_cast<const uint8_t *>(inBuffer);
                    size_t idx = 0;

                    // Extract signE
                    Stream signE(p + idx, p + idx + SIGN_E_BYTES_LENGTH);
                    idx += SIGN_E_BYTES_LENGTH;

                    // Extract signL
                    Stream signL(p + idx, p + idx + SIGN_L_BYTES_LENGTH);
                    idx += SIGN_L_BYTES_LENGTH;

                    // Extract nonce
                    Stream nonce(p + idx, p + idx + NONCE_BYTES_LENGTH);
                    idx += NONCE_BYTES_LENGTH;

                    // 3. Decode length
                    Stream length;
                    uint64_t decodedLen{};
                    size_t nBytes{};
                    const auto r00 = cpl::codec::Length::Decode(Stream(p + idx, p + idx + inSize - idx));
                    if (!r00) {
                        return cpl::Err(cpl::Error(crypto::Errors::LENGTH_ENCODE_(), CPL_FILE_AND_LINE));
                    }
                    decodedLen = static_cast<uint64_t>(std::get<0>(r00.value()));
                    nBytes = std::get<1>(r00.value());
                    if (idx + nBytes > inSize) {
                        return cpl::Err(cpl::Error(cpl::Error::InvalidArgument(), "Invalid length encoding"));
                    }
                    length.assign(p + idx, p + idx + nBytes);
                    idx += nBytes;

                    // Validate decoded size
                    if (decodedLen > inSize) {
                        return cpl::Err(cpl::Error(cpl::Error::InvalidArgument(), "Invalid data size"));
                    }

                    // 4. Validate output buffer size
                    if (outSize < decodedLen) {
                        outSize = static_cast<size_t>(decodedLen);
                        return cpl::Err(cpl::Error(cpl::Error::OutOfRange(), "Output buffer too small"));
                    }

                    // Extract encrypted payload
                    size_t encryptedSize = inSize - idx;
                    Stream encrypted(p + idx, p + idx + encryptedSize);

                    // 5. Derive keys
                    Stream encKey{};
                    Stream signKey{}; {
                        size_t size = SHA256::SHA256_BYTES;
                        encKey.resize(size);
                        signKey.resize(size);
                        const auto r01 = cpl::crypto::impl::hmac256(
                            encKey.data(), size,
                            nonce.data(), nonce.size(),
                            key.data(), key.size());
                        if (!r01) {
                            return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                        }
                        encKey.resize(size);
                        size = SHA256::SHA256_BYTES;
                        const auto r02 = cpl::crypto::impl::hmac256(
                            signKey.data(), size,
                            key.data(), key.size(),
                            nonce.data(), nonce.size()
                        );
                        if (!r02) {
                            return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                        }
                        signKey.resize(size);
                    }

                    // 6. Verify signL (HMAC of nonce + length)
                    {
                        auto instance = SHA256_HMAC(signKey.data(), signKey.size());
                        size_t size{SHA256::SHA256_BYTES};
                        Stream computedSignL;
                        computedSignL.resize(size); {
                            const auto r = instance.Update(nonce.data(), nonce.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = instance.Update(length.data(), length.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = instance.Summary(computedSignL.data(), size);
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        }
                        if (size != SHA256::SHA256_BYTES) {
                            return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), "Unexpected HMAC output size"));
                        }
                        computedSignL.resize(SIGN_L_BYTES_LENGTH);

                        // Compare signatures
                        if (computedSignL != signL) {
                            return cpl::Err(cpl::Error(cpl::Error::InvalidArgument(),
                                                       "Signature verification failed (signL)"));
                        }
                    }

                    // 7. Verify signE (HMAC of signL + nonce + length + encrypted)
                    {
                        auto h = SHA256_HMAC(signKey.data(), signKey.size());
                        size_t size{SHA256::SHA256_BYTES};
                        Stream computedSignE;
                        computedSignE.resize(SHA256::SHA256_BYTES); {
                            const auto r = h.Update(signL.data(), signL.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = h.Update(nonce.data(), nonce.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = h.Update(length.data(), length.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = h.Update(encrypted.data(), encrypted.size());
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        } {
                            const auto r = h.Summary(computedSignE.data(), size);
                            if (!r) {
                                return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                            }
                        }
                        if (size != SHA256::SHA256_BYTES) {
                            return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), "Unexpected HMAC output size"));
                        }
                        computedSignE.resize(SIGN_E_BYTES_LENGTH);

                        // Compare signatures
                        if (computedSignE != signE) {
                            return cpl::Err(cpl::Error(cpl::Error::InvalidArgument(),
                                                       "Signature verification failed (signE)"));
                        }
                    }

                    // 8. Decrypt payload
                    {
                        auto _rc4 = RC4::Create(encKey.data(), encKey.size());
                        if (!_rc4) {
                            return Err(Errors::CREATE_RC4_(), CPL_FILE_AND_LINE);
                        }
                        auto rc4 = _rc4.value();
                        size_t decryptedSize{};
                        const auto r = rc4.Decrypt(outBuffer, decryptedSize, encrypted.data(), encrypted.size());
                        if (!r) {
                            return r;
                        }
                    }

                    outSize = static_cast<size_t>(decodedLen);
                    return {};
                }
            };
        }

        namespace stl {
            class IRandom {
            public:
                virtual ~IRandom() = default;

                virtual Result<Stream> Rand(_In_ size_t size) = 0;

                virtual cpl::crypto::IRandom *GetInnerRandomProvider() = 0;
            };

            class IHash {
            public:
                virtual ~IHash() = default;

                virtual Int32Result Update(_In_ const Stream &buffer) = 0;

                virtual Result<Stream> Summary() = 0;
            };

            class ISync {
            public:
                virtual ~ISync() = default;

                virtual Result<Stream> Encrypt(_In_ const Stream &buffer) = 0;

                virtual Result<Stream> Decrypt(_In_ const Stream &buffer) = 0;
            };

            class IAsync : public ISync {
            public:
                ~IAsync() override = default;

                virtual Result<Stream> Sign(_In_ const Stream &buffer) = 0;

                virtual Result<bool> Verify(
                    _In_ const Stream &buffer,
                    _In_ const Stream &expected
                ) = 0;
            };

            namespace impl {
                static cpl::Result<Stream> sha256(const Stream &data) {
                    Stream buffer{};
                    size_t size = 32;
                    buffer.resize(size);
                    const auto r00 = crypto::impl::sha256(buffer.data(), size, data.data(), data.size());
                    if (!r00 || size != 32) {
                        return cpl::Err(cpl::Error(crypto::Errors::SHA256_(), CPL_FILE_AND_LINE));
                    }
                    buffer.resize(size);
                    return buffer;
                }

                static cpl::Result<Stream> hmac256(const Stream &key, const Stream &data) {
                    Stream buffer{};
                    size_t size = 32;
                    buffer.resize(size);
                    const auto r00 = crypto::impl::hmac256(buffer.data(), size, key.data(), key.size(), data.data(),
                                                           data.size());
                    if (!r00 || size != 32) {
                        return cpl::Err(cpl::Error(crypto::Errors::HMAC256_(), CPL_FILE_AND_LINE));
                    }
                    buffer.resize(size);
                    return buffer;
                }

                class STLRandomWrapper final : public cpl::crypto::stl::IRandom {
                    cpl::crypto::IRandom *randomProvider = nullptr;

                public:
                    explicit STLRandomWrapper(cpl::crypto::IRandom *randomProvider) : randomProvider(randomProvider) {
                        if (nullptr == this->randomProvider) {
                            this->randomProvider = &cpl::crypto::impl::GetUnsafeRandomProvider();
                        }
                    }

                    ~STLRandomWrapper() override = default;

                    Result<Stream> Rand(size_t size) override {
                        Stream buffer{};
                        buffer.resize(size); {
                            auto *provider = &cpl::crypto::impl::GetUnsafeRandomProvider();
                            const auto r = provider->Rand(buffer.data(), size).transform_error([](const cpl::Error &e) {
                                // e.Reason += CPL_FILE_AND_LINE;
                                return cpl::Error{
                                    e.Code,
                                    (e.Reason + CPL_FILE_AND_LINE).c_str()
                                };
                            });

                            if (!r) {
                                return Result<Stream>(r);
                            }
                        }
                        return buffer;
                    }

                    cpl::crypto::IRandom *GetInnerRandomProvider() override {
                        return this->randomProvider;
                    }
                };

                class Crypto_RC4_HMAC256 final : public cpl::crypto::stl::ISync {
                    std::unique_ptr<cpl::crypto::impl::Crypto_RC4_HMAC256> crypto{};

                public:
                    explicit Crypto_RC4_HMAC256(const Stream &key, cpl::crypto::IRandom *randomProvider = nullptr) {
                        this->crypto.reset(new cpl::crypto::impl::Crypto_RC4_HMAC256(key, randomProvider));
                    }

                    ~Crypto_RC4_HMAC256() override = default;

                    Result<Stream> Encrypt(const Stream &in) override {
                        Stream buffer{};
                        buffer.resize(
                            in.size()
                            + cpl::crypto::impl::Crypto_RC4_HMAC256::NONCE_BYTES_LENGTH
                            + cpl::crypto::impl::Crypto_RC4_HMAC256::SIGN_L_BYTES_LENGTH
                            + cpl::crypto::impl::Crypto_RC4_HMAC256::SIGN_E_BYTES_LENGTH + 8
                        );
                        size_t outSize{}; {
                            const auto r = crypto->Encrypt(buffer.data(), outSize, in.data(), in.size()).
                                    transform_error([](const cpl::Error &e) {
                                        return cpl::Error{
                                            e.Code,
                                            (e.Reason + CPL_FILE_AND_LINE).c_str()
                                        };
                                    });
                            if (!r) {
                                return Result<Stream>(r);
                            }
                        }
                        buffer.resize(outSize);
                        return buffer;
                    }

                    Result<Stream> Decrypt(const Stream &in) override {
                        Stream buffer{};
                        buffer.resize(in.size());
                        size_t outSize = buffer.size(); {
                            const auto r = crypto->Decrypt(buffer.data(), outSize, in.data(), in.size()).
                                    transform_error([](const cpl::Error &e) {
                                        return cpl::Error{
                                            e.Code,
                                            (e.Reason + CPL_FILE_AND_LINE).c_str()
                                        };
                                    });
                            if (!r) {
                                return Result<Stream>(r);
                            }
                        }
                        buffer.resize(outSize);
                        return buffer;
                    }
                };
            }
        }
    }
}

#endif // CPL_CRYPTO_PURPLE_HORIZON_STARRY_FORTUNE_JOURNEY_BRAVE_MIRROR_LANDSCAPE
