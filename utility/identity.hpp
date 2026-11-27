// utility/identity.hpp - identity encoding (base32x), ObjectId generation and the machine seed.
//
// base32x: the alphabet is 0-9A-Z without the four easily confused characters I L O V (exactly
// 32 symbols); the removed ILOV characters in turn act as padding markers (they are not in the
// alphabet, so decoding is unambiguous):
//   I=pad 1 bit, L=pad 2 bit, O=pad 3 bit, V=pad 4 bit
// Bit for bit compatible with the Python/Go reference implementations:
//   - Encode      encodes from left to right (high bits aligned); a tail shorter than 5 bits ends
//                 with padding, and Decode restores the input completely;
//   - EncodeForId encodes from right to left (low bits aligned); the gap falls on the padding at
//                 the left, which gives a stable encoding for fixed-length IDs (12-byte ObjectId
//                 -> 20 characters); its output cannot be decoded by Decode
//                 (Decode only recognizes padding on the right).
//
// ObjectId: 12 bytes
//   | 0  1  2  3 | 4  5  6  | 7  8  | 9 10 11 |
//   |  TIMESTAMP |  MACHINE |  PID  | COUNTER |
//   - TIMESTAMP: Unix seconds, big endian;
//   - MACHINE  : first 3 bytes of the SHA256 of the sorted MAC list (comma-joined); the reference
//                implementations do not agree on the source or the hash of the fingerprint
//                (Go: MD5(MACs), Python: MD5(hostname)), so these 3 bytes are only a host
//                fingerprint that stays stable on the same machine; byte for byte equality with
//                the implementations in other languages is not promised;
//                without a MAC it degrades to SHA256(host name)[:3], and to random when that
//                fails as well;
//   - PID      : big endian; when the PID is 1 (the init process of a container) a random value
//                is used instead, as in the reference implementations;
//   - COUNTER  : process-wide monotonically increasing counter seeded from system randomness,
//                big endian 3 bytes (& 0xffffff).
//
// Machine seed (the identity of the terminal, 32 bytes):
//   | MACHINE ID (16 bytes) | HOST NAME (16 bytes) |
//   - Linux   : the machine id is read from /etc/machine-id, then /var/lib/dbus/machine-id,
//               then /sys/class/dmi/id/product_uuid (the first one that is readable and not
//               blank); it is copied as text bytes with the whitespace removed, never decoded
//               as hex, exactly like the old Go client;
//   - host name: the first 16 bytes, zero padded;
//   - Windows : the same derivation as the Windows client (system GUID ++ hardware UUID).
//
// Dependencies: includes the top-level base.hpp directly (Error/Result); randomness goes through
// naion (CryptGenRandom / getrandom), SHA256 through crypto; iphlpapi is loaded dynamically,
// following the project convention, so that no static link dependency is added. On Windows the
// registry functions of advapi32 are called directly, as the Windows client does.

#ifndef CPL_IDENTITY_HPP_ORCHESTRA_MEADOW_FURNITURE_TUNNEL_CIRCLE_POETRY
#define CPL_IDENTITY_HPP_ORCHESTRA_MEADOW_FURNITURE_TUNNEL_CIRCLE_POETRY

#include "../base.hpp" // the single authoritative base header
#include "../crypto.hpp" // cpl::crypto::impl::sha256 (host fingerprint)
#include "../naion.hpp" // cpl::naion::RandomBytesBuf (system randomness)

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#include <iphlpapi.h>
// The machine seed reads the registry through advapi32, the same import library the
// Windows client links.
#if defined(_MSC_VER)
#pragma comment(lib, "advapi32.lib")
#endif
#else
#include <unistd.h>
#if defined(__linux__)
#include <ifaddrs.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#endif
#endif

using namespace std;

namespace cpl {
    namespace identity {
        class Errors final {
        public:
            // C++11 note: ODR-safe via scoped enum (see Error::NullPointer note).
            enum : int64_t {
                base = static_cast<int64_t>(5) << 32,
                Base32xInvalidCharacter = base | 1, // decoding met a character outside the alphabet/padding set
                Base32xPaddingMismatch = base | 2, // bit length is not a multiple of 8 after removing the padding
            };
        };

        /**
         * base32x encoding and decoding. See the file header for the alphabet and the padding semantics.
         */
        class Base32x final {
        public:
            // Encoding table: '0'-'9' 'A'-'Z' without I L O V (32 characters)
            static const char *EncodeTable() {
                static const char kTable[] = "0123456789ABCDEFGHJKMNPQRSTUWXYZ";
                return kTable;
            }

            // Padding table: index + 1 = the number of padding bits the marker stands for
            static const char *PaddingTable() {
                static const char kTable[] = "ILOV";
                return kTable;
            }

            /**
             * Encodes from left to right (high bits aligned). With withPadding a padding marker is appended to the tail.
             * The output is restored completely by Decode.
             */
            static Result<string> Encode(
                _In_ const void *in,
                _In_ const size_t size,
                _In_ const bool withPadding = true
            ) {
                if (nullptr == in) {
                    return Err(Error(Error::NullPointer, "[X] Base32x::Encode null input" CPL_FILE_AND_LINE));
                }
                if (0 == size) {
                    return Err(Error(Error::NoData, "[X] Base32x::Encode empty input" CPL_FILE_AND_LINE));
                }
                const auto *pin = static_cast<const uint8_t *>(in);
                const size_t inBitLen = size * 8;
                Stream buf{};
                buf.reserve(size + 1);
                buf.assign(pin, pin + size);
                size_t toEncodeBitLen = inBitLen;
                char padding = '\0';
                if (0 != inBitLen % 5) {
                    toEncodeBitLen = (inBitLen / 5 + 1) * 5;
                    // Append one 0 byte to the tail so that a 5-bit window crossing a byte boundary can be read
                    buf.push_back(0);
                    padding = PaddingTable()[toEncodeBitLen - inBitLen - 1];
                }
                string out{};
                out.reserve(toEncodeBitLen / 5 + 1);
                for (size_t j = 0; j < toEncodeBitLen; j += 5) {
                    const size_t k = j + 4;
                    const size_t idx0 = j / 8;
                    const size_t idx1 = k / 8;
                    uint8_t idx = 0;
                    if (idx0 == idx1) {
                        idx = static_cast<uint8_t>((buf[idx0] >> (7 - k % 8)) & 0x1f);
                    } else {
                        // A 5-bit window crosses at most two adjacent bytes
                        idx = static_cast<uint8_t>(
                            ((buf[idx0] << (5 - (8 - j % 8))) | ((buf[idx1] >> (7 - k % 8)) & 0x1f)) & 0x1f);
                    }
                    out.push_back(EncodeTable()[idx]);
                }
                if (withPadding && '\0' != padding) {
                    out.push_back(padding);
                }
                Ok(out)
            }

            static Result<string> Encode(_In_ const Stream &in, _In_ const bool withPadding = true) {
                return Encode(in.data(), in.size(), withPadding);
            }

            /**
             * Encodes from right to left (low bits aligned). With withPadding a padding marker is inserted at the head.
             * Used for ID encoding: the low-bit alignment makes the output of a fixed-length ID equally
             * long and places the low bytes at the end of the encoding; when zero bytes are added at
             * the high end (the low nibble is 0) the output keeps its common suffix.
             * Note that the output cannot be decoded by Decode (Decode only recognizes padding on the right).
             */
            static Result<string> EncodeForId(
                _In_ const void *in,
                _In_ const size_t size,
                _In_ const bool withPadding = false
            ) {
                if (nullptr == in) {
                    return Err(Error(Error::NullPointer, "[X] Base32x::EncodeForId null input" CPL_FILE_AND_LINE));
                }
                if (0 == size) {
                    return Err(Error(Error::NoData, "[X] Base32x::EncodeForId empty input" CPL_FILE_AND_LINE));
                }
                const auto *pin = static_cast<const uint8_t *>(in);
                const size_t inBitLen = size * 8;
                Stream buf{};
                size_t toEncodeBitLen = 0;
                size_t charCount = 0;
                char padding = '\0';
                if (0 == inBitLen % 5) {
                    toEncodeBitLen = inBitLen;
                    charCount = inBitLen / 5;
                    buf.assign(pin, pin + size);
                } else {
                    // Add one 0 byte at the head, take the 5-bit windows from right to left, and leave the gap at the high bits
                    charCount = inBitLen / 5 + 1;
                    toEncodeBitLen = inBitLen + 8;
                    buf.reserve(size + 1);
                    buf.push_back(0);
                    buf.insert(buf.end(), pin, pin + size);
                    padding = PaddingTable()[charCount * 5 - inBitLen - 1];
                }
                const size_t paddingLen = (withPadding && '\0' != padding) ? 1 : 0;
                string out{};
                out.assign(charCount + paddingLen, '\0');
                for (size_t i = 0; i < charCount; i++) {
                    const size_t k = toEncodeBitLen - 1 - i * 5;
                    const size_t j = k - 4;
                    const size_t idx0 = j / 8;
                    const size_t idx1 = k / 8;
                    uint8_t idx = 0;
                    if (idx0 == idx1) {
                        idx = static_cast<uint8_t>((buf[idx0] >> (7 - k % 8)) & 0x1f);
                    } else {
                        idx = static_cast<uint8_t>(
                            ((buf[idx0] << (5 - (8 - j % 8))) | ((buf[idx1] >> (7 - k % 8)) & 0x1f)) & 0x1f);
                    }
                    // i=0 is the lowest 5 bits, written to the rightmost position of the output
                    out[paddingLen + charCount - 1 - i] = EncodeTable()[idx];
                }
                if (0 != paddingLen) {
                    out[0] = padding; // padding marker at the head
                }
                Ok(out)
            }

            static Result<string> EncodeForId(_In_ const Stream &in, _In_ const bool withPadding = false) {
                return EncodeForId(in.data(), in.size(), withPadding);
            }

            /**
             * Decodes the output of Encode (including the padding marker on the right).
             */
            static Result<Stream> Decode(_In_ const char *in) {
                if (nullptr == in) {
                    return Err(Error(Error::NullPointer, "[X] Base32x::Decode null input" CPL_FILE_AND_LINE));
                }
                const size_t n = strlen(in);
                if (0 == n) {
                    return Err(Error(Error::NoData, "[X] Base32x::Decode empty input" CPL_FILE_AND_LINE));
                }
                // Strip the last character when it is a padding marker (the alphabet does not contain ILOV, so this is unambiguous)
                size_t dataLen = n;
                size_t paddingBitLen = 0;
                const char last = in[n - 1];
                for (size_t p = 0; p < 4; p++) {
                    if (last == PaddingTable()[p]) {
                        paddingBitLen = p + 1;
                        dataLen = n - 1;
                        break;
                    }
                }
                if (0 == dataLen) {
                    return Err(Error(Errors::Base32xPaddingMismatch,
                                     "[X] Base32x::Decode padding only" CPL_FILE_AND_LINE));
                }
                const size_t outBitLen = dataLen * 5 - paddingBitLen;
                if (0 != outBitLen % 8) {
                    return Err(Error(Errors::Base32xPaddingMismatch,
                                     "[X] Base32x::Decode length mismatch" CPL_FILE_AND_LINE));
                }
                const auto &table = GetDecodeTable();
                // Allocate one extra slot for a write that crosses a byte boundary and trim it at the end (same as the reference implementations)
                Stream out(outBitLen / 8 + 1, 0);
                for (size_t e = 0; e < dataLen; e++) {
                    const auto c = static_cast<uint8_t>(in[e]);
                    const auto d = (c < 128) ? table.v[c] : static_cast<int8_t>(-1);
                    if (d < 0) {
                        return Err(Error(Errors::Base32xInvalidCharacter,
                                         "[X] Base32x::Decode invalid character" CPL_FILE_AND_LINE));
                    }
                    const size_t bitIdx = e * 5;
                    const size_t idx0 = bitIdx / 8;
                    const size_t idx1 = (bitIdx + 4) / 8;
                    if (idx0 == idx1) {
                        out[idx0] = static_cast<uint8_t>(out[idx0] | (d << (7 - (bitIdx + 4) % 8)));
                    } else {
                        out[idx0] = static_cast<uint8_t>(out[idx0] | (d >> (5 - (8 - bitIdx % 8))));
                        out[idx1] = static_cast<uint8_t>(out[idx1] | ((d << (7 - (bitIdx + 4) % 8)) & 0xff));
                    }
                }
                out.resize(outBitLen / 8);
                Ok(out)
            }

            static Result<Stream> Decode(_In_ const string &in) {
                return Decode(in.c_str());
            }

        private:
            struct DecodeTableT {
                int8_t v[128];

                DecodeTableT() {
                    memset(v, -1, sizeof(v));
                    // Note: the counter must not be an int8_t: 31+1 wraps around to a negative number and loops forever
                    for (int i = 0; i < 32; i++) {
                        v[static_cast<uint8_t>(EncodeTable()[i])] = static_cast<int8_t>(i);
                    }
                }
            };

            static const DecodeTableT &GetDecodeTable() {
                static DecodeTableT table{};
                return table;
            }
        };

        namespace impl {
            // MAC string format identical to Go net.HardwareAddr.String(): lowercase hex separated by colons
            inline string FormatMac(_In_ const uint8_t *addr, _In_ const size_t len) {
                static const char kHex[] = "0123456789abcdef";
                string mac{};
                mac.reserve(len * 3);
                for (size_t i = 0; i < len; i++) {
                    if (!mac.empty()) {
                        mac.push_back(':');
                    }
                    mac.push_back(kHex[(addr[i] >> 4) & 0xf]);
                    mac.push_back(kHex[addr[i] & 0xf]);
                }
                return mac;
            }

#ifdef _WIN32
            // iphlpapi is loaded dynamically, following the project convention (no new static link dependency); the module stays loaded until the process exits
            inline vector<string> CollectMacAddresses() {
                vector<string> macs{};
                const HMODULE module = LoadLibraryA("iphlpapi.dll");
                if (nullptr == module) {
                    return macs;
                }
                using GetAdaptersInfoFunc = ULONG (WINAPI *)(PIP_ADAPTER_INFO, PULONG);
                const auto getAdaptersInfo = reinterpret_cast<GetAdaptersInfoFunc>(
                    GetProcAddress(module, "GetAdaptersInfo"));
                if (nullptr == getAdaptersInfo) {
                    return macs;
                }
                ULONG size = 0;
                if (ERROR_BUFFER_OVERFLOW != getAdaptersInfo(nullptr, &size) || 0 == size) {
                    return macs;
                }
                vector<uint8_t> buffer(size, 0);
                auto *info = reinterpret_cast<PIP_ADAPTER_INFO>(buffer.data());
                if (NO_ERROR != getAdaptersInfo(info, &size)) {
                    return macs;
                }
                for (auto *adapter = info; nullptr != adapter; adapter = adapter->Next) {
                    if (0 == adapter->AddressLength) {
                        continue;
                    }
                    macs.push_back(FormatMac(adapter->Address, adapter->AddressLength));
                }
                return macs;
            }

            inline bool GetHostname(_Out_ string &host) {
                char buffer[256]{};
                DWORD size = sizeof(buffer);
                if (0 == GetComputerNameA(buffer, &size)) {
                    return false;
                }
                host.assign(buffer, size);
                return true;
            }

            // Byte for byte mirror of cpl::sys::utility::GetSystemGUID() (win32/utility.hpp), the
            // first input of the key derivation of the Windows client: the 16-byte machine GUID
            // from the registry (HKLM\Software\Microsoft\Cryptography\MachineGuid).
            // The two must stay identical, otherwise this seed differs from the seed of the
            // Windows client.
            inline Result<Stream> GetSystemGUID() {
                HKEY hKey = nullptr;
                if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Cryptography", 0,
                                  KEY_READ | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
                    return Err(Error(Error::UnavailableAPI, "[X] RegOpenKeyExA failed" CPL_FILE_AND_LINE));
                }
                const auto closeKey = cpl::base::MakeDefer([&]() {
                        if (hKey != nullptr) { RegCloseKey(hKey); }
                    });
                char value[64] = {};
                DWORD valueSize = sizeof(value);
                DWORD type = 0;
                if (RegQueryValueExA(hKey, "MachineGuid", nullptr, &type,
                                     reinterpret_cast<LPBYTE>(value), &valueSize) != ERROR_SUCCESS) {
                    return Err(Error(Error::UnavailableAPI, "[X] RegQueryValueExA failed" CPL_FILE_AND_LINE));
                }
                // The GUID is a 36-character string "xxxxxxxx-xxxx-..."; fold it to 16 bytes.
                // The last byte of the value (the NUL terminator) is dropped, as in the original.
                const string guid(value, valueSize ? valueSize - 1 : 0);
                Stream out(16, 0);
                // The original removes the dashes with strings::ReplaceAll; skipping them here
                // gives the same text and keeps this header independent of strings.hpp.
                string hex{};
                for (const char c : guid) {
                    if (c != '-') {
                        hex.push_back(c);
                    }
                }
                for (size_t i = 0; i < 16 && i * 2 + 1 < hex.size(); ++i) {
                    const auto hi = hex[i * 2];
                    const auto lo = hex[i * 2 + 1];
                    auto hexVal = [](const char c) -> int {
                        if (c >= '0' && c <= '9') { return c - '0'; }
                        if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
                        if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
                        return 0;
                    };
                    out[i] = static_cast<uint8_t>((hexVal(hi) << 4) | hexVal(lo));
                }
                return out;
            }

            // Byte for byte mirror of cpl::sys::utility::GetHardwareUUID() (win32/utility.hpp),
            // the second input of the key derivation of the Windows client: a 16-byte hardware
            // UUID derived from the serial number of the system volume.
            inline Result<Stream> GetHardwareUUID() {
                char sysDir[MAX_PATH] = {};
                if (GetSystemDirectoryA(sysDir, static_cast<UINT>(sizeof(sysDir))) == 0) {
                    return Err(Error(Error::UnavailableAPI, "[X] GetSystemDirectoryA failed" CPL_FILE_AND_LINE));
                }
                // The drive letter is the first 2 chars ("C:").
                char root[] = {sysDir[0], ':', '\\', 0};
                DWORD serial = 0;
                if (!GetVolumeInformationA(root, nullptr, 0, &serial, nullptr, nullptr, nullptr, 0)) {
                    return Err(Error(Error::UnavailableAPI, "[X] GetVolumeInformationA failed" CPL_FILE_AND_LINE));
                }
                Stream out(16, 0);
                // Spread the 32-bit serial across 16 bytes deterministically.
                for (size_t i = 0; i < 16; ++i) {
                    out[i] = static_cast<uint8_t>((serial >> ((i % 4) * 8)) ^ (i * 0x5Bu));
                }
                return out;
            }

            // The Windows client substitutes 16 zero bytes for an identifier it cannot read.
            inline Stream BytesOrZeros(_In_ const Result<Stream> &r) {
                if (!r) {
                    return Stream(16, 0);
                }
                return r.value();
            }
#else
#if defined(__linux__)
            inline vector<string> CollectMacAddresses() {
                vector<string> macs{};
                struct ifaddrs *interfaces = nullptr;
                if (0 != getifaddrs(&interfaces)) {
                    return macs;
                }
                for (auto *ifa = interfaces; nullptr != ifa; ifa = ifa->ifa_next) {
                    if (nullptr == ifa->ifa_addr || AF_PACKET != ifa->ifa_addr->sa_family) {
                        continue;
                    }
                    const auto *sa = reinterpret_cast<const struct sockaddr_ll *>(ifa->ifa_addr);
                    // sll_addr is an array inside the structure, so its address is never null.
                    if (0 == sa->sll_halen) {
                        continue;
                    }
                    macs.push_back(FormatMac(sa->sll_addr, sa->sll_halen));
                }
                freeifaddrs(interfaces);
                return macs;
            }
#else
            inline vector<string> CollectMacAddresses() {
                return vector<string>{};
            }
#endif

            inline bool GetHostname(_Out_ string &host) {
                char buffer[256]{};
                if (0 != gethostname(buffer, sizeof(buffer))) {
                    return false;
                }
                host.assign(buffer);
                return true;
            }
#endif

            // Removes every whitespace character (space, tab, newline, carriage return, ...).
            inline string StripWhitespace(_In_ const string &in) {
                string out{};
                out.reserve(in.size());
                for (const char c : in) {
                    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f') {
                        continue;
                    }
                    out.push_back(c);
                }
                return out;
            }

#if !defined(_WIN32)
            // The machine id sources of Linux, in the order they are tried.
            const char *const kMachineIdSources[] = {
                "/etc/machine-id",
                "/var/lib/dbus/machine-id",
            };

            // Last resort when neither machine-id file is usable: the product UUID of the SMBIOS
            // table (readable by root only).
            const char *const kProductUuidSource = "/sys/class/dmi/id/product_uuid";

            // Upper bound of what is read from one source; the largest of them holds 36 characters.
            const size_t kMaxMachineIdBytes = 4096;

            // Reads a text file into `out`. Returns false when the file cannot be opened or holds
            // nothing but whitespace: an empty machine id would make half of the seed all zero,
            // so it counts as missing and the next source is tried.
            inline bool ReadMachineIdSource(_In_ const char *path, _Out_ string &out) {
                FILE *fp = std::fopen(path, "rb");
                if (fp == nullptr) {
                    return false;
                }
                // RAII: the file is closed on every exit path, including an exception thrown by
                // the string allocation below.
                const auto closeFile = cpl::base::MakeDefer([&]() noexcept {
                    std::fclose(fp);
                    fp = nullptr;
                });
                out.clear();
                char buffer[256]{};
                for (;;) {
                    const size_t n = std::fread(buffer, 1, sizeof(buffer), fp);
                    if (n > 0) {
                        out.append(buffer, n);
                    }
                    // A short read means that nothing more is coming (end of file or an error).
                    // Reading until EOF also works for sysfs, whose files report a size of 0.
                    if (n < sizeof(buffer) || out.size() >= kMaxMachineIdBytes) {
                        break;
                    }
                }
                return !StripWhitespace(out).empty();
            }
#endif

            inline uint32_t CurrentPid() {
#ifdef _WIN32
                return static_cast<uint32_t>(GetCurrentProcessId());
#else
                return static_cast<uint32_t>(getpid());
#endif
            }

            inline bool RandomBytes(_Out_ void *buffer, _In_ const size_t size) {
                return cpl::naion::RandomBytesBuf(buffer, size).has_value();
            }

            // First 3 bytes of the SHA256 of in (host fingerprint); zeroed for empty input/on failure (theoretically unreachable)
            inline void Hash3(_Out_ uint8_t out[3], _In_ const string &in) {
                if (in.empty()) {
                    memset(out, 0, 3);
                    return;
                }
                uint8_t digest[cpl::crypto::impl::SHA256::SHA256_BYTES]{};
                size_t size = sizeof(digest);
                const auto r0 = cpl::crypto::impl::sha256(digest, size, in.data(), in.size());
                if (!r0) {
                    memset(out, 0, 3);
                    return;
                }
                out[0] = digest[0];
                out[1] = digest[1];
                out[2] = digest[2];
            }

            /**
             * Process-wide state: counter seed / host fingerprint / PID.
             * Initialized lazily on the first Generate() (Meyers singleton, thread-safe in C++11).
             */
            struct ObjectIdState {
                uint32_t counter{0};
                uint8_t machine[3]{};
                uint16_t pid{0};
                std::mutex lock{};

                ObjectIdState() {
                    // Counter seed: 4 bytes of system randomness (big endian); degrades to a time mix on failure
                    {
                        uint8_t seed[4]{};
                        if (RandomBytes(seed, sizeof(seed))) {
                            counter = (static_cast<uint32_t>(seed[0]) << 24)
                                    | (static_cast<uint32_t>(seed[1]) << 16)
                                    | (static_cast<uint32_t>(seed[2]) << 8)
                                    | static_cast<uint32_t>(seed[3]);
                        } else {
                            counter = static_cast<uint32_t>(time(nullptr)) ^ 0x9e3779b9u;
                        }
                    }
                    // Host fingerprint: MAC list (sorted, comma-joined) -> host name -> random
                    {
                        auto macs = CollectMacAddresses();
                        sort(macs.begin(), macs.end());
                        if (!macs.empty()) {
                            Hash3(machine, cpl::strings::Join(macs, ","));
                        } else {
                            string host{};
                            if (GetHostname(host) && !host.empty()) {
                                Hash3(machine, host);
                            } else {
                                RandomBytes(machine, sizeof(machine));
                            }
                        }
                    }
                    // PID: when it is 1 (the init process of a container) a random value is used instead, as in the reference implementations, to avoid collisions between containers on the same host
                    {
                        const uint32_t current = CurrentPid();
                        if (current > 1) {
                            pid = static_cast<uint16_t>(current & 0xffff);
                        } else {
                            uint8_t seed[2]{};
                            if (RandomBytes(seed, sizeof(seed))) {
                                pid = static_cast<uint16_t>((seed[0] << 8) | seed[1]);
                            } else {
                                pid = static_cast<uint16_t>(time(nullptr) & 0xffff);
                            }
                        }
                    }
                }
            };

            inline ObjectIdState &State() {
                static ObjectIdState instance{};
                return instance;
            }
        }

        /**
         * 12-byte ObjectId generator (layout in the file header comment), thread safe.
         */
        class ObjectId final {
        public:
            static constexpr size_t SIZE = 12;

            static Result<Stream> Generate() {
                Stream oid(SIZE, 0);
                const uint32_t timestamp = static_cast<uint32_t>(time(nullptr));
                oid[0] = static_cast<uint8_t>(timestamp >> 24);
                oid[1] = static_cast<uint8_t>(timestamp >> 16);
                oid[2] = static_cast<uint8_t>(timestamp >> 8);
                oid[3] = static_cast<uint8_t>(timestamp);
                auto &state = impl::State();
                oid[4] = state.machine[0];
                oid[5] = state.machine[1];
                oid[6] = state.machine[2];
                oid[7] = static_cast<uint8_t>(state.pid >> 8);
                oid[8] = static_cast<uint8_t>(state.pid);
                {
                    lock_guard<mutex> guard(state.lock);
                    state.counter = (state.counter + 1) & 0xffffffu;
                    oid[9] = static_cast<uint8_t>(state.counter >> 16);
                    oid[10] = static_cast<uint8_t>(state.counter >> 8);
                    oid[11] = static_cast<uint8_t>(state.counter);
                }
                Ok(oid)
            }

            /**
             * Convenience entry point: generates an id and encodes it right-aligned in base32x (12 bytes -> 20 characters, no padding).
             */
            static Result<string> GenerateEncoded() {
                const auto r0 = Generate();
                if (!r0) {
                    return Err(r0.error());
                }
                return Base32x::EncodeForId(r0.value());
            }
        };

        /**
         * Derives the terminal identity seed from stable machine facts with the inputs given by
         * the caller (pure function, used by the tests).
         * Linux layout: the first 16 bytes of the machine id (whitespace removed, zero padded),
         * followed by the first 16 bytes of the host name (zero padded).
         * The machine id is copied as bytes and never decoded as hex, so a machine id that is
         * not hex still gives a stable seed.
         */
        inline cpl::naion::ESD MachineSeedFrom(_In_ const std::string &machineId, _In_ const std::string &hostName) {
            cpl::naion::ESD seed{}; // value-initialized: the padding is zero
            const size_t half = seed.size() / 2;

            // Step 1: machine id. Drop the whitespace (the trailing newline of /etc/machine-id),
            // then copy from the left; a shorter id leaves the rest zero.
            const string id = impl::StripWhitespace(machineId);
            const size_t idBytes = id.size() < half ? id.size() : half;
            std::memcpy(seed.data(), id.data(), idBytes);

            // Step 2: host name. The first 16 bytes, copied from the left and zero padded.
            const size_t hostBytes = hostName.size() < half ? hostName.size() : half;
            std::memcpy(seed.data() + half, hostName.data(), hostBytes);
            return seed;
        }

        /**
         * Derives the terminal identity seed from stable machine facts.
         * Linux: the first 16 bytes of the machine id (whitespace removed, zero padded), followed by the
         * first 16 bytes of the host name. Windows: the same derivation as the Windows client.
         * Returns a Result so that a missing machine id can be reported.
         */
        inline Result<cpl::naion::ESD> MachineSeed() {
#if defined(_WIN32)
            // Same derivation as Globals::MakeSecretKey() of the Windows client
            // (ifw/client/windows/src/_global.hpp): system GUID ++ hardware UUID.
            cpl::naion::ESD seed{};
            // Step 1: the 16-byte system GUID, or 16 zero bytes when it cannot be read.
            const Stream guid = impl::BytesOrZeros(impl::GetSystemGUID());
            // Step 2: the 16-byte hardware UUID, or 16 zero bytes when it cannot be read.
            const Stream uuid = impl::BytesOrZeros(impl::GetHardwareUUID());
            // Step 3: GUID first, UUID second. Only the first 32 bytes are used should the two
            // ever be longer; a shorter input leaves the rest of the seed zero.
            Stream buffer(guid.begin(), guid.end());
            buffer.insert(buffer.end(), uuid.begin(), uuid.end());
            const size_t size = buffer.size() > seed.size() ? seed.size() : buffer.size();
            std::memmove(seed.data(), buffer.data(), size);
            return seed;
#else
            // Step 1: machine id. /etc/machine-id first, /var/lib/dbus/machine-id when it is missing.
            string machineId{};
            bool found = false;
            for (const char *const source : impl::kMachineIdSources) {
                found = impl::ReadMachineIdSource(source, machineId);
                if (found) {
                    break;
                }
            }
            // Step 2: fall back to the SMBIOS product UUID when neither machine-id file is usable.
            if (!found) {
                found = impl::ReadMachineIdSource(impl::kProductUuidSource, machineId);
            }
            // Step 3: nothing found. Report it instead of silently deriving an identity whose
            // first half is all zero.
            if (!found) {
                return cpl::MakeErr(cpl::Error::FileOpen,
                                    "[X] machine id not found: none of /etc/machine-id, "
                                    "/var/lib/dbus/machine-id, /sys/class/dmi/id/product_uuid is readable"
                                    CPL_FILE_AND_LINE);
            }
            // Step 4: host name. An unknown host name leaves the second half zero, as in the
            // old Go client.
            string hostName{};
            if (!impl::GetHostname(hostName)) {
                hostName.clear();
            }
            return MachineSeedFrom(machineId, hostName);
#endif
        }
    }
}

#endif //CPL_IDENTITY_HPP_ORCHESTRA_MEADOW_FURNITURE_TUNNEL_CIRCLE_POETRY
