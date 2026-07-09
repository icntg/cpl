#ifndef CPL_STRINGS_HPP_JUSTICE_TENSION_STRONGER_MOISTURE_BRIGHTLY_CULTURE_ENCHANTED_GALLERY
#define CPL_STRINGS_HPP_JUSTICE_TENSION_STRONGER_MOISTURE_BRIGHTLY_CULTURE_ENCHANTED_GALLERY

#include <cinttypes>
#include "base.hpp"
#include <string>
#include <vector>
#include <cstdarg>
#include <tuple>
#include <cstring>
#include <cwchar>
#include <cctype>

namespace cpl {
    namespace strings {
        class Errors final {
        public:
            static constexpr int64_t base = static_cast<int64_t>(1) << 32;
            static constexpr cpl::Error::CodeDef UnHexlifyStringLengthOdd = {base | 1};
            static constexpr cpl::Error::CodeDef DecodeLengthAsUTF8 = {base | 2};
            static constexpr cpl::Error::CodeDef StringFormat = {base | 3};
            static constexpr cpl::Error::CodeDef UTF16LEBytesToWStringLengthOdd = {base | 6};
        };

        // Forward declaration
        inline Result<std::string> Format(const char *tpl, ...);

        inline Result<std::wstring> Format(const wchar_t *tpl, ...);
    }

    namespace codec {
        // hexlify test pass
        class Hex final {
        public:
            static Result<std::string> Hexlify(_In_ const void *in, _In_ const size_t size) noexcept {
                if (!in || size == 0) {
                    return cpl::Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
                }
                std::string out{};
                const auto pin = static_cast<const uint8_t *>(in);
                for (size_t i = 0; i < size; i++) {
                    const auto ch = pin[i];
                    const auto ch1 = (ch >> 4u) & 0xf;
                    if (ch1 <= 9) {
                        out.push_back(static_cast<char>(ch1 + '0'));
                    } else if (ch1 <= 15) {
                        out.push_back(static_cast<char>(ch1 - 10 + 'A'));
                    } else {
                        return cpl::Err(cpl::Error(cpl::Error::OutOfRange, CPL_FILE_AND_LINE));
                    }
                    const unsigned char ch0 = ch & 0xf;
                    if (ch0 <= 9) {
                        out.push_back(static_cast<char>(ch0 + '0'));
                    } else if (ch0 <= 15) {
                        out.push_back(static_cast<char>(ch0 - 10 + 'A'));
                    } else {
                        return cpl::Err(cpl::Error(cpl::Error::OutOfRange, CPL_FILE_AND_LINE));
                    }
                }
                return out;
            }

            static Result<std::string> Hexlify(_In_ const Stream &in) {
                return Hexlify(in.data(), in.size());
            }

            static Result<Stream> UnHexlify(_In_ const char *in) {
                if (!in) {
                    return cpl::Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
                }
                const auto n = strlen(in);
                if (n % 2 != 0) {
                    return Err(cpl::Error(strings::Errors::UnHexlifyStringLengthOdd, CPL_FILE_AND_LINE));
                }
                const auto m = n / 2;
                Stream out{};
                out.reserve(m);
                for (size_t i = 0; i < m; i++) {
                    const char cs[]{in[i * 2], in[i * 2 + 1]};
                    uint8_t v{}, w{};
                    for (const auto c: cs) {
                        if ('0' <= c && c <= '9') {
                            w = c - '0';
                        } else if ('A' <= c && c <= 'F') {
                            w = c - 'A' + 10;
                        } else if ('a' <= c && c <= 'f') {
                            w = c - 'a' + 10;
                        } else {
                            return Err(cpl::Error(cpl::Error::InvalidArgument, "[X] UnHexlify invalid character" CPL_FILE_AND_LINE));
                        }
                        v = static_cast<uint8_t>((v << 4) | (w & 0xf));
                    }
                    out.push_back(v);
                }
                return out;
            }

            static Result<Stream> UnHexlify(_In_ const std::string &in) {
                return UnHexlify(in.data());
            }
        };

        // base64encode test pass
        class Base64 final {
        protected:
            // Function to check if a character is a valid base64 character
            static int32_t checkBase64Characters(_In_ const char *in) {
                const auto size = strlen(in);
                if (size == 0 || size % 4 != 0) {
                    return -1;
                }
                size_t right_idx = size;
                const auto ch_1 = in[size - 1];
                const auto ch_2 = in[size - 2];

                if (ch_1 == '=' && ch_2 == '=') {
                    right_idx = size - 2;
                } else if (ch_1 == '=') {
                    right_idx = size - 1;
                }
                for (size_t i = 0; i < right_idx; i++) {
                    const auto c = static_cast<unsigned char>(in[i]);
                    const auto r = isalnum(c) || (c == '+') || (c == '/');
                    if (!r) {
                        return static_cast<int32_t>(i) + 1;
                    }
                }
                return 0;
            }

            const std::string base64_chars =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                    "abcdefghijklmnopqrstuvwxyz"
                    "0123456789+/";


            std::string base64_reverse_table() const {
                std::string table{};
                for (size_t i = 0; i < 128; i++) {
                    table.push_back(-1);
                }
                for (size_t i = 0; i < this->base64_chars.size(); i++) {
                    const auto ch = static_cast<uint8_t>(this->base64_chars[i]); // convert to unsigned
                    if (ch < table.size()) {
                        // bounds check
                        table[ch] = static_cast<char>(i);
                    }
                }
                return table;
            }

        public:
            static Result<std::string> Base64Encode(_In_ const void *in, _In_ const size_t size) {
                if (!in || size == 0) {
                    return cpl::Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
                }
                static auto self = Base64();
                std::string out{};
                out.clear();
                int i = 0;
                int j = 0;
                uint8_t a3[3]{};
                uint8_t b4[4]{};
                const auto *input = static_cast<const uint8_t *>(in);

                const auto withPadding = size % 3 > 0;
                const auto blockCounter = size / 3;

                for (i = 0; i < blockCounter; i++) {
                    a3[0] = input[i * 3];
                    a3[1] = input[i * 3 + 1];
                    a3[2] = input[i * 3 + 2];

                    b4[0] = (a3[0] & 0xfc) >> 2;
                    b4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
                    b4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
                    b4[3] = a3[2] & 0x3f;

                    for (j = 0; j < 4; j++) {
                        out.push_back(self.base64_chars[b4[j]]);
                    }
                }
                if (withPadding) {
                    const auto base = blockCounter * 3;
                    const auto n = size % 3;
                    a3[0] = input[base];
                    a3[2] = 0;
                    if (n == 1) {
                        a3[1] = 0;
                        b4[0] = (a3[0] & 0xfc) >> 2;
                        out.push_back(self.base64_chars[b4[0]]);
                        b4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
                        out.push_back(self.base64_chars[b4[1]]);
                        out.push_back('=');
                        out.push_back('=');
                    } else if (n == 2) {
                        a3[1] = input[base + 1];
                        b4[0] = (a3[0] & 0xfc) >> 2;
                        out.push_back(self.base64_chars[b4[0]]);
                        b4[1] = ((a3[0] & 0x03) << 4) + ((a3[1] & 0xf0) >> 4);
                        out.push_back(self.base64_chars[b4[1]]);
                        b4[2] = ((a3[1] & 0x0f) << 2) + ((a3[2] & 0xc0) >> 6);
                        out.push_back(self.base64_chars[b4[2]]);
                        out.push_back('=');
                    }
                }
                return out;
            }

            static Result<Stream> Base64Decode(_In_ const char *in) {
                if (!in) {
                    return cpl::Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
                }
                auto in_len = strlen(in);
                const auto ir = checkBase64Characters(in);
                if (ir < 0) {
                    auto es = cpl::strings::Format(
                        "[X] Base64Decode length[%lu] error" CPL_FILE_AND_LINE,
                        static_cast<uint32_t>(in_len)
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Error::OutOfRange, es.value());
                }
                if (ir > 0) {
                    auto es = cpl::strings::Format(
                        "[X] Base64Decode character at [%lu] is error" CPL_FILE_AND_LINE,
                        static_cast<uint32_t>(ir - 1)
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Error::OutOfRange, es.value());
                }
                static auto self = Base64();
                static auto table = self.base64_reverse_table();

                int i = 0;
                int in_ = 0;
                unsigned char char_array_4[4]{}, char_array_3[3]{};
                Stream out{};
                out.clear();

                while (in_len-- && (in[in_] != '=')) {
                    char_array_4[i++] = in[in_];
                    in_++;
                    if (i == 4) {
                        for (i = 0; i < 4; i++) {
                            char_array_4[i] = table[char_array_4[i]];
                        }

                        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                        for (i = 0; (i < 3); i++) {
                            out.push_back(char_array_3[i]);
                        }
                        i = 0;
                    }
                }

                if (i) {
                    int j = 0;
                    for (j = i; j < 4; j++) {
                        char_array_4[j] = 0;
                    }

                    for (j = 0; j < 4; j++) {
                        char_array_4[j] = table[char_array_4[j]];
                    }

                    char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
                    char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
                    char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

                    for (j = 0; (j < i - 1); j++) {
                        out.push_back(char_array_3[j]);
                    }
                }

                return out;
            }

            static Result<std::string> UrlSafeBase64Encode(
                _In_ const void *in,
                _In_ const size_t size
            ) {
                return Base64Encode(in, size).map([&](std::string out) {
                    for (char &c: out) {
                        if (c == '+') { c = '-'; }
                        if (c == '/') { c = '_'; }
                    }
                    // Remove padding '=' characters
                    const auto pos = out.find('=');
                    if (pos != std::string::npos) {
                        out.erase(pos);
                    }
                    return out;
                });
            }

            static Result<std::string> UrlSafeBase64Encode(_In_ const Stream &in) {
                return UrlSafeBase64Encode(in.data(), in.size());
            }

            static Result<Stream> UrlSafeBase64Decode(_In_ const char *in) {
                std::string in0 = in;
                for (char &c: in0) {
                    if (c == '-') { c = '+'; }
                    if (c == '_') { c = '/'; }
                }
                // Add back padding '=' characters if necessary
                while (in0.size() % 4 != 0) {
                    in0 += '=';
                }
                return Base64Decode(in0.data());
            }
        };

        class Length final {
        public:
            /**
             * length codec as utf-8
             */
            static Result<Stream> Encode(_In_ const int64_t length) {
                static int64_t _max_ = 1;
                if (1 == _max_) {
                    _max_ = _max_ << 42;
                }
                if (length < 0 || length >= _max_) {
                    auto es = cpl::strings::Format(
                        "[X] input length [%" PRId64 "] is out of range" CPL_FILE_AND_LINE, length
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Error::OutOfRange, es.value());
                }
                Stream out{};
                out.clear();
                if (length < 128) {
                    out.push_back(static_cast<uint8_t>(length));
                    return out;
                }
                uint8_t buffer[8] = {};
                int idx = 0; {
                    int64_t n = length;

                    while (n > 0) {
                        const int64_t fn = n & 0x3f;
                        n = n >> 6;
                        const auto v = static_cast<uint8_t>((0x80 | fn) & 0xbf);
                        buffer[idx] = v;
                        idx++;
                        const int64_t hlc = 8 - idx - 2;
                        if (n >= (static_cast<int64_t>(1) << hlc)) {
                            continue;
                        }
                        const int64_t hh = ((1 << (idx + 1)) - 1) << (hlc + 1);
                        const int64_t hb = hh | n;
                        buffer[idx] = static_cast<uint8_t>(hb);
                        idx++;
                        break;
                    }
                }
                if (idx > 6) {
                    auto es = cpl::strings::Format(
                        "[X] input length [%" PRId64 "] is out of range" CPL_FILE_AND_LINE, length);
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Error::OutOfRange, es.value());
                }
                out.resize(idx);
                for (size_t i = 0; i < idx; i++) {
                    const auto j = idx - i - 1;
                    out[j] = buffer[i];
                }
                Ok(out)
            }

            /**
             * length codec as utf-8
             */
            static Result<std::tuple<int64_t, uint8_t> > Decode(_In_ const Stream &stream) {
                if (stream.empty()) {
                    return cpl::Err(cpl::Error(cpl::Error::NoData, CPL_FILE_AND_LINE));
                }
                int64_t decodedLength{};
                uint8_t nBytes{};
                const uint8_t header = stream[0];
                if (stream[0] >> 7 == 0) {
                    decodedLength = header;
                    nBytes = 1;
                    return std::tuple<int64_t, uint8_t>(decodedLength, nBytes);
                }
                for (size_t i = 0; i < 7; i++) {
                    const size_t rn = 7 - i;
                    if (((header >> rn) & 1u) == 0u) {
                        nBytes = i;
                        break;
                    }
                }
                if (nBytes == 0) {
                    return cpl::Err(cpl::Error(strings::Errors::DecodeLengthAsUTF8,
                                               "Invalid UTF-8 length prefix" CPL_FILE_AND_LINE));
                }
                if (stream.size() < nBytes) {
                    return cpl::Err(cpl::Error(cpl::Error::OutOfRange,
                                               "Insufficient bytes for length field" CPL_FILE_AND_LINE));
                }
                int64_t tail = 0;
                for (size_t i = 1; i < nBytes; i++) {
                    if (stream[i] >> 6 != 2) {
                        return cpl::Err(cpl::Error(cpl::Error::InvalidArgument, "Invalid continuation byte"));
                    }
                    tail = (tail << 6) | (stream[i] & 0x3f);
                }
                const uint8_t mask = (1 << (8 - nBytes)) - 1;
                const int64_t offset = 6 * (nBytes - 1);
                decodedLength = ((header & mask) << offset) | tail;
                return std::tuple<int64_t, uint8_t>{decodedLength, nBytes};
            }
        };
    }

    namespace strings {
        inline Result<std::string> VFormat(
            _In_ const char *tpl,
            _In_ va_list ap
        ) {
            static constexpr auto delta = 256;
            if (tpl == nullptr) {
                return cpl::Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
            }
            std::vector<char> buffer{};
            size_t len = strlen(tpl) + delta;

            while (true) {
                buffer.resize(len);
                va_list ap_copy;
                va_copy(ap_copy, ap);
                const int nWritten = vsnprintf(buffer.data(), len, tpl, ap_copy);
                va_end(ap_copy);

                if (nWritten < 0) {
                    len = len * 2;
                    if (len > (1u << 20)) {
                        return cpl::Err(cpl::Error(Errors::StringFormat, "vsnprintf failed" CPL_FILE_AND_LINE));
                    }
                    continue;
                }
                if (static_cast<size_t>(nWritten) >= len) {
                    len = static_cast<size_t>(nWritten) + delta;
                    continue;
                }
                return std::string{buffer.data(), static_cast<size_t>(nWritten)};
            }
        }

        inline Result<std::wstring> VFormat(
            _In_ const wchar_t *tpl,
            _In_ va_list ap
        ) {
            static constexpr auto delta = 256;
            if (tpl == nullptr) {
                return cpl::Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
            }
            std::vector<wchar_t> buffer{};
            size_t len = wcslen(tpl) + delta; // initial buffer size
            while (true) {
                buffer.resize(len);
                va_list ap_copy;
                va_copy(ap_copy, ap);
                const int nWritten = vswprintf(buffer.data(), len, tpl, ap_copy);
                va_end(ap_copy);
                if (nWritten < 0) {
                    len = len * 2;
                    if (len > (1u << 20)) {
                        return cpl::Err(cpl::Error(Errors::StringFormat, "vswprintf failed"));
                    }
                    continue;
                }
                if (static_cast<size_t>(nWritten) >= len) {
                    len = static_cast<size_t>(nWritten) + delta;
                    continue;
                }
                return std::wstring{buffer.data(), static_cast<size_t>(nWritten)};
            }
        }

        inline Result<std::string> VFormat(_In_ const char *tpl, ...) {
            va_list args;
            va_start(args, tpl);
            const auto ret = VFormat(tpl, args);
            va_end(args);
            return ret;
        }

        inline Result<std::wstring> VFormat(_In_ const wchar_t *tpl, ...) {
            va_list args;
            va_start(args, tpl);
            const auto ret = VFormat(tpl, args);
            va_end(args);
            return ret;
        }

        /**
         * Simplified helper
         * @param tpl
         * @param ...
         * @return
         */
        inline Result<std::string> Format(const char *tpl, ...) {
            va_list args;
            va_start(args, tpl);
            const auto ret = VFormat(tpl, args);
            va_end(args);

            return ret;
        }

        inline Result<std::wstring> Format(const wchar_t *tpl, ...) {
            va_list args;
            va_start(args, tpl);
            const auto ret = VFormat(tpl, args);
            va_end(args);

            return ret;
        }

        inline Stream WStringToUTF16LEBytes(const std::wstring &ws) {
            // Get pointer to wchar_t data.
            const auto *pData = reinterpret_cast<const uint8_t *>(ws.c_str());

            // Total byte count: wchar count * sizeof(wchar_t).
            const size_t byteCount = ws.length() * sizeof(wchar_t);

            // Build byte vector.
            return Stream{pData, pData + byteCount};
        }

        inline Result<std::wstring> UTF16LEBytesToWString(const Stream &stream) {
            if (stream.empty()) return L"";

            // Byte length must be aligned to wchar_t size.
            if (stream.size() % sizeof(wchar_t) != 0) {
                return Err(cpl::Error(strings::Errors::UTF16LEBytesToWStringLengthOdd, CPL_FILE_AND_LINE));
            }

            // Number of wide characters.
            const size_t charCount = stream.size() / sizeof(wchar_t);

            // Construct wstring from raw bytes.
            return std::wstring{
                reinterpret_cast<const wchar_t *>(stream.data()), // byte buffer as wchar_t
                charCount // number of characters
            };
        }


        inline std::string Trim(const std::string &str) {
            const size_t first = str.find_first_not_of(" \t\n\r\f\v");
            if (first == std::string::npos) {
                return "";
            }
            const size_t last = str.find_last_not_of(" \t\n\r\f\v");
            return str.substr(first, last - first + 1);
        }

        inline std::vector<std::string> Split(const std::string &str, const std::string &delim) {
            if (delim.empty()) {
                return std::vector<std::string>{str}; // Empty delimiter: return source string.
            }
            std::vector<std::string> tokens;
            size_t prev = 0, pos = 0;
            do {
                pos = str.find(delim, prev);
                if (pos == std::string::npos) { pos = str.length(); }
                std::string token = str.substr(prev, pos - prev);
                // if (!token.empty()) { tokens.push_back(token); }
                tokens.push_back(token);
                prev = pos + delim.length();
            } while (pos < str.length() && prev < str.length());
            return tokens;
        }

        inline std::string Join(const std::vector<std::string> &array, const std::string &delim) {
            if (array.empty()) {
                return "";
            }
            if (array.size() == 1) {
                return array[0];
            }
            //
            {
                std::string buffer{};
                for (auto &s: array) {
                    buffer += s;
                    buffer += delim;
                }
                const auto n = buffer.length();
                return buffer.substr(0, n - delim.length());
            }
        }

        inline bool IsDigital(const std::string &s) {
            // return all_of(s.begin(), s.end(), isdigit);
            for (const unsigned char ch: s) {
                if (ch < '0' || ch > '9') {
                    return false;
                }
            }
            return true;
        }

        inline char Upper(const char c) {
            if (c >= 'a' && c <= 'z') {
                return static_cast<char>(c - 'a' + 'A');
            }
            return c;
        }

        inline void Upper(std::string &str) {
            for (size_t i = 0; i < str.length(); i++) {
                const auto ch = str[i];
                if (ch >= 'a' && ch <= 'z') {
                    str[i] = static_cast<char>(ch - ('a' - 'A'));
                }
            }
        }

        inline std::string ToUpper(const std::string &str) {
            auto s = str;
            Upper(s);
            return s;
        }

        inline void Lower(std::string &str) {
            for (size_t i = 0; i < str.length(); i++) {
                const auto ch = str[i];
                if (ch >= 'A' && ch <= 'Z') {
                    str[i] = static_cast<char>(ch + ('a' - 'A'));
                }
            }
        }

        inline std::string ToLower(const std::string &str) {
            auto s = str;
            Lower(s);
            return s;
        }

        inline bool EndsWith(const std::string &str, const std::string &suffix) {
            if (suffix.length() > str.length()) {
                return false;
            }
            for (size_t i = 0; i < suffix.length(); i++) {
                auto n = suffix.length() - 1 - i;
                auto m = str.length() - 1 - i;
                if (str[m] != suffix[n]) {
                    return false;
                }
            }
            return true;
        }

        inline bool StartsWith(const std::string &str, const std::string &prefix) {
            if (prefix.length() > str.length()) {
                return false;
            }
            for (size_t i = 0; i < prefix.length(); i++) {
                if (str[i] != prefix[i]) {
                    return false;
                }
            }
            return true;
        }

        inline Result<const char *> StrInStr(const char *mainStr, const char *subStr) {
            if (!mainStr || !subStr) {
                return cpl::Err(cpl::Error(cpl::Error::NullPointer, CPL_FILE_AND_LINE));
            }
            auto *cp = mainStr;
            const char *s1{}, *s2{};
            if (!*subStr) {
                return cp;
            }
            while (*cp) {
                s1 = cp;
                s2 = subStr;
                while (*s1 && *s2 && Upper(*s1) == Upper(*s2)) {
                    s1++, s2++;
                }
                if (!*s2) {
                    return cp;
                }
                cp++;
            }
            return Err(cpl::Error(cpl::Error::NoData, "[X] StrInStr substring not found" CPL_FILE_AND_LINE));
        }

        inline std::string ReplaceAll(const std::string &str, const std::string &from, const std::string &to) {
            if (from.empty()) {
                return str; // Avoid empty-delimiter edge case.
            }
            std::vector<std::string> t = Split(str, from);
            return Join(t, to);
        }
    }
}

#endif //CPL_STRINGS_HPP_JUSTICE_TENSION_STRONGER_MOISTURE_BRIGHTLY_CULTURE_ENCHANTED_GALLERY
