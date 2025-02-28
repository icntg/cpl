#ifndef CPL_STRINGS_HPP_JUSTICE_TENSION_STRONGER_MOISTURE_BRIGHTLY_CULTURE_ENCHANTED_GALLERY
#define CPL_STRINGS_HPP_JUSTICE_TENSION_STRONGER_MOISTURE_BRIGHTLY_CULTURE_ENCHANTED_GALLERY

#include <algorithm>
#include <string>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <tchar.h>
#include <vector>

using namespace std;

namespace cpl {
    namespace strings {
        inline size_t VFormat(string &out, const TCHAR *tpl, va_list ap) {
            TCHAR *buffer{};
            size_t len = _tcslen(tpl);
            size_t nWritten = 0;
            do {
                len = len << 1u;
                void *p = buffer;
                buffer = static_cast<TCHAR *>(realloc(p, len));
                if (buffer == nullptr) {
                    buffer = static_cast<TCHAR *>(p);
                    goto __ERROR__;
                }
                nWritten = vsnprintf(buffer, len, tpl, ap);
            } while (nWritten >= len - 1);
            out = string(buffer);
            goto __FREE__;

        __ERROR__:
            PASS;
        __FREE__:
            if (buffer) {
                free(buffer);
                buffer = nullptr;
            }
            return nWritten;
        }

        inline size_t Format(string &out, const TCHAR *tpl, ...) {
            va_list args;
            va_start(args, tpl);
            const auto nWritten = VFormat(out, tpl, args);
            va_end(args);
            return nWritten;
        }

        inline string Format(const TCHAR *tpl, ...) {
            string out{};
            va_list args;
            va_start(args, tpl);
            VFormat(out, tpl, args);
            va_end(args);
            return out;
        }

        inline string Trim(const string &str) {
            const size_t first = str.find_first_not_of(" \t\n\r\f\v");
            if (first == std::string::npos)
                return ""; // 字符串全是空白字符

            const size_t last = str.find_last_not_of(" \t\n\r\f\v");
            return str.substr(first, (last - first + 1));
        }

        inline vector<string> Split(const string &str, const string &delim) {
            std::vector<std::string> tokens;
            size_t prev = 0, pos = 0;
            do {
                pos = str.find(delim, prev);
                if (pos == std::string::npos) pos = str.length();
                std::string token = str.substr(prev, pos - prev);
                if (!token.empty()) tokens.push_back(token);
                prev = pos + delim.length();
            } while (pos < str.length() && prev < str.length());
            return tokens;
        }

        inline string Join(const vector<string> &array, const string &delim) {
            if (array.empty()) {
                return "";
            } else if (array.size() == 1) {
                return array[0];
            } else {
                string buffer{};
                for (auto &s: array) {
                    buffer += s;
                    buffer += delim;
                }
                auto n = buffer.length();
                return buffer.substr(0, n - delim.length());
            }
        }

        __attribute__((unused)) inline void Upper(string &str) {
            for (auto i = 0; i < str.length(); i++) {
                auto ch = str[i];
                if (ch <= 'z' && ch >= 'a') {
                    str[i] = static_cast<char>(ch - ('a' - 'A'));
                }
            }
        }

        __attribute__((unused)) inline void Lower(string &str) {
            for (auto i = 0; i < str.length(); i++) {
                const auto ch = str[i];
                if (ch <= 'Z' && ch >= 'A') {
                    str[i] = static_cast<char>(ch + ('a' - 'A'));
                }
            }
        }

        inline bool EndsWith(const string &str, const string &suffix) {
            if (suffix.length() > str.length()) {
                return false;
            }
            for (auto i = 0; i < suffix.length(); i++) {
                auto n = suffix.length() - 1 - i;
                auto m = str.length() - 1 - i;
                if (str[m] != suffix[n]) {
                    return false;
                }
            }
            return true;
        }

        inline bool StartsWith(const string &str, const string &prefix) {
            if (prefix.length() > str.length()) {
                return false;
            }
            for (auto i = 0; i < prefix.length(); i++) {
                if (str[i] != prefix[i]) {
                    return false;
                }
            }
            return true;
        }

        inline string Hex(const string &s) {
            static TCHAR HEX_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
            string buffer;
            for (const auto ch: s) {
                buffer.push_back(HEX_TABLE[(ch >> 4) & 0x0f]);
                buffer.push_back(HEX_TABLE[ch & 0x0f]);
            }
            return buffer;
        }

        inline int32_t Unhex(const string &hex, string &out) {
            if (hex.length() % 2 != 0) {
                return -1;
            }
            out.reserve(hex.length() / 2 + 2);
            for (auto i = 0; i < hex.length(); i += 2) {
                const auto ch0 = hex[i];
                const auto ch1 = hex[i + 1];
                char bh{}, bl{};
                if (ch0 >= '0' && ch0 <= '9') {
                    bh = static_cast<char>(ch0 - '0');
                } else if (ch0 >= 'A' && ch0 <= 'F') {
                    bh = static_cast<char>(ch0 - 'A' + 10);
                } else if (ch0 >= 'a' && ch0 <= 'f') {
                    bh = static_cast<char>(ch0 - 'a' + 10);
                } else {
                    return i;
                }
                if (ch1 >= '0' && ch1 <= '9') {
                    bl = static_cast<char>(ch1 - '0');
                } else if (ch1 >= 'A' && ch1 <= 'F') {
                    bl = static_cast<char>(ch1 - 'A' + 10);
                } else if (ch1 >= 'a' && ch1 <= 'f') {
                    bl = static_cast<char>(ch1 - 'a' + 10);
                } else {
                    return i + 1;
                }
                const auto ch = static_cast<char>((bh << 4) | bl);
                out.push_back(ch);
            }
            return 0;
        }

        inline string Unhex(const string &hex) {
            string out{};
            Unhex(hex, out);
            return out;
        }

        inline bool IsDigital(const string &s) {
            return all_of(s.begin(), s.end(), isdigit);
            // for (const auto ch: s) {
            //     if (ch < _T('0') || ch > _T('9')) {
            //         return false;
            //     }
            // }
            // return true;
        }

        inline TCHAR Upper(const TCHAR c) {
            if (c >= _T('a') && c <= _T('z')) {
                return static_cast<TCHAR>(c - (_T('a') - _T('A')));
            }
            return c;
        }

        inline TCHAR *StrInStr(const TCHAR *mainStr, const TCHAR *subStr) {
            TCHAR *cp = nullptr;
            memmove(&cp, &mainStr, sizeof(TCHAR *));
            TCHAR *s1 = nullptr, *s2 = nullptr;
            if (!*subStr) {
                return cp;
            }
            while (*cp) {
                s1 = cp;
                memmove(&s2, &subStr, sizeof(TCHAR *));
                while (*s1 && *s2 && Upper(*s1) == Upper(*s2)) {
                    s1++, s2++;
                }
                if (!*s2) {
                    return cp;
                }
                cp++;
            }
            return nullptr;
        }

        inline int32_t FromWString(const wstring &s, string &out, const UINT CodePage = CP_ACP) {
            int32_t retCode = ERROR_SUCCESS;
            const auto size = WideCharToMultiByte(CodePage, 0, s.data(), -1, nullptr, 0, nullptr, nullptr);
            const auto buffer = new(nothrow) TCHAR[size];
            if (nullptr == buffer) {
                retCode = ERROR_NOT_ENOUGH_MEMORY;
                goto __ERROR__;
            }
            {
                const auto r0 = WideCharToMultiByte(CodePage, 0, s.data(), -1, buffer, size, nullptr, nullptr);
                if (0 == r0) {
                    const auto e = GetLastError();
                    retCode = static_cast<int32_t>(e);
                    goto __ERROR__;
                }
                out = string(buffer);
            }

            goto __FREE__;
        __ERROR__:
            PASS;
        __FREE__:
            delete[] buffer;
            return retCode;
        }

        inline string FromWString(const wstring &s, const UINT CodePage = CP_ACP) {
            string ret{};
            FromWString(s, ret, CodePage);
            return ret;
        }

        inline int32_t FromString(const string &s, wstring &out, const UINT CodePage = CP_ACP) {
            int32_t retCode = ERROR_SUCCESS;
            const auto size = MultiByteToWideChar(CodePage, 0, s.data(), -1, nullptr, 0);
            const auto buffer = new(nothrow) wchar_t[size];
            if (nullptr == buffer) {
                retCode = ERROR_NOT_ENOUGH_MEMORY;
                goto __ERROR__;
            }
            {
                const auto r0 = MultiByteToWideChar(CodePage, 0, s.data(), -1, buffer, size);
                if (0 == r0) {
                    const auto e = GetLastError();
                    retCode = static_cast<int32_t>(e);
                    goto __ERROR__;
                }
                out = wstring(buffer);
            }

            goto __FREE__;
        __ERROR__:
            PASS;
        __FREE__:
            delete[] buffer;
            return retCode;
        }

        inline wstring FromString(const string &s, const UINT CodePage = CP_ACP) {
            wstring ret{};
            FromString(s, ret, CodePage);
            return ret;
        }

        inline string ReplaceAll(const string &str, const string &from, const string &to) {
            vector<string> t = Split(str, from);
            return Join(t, to);
        }

        __attribute__((unused)) inline int32_t Base64Encode(string &dst, const string &src) {
            static const char base64_table[] = 
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789+/";
            
            const size_t len = src.length();
            dst.clear();
            dst.reserve(((len + 2) / 3) * 4);
            
            for (size_t i = 0; i < len; i += 3) {
                uint32_t octet_a = i < len ? (uint8_t)src[i] : 0;
                uint32_t octet_b = i + 1 < len ? (uint8_t)src[i + 1] : 0;
                uint32_t octet_c = i + 2 < len ? (uint8_t)src[i + 2] : 0;
                
                uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;
                
                dst.push_back(base64_table[(triple >> 18) & 0x3F]);
                dst.push_back(base64_table[(triple >> 12) & 0x3F]);
                dst.push_back(base64_table[(triple >> 6) & 0x3F]);
                dst.push_back(base64_table[triple & 0x3F]);
            }
            
            // Add padding
            switch (len % 3) {
                case 1:
                    dst[dst.length() - 2] = '=';
                    dst[dst.length() - 1] = '=';
                    break;
                case 2:
                    dst[dst.length() - 1] = '=';
                    break;
            }
            
            return 0;
        }

        __attribute__((unused)) inline int32_t Base64Decode(string &dst, const string &src) {
            static const int8_t base64_reverse_table[256] = {
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 00-0F */
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 10-1F */
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,  /* 20-2F */
                52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,  /* 30-3F */
                -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,  /* 40-4F */
                15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,  /* 50-5F */
                -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,  /* 60-6F */
                41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,  /* 70-7F */
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 80-8F */
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* 90-9F */
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* A0-AF */
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* B0-BF */
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* C0-CF */
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* D0-DF */
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,  /* E0-EF */
                -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1   /* F0-FF */
            };

            dst.clear();
            const size_t len = src.length();
            if (len % 4 != 0) {
                return -1; // Invalid base64 length
            }

            size_t padding = 0;
            if (len > 0 && src[len - 1] == '=') padding++;
            if (len > 1 && src[len - 2] == '=') padding++;
            
            dst.reserve((len * 3) / 4 - padding);

            for (size_t i = 0; i < len; i += 4) {
                auto sextet_a = base64_reverse_table[src[i]];
                auto sextet_b = base64_reverse_table[src[i + 1]];
                auto sextet_c = base64_reverse_table[src[i + 2]];
                auto sextet_d = base64_reverse_table[src[i + 3]];

                if (sextet_a == -1 || sextet_b == -1 || 
                    (sextet_c == -1 && src[i + 2] != '=') ||
                    (sextet_d == -1 && src[i + 3] != '=')) {
                    return static_cast<int32_t>(i + 1); // Invalid base64 character
                }

                uint32_t triple = (sextet_a << 18) | (sextet_b << 12) |
                                 ((sextet_c & 0x3F) << 6) | (sextet_d & 0x3F);

                dst.push_back(static_cast<char>((triple >> 16u) & 0xFF));
                if (src[i + 2] != '=') {
                    dst.push_back(static_cast<char>((triple >> 8u) & 0xFF));
                }
                if (src[i + 3] != '=') {
                    dst.push_back(static_cast<char>(triple & 0xFF));
                }
            }

            // Convert back to original encoding if needed
            if constexpr (sizeof(TCHAR) == sizeof(wchar_t)) {
                wstring wide_str;
                int32_t ret = FromString(dst, wide_str, CP_UTF8);
                if (ret != ERROR_SUCCESS) {
                    return ret;
                }
                dst = string(wide_str.begin(), wide_str.end());
            }

            return 0;
        }
    }
}


#endif //CPL_STRINGS_HPP_JUSTICE_TENSION_STRONGER_MOISTURE_BRIGHTLY_CULTURE_ENCHANTED_GALLERY
