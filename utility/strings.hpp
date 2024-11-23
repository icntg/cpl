#ifndef STRINGS_HPP_PNFK2EXVBOBKFYHHBIBEH3Z4
#define STRINGS_HPP_PNFK2EXVBOBKFYHHBIBEH3Z4

#include <string>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <tchar.h>
#include <vector>

using namespace std;

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
        do{}while(false);
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

    inline string Trim(const string& str) {
        const size_t first = str.find_first_not_of(" \t\n\r\f\v");
        if (first == std::string::npos)
            return ""; // 字符串全是空白字符

        const size_t last = str.find_last_not_of(" \t\n\r\f\v");
        return str.substr(first, (last - first + 1));
    }

    inline vector<string> Split(const string& str, const string& delim) {
        std::vector<std::string> tokens;
        size_t prev = 0, pos = 0;
        do {
            pos = str.find(delim, prev);
            if (pos == std::string::npos) pos = str.length();
            std::string token = str.substr(prev, pos-prev);
            if (!token.empty()) tokens.push_back(token);
            prev = pos + delim.length();
        } while (pos < str.length() && prev < str.length());
        return tokens;
    }

    inline string Join(const vector<string>& array, const string& delim) {
        if (array.empty()) {
            return "";
        } else if (array.size() == 1) {
            return array[0];
        } else {
            string buffer{};
            for (auto& s : array) {
                buffer += s;
                buffer += delim;
            }
            auto n = buffer.length();
            return buffer.substr(0, n - delim.length());
        }
    }

    inline void Upper(string& str) {
        for (auto i = 0; i < str.length(); i++) {
            auto ch = str[i];
            if (ch <= 'z' && ch >= 'a') {
                str[i] = static_cast<char>(ch - ('a' - 'A'));
            }
        }
    }

    inline void Lower(string& str) {
        for (auto i = 0; i < str.length(); i++) {
            const auto ch = str[i];
            if (ch <= 'Z' && ch >= 'A') {
                str[i] = static_cast<char>(ch + ('a' - 'A'));
            }
        }
    }

    inline bool EndsWith(const string& str, const string& suffix) {
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

    inline bool StartsWith(const string& str, const string& prefix) {
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
        for (auto i = 0; i < hex.length(); i+=2) {
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
        for (const auto ch: s) {
            if (ch < _T('0') || ch > _T('9')) {
                return false;
            }
        }
        return true;
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

    inline string FromWString(const wstring &s, const UINT CodePage = CP_ACP) {
        string ret{};
        const auto size = WideCharToMultiByte(CodePage, 0, s.data(), -1, nullptr, 0, nullptr, nullptr);
        const auto buffer = new (nothrow) TCHAR[size];
        if (nullptr == buffer) {
            goto __ERROR__;
        }
        WideCharToMultiByte(CodePage, 0, s.data(), -1, buffer, size, nullptr, nullptr);
        ret = string(buffer);
        goto __FREE__;
        __ERROR__:
        do{}while(false);
        __FREE__:
        delete[] buffer;
        return ret;
    }

    inline wstring FromString(const string &s, const UINT CodePage = CP_ACP) {
        wstring ret{};
        const auto size = MultiByteToWideChar(CodePage, 0, s.data(), -1, nullptr, 0);
        const auto buffer = new (nothrow) wchar_t[size];
        if (nullptr == buffer) {
            goto __ERROR__;
        }
        MultiByteToWideChar(CodePage, 0, s.data(), -1, buffer, size);
        ret = wstring(buffer);
        goto __FREE__;
        __ERROR__:
        do{}while(false);
        __FREE__:
        delete[] buffer;
        return ret;
    }

    inline string ReplaceAll(const string& str, const string& from, const string& to) {
        vector<string> t = Split(str, from);
        return Join(t, to);
    }
}

#endif //STRINGS_HPP_PNFK2EXVBOBKFYHHBIBEH3Z4
