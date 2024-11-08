#ifndef STRINGS_HPP_PNFK2EXVBOBKFYHHBIBEH3Z4
#define STRINGS_HPP_PNFK2EXVBOBKFYHHBIBEH3Z4

#include <string>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <cstdint>
#include <tchar.h>
#include <vector>

using namespace std;

namespace strings {
    inline unsigned long Format(string &out, const TCHAR *tpl, ...) {
        va_list args;
        va_start(args, tpl);

        TCHAR *buffer = nullptr;
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
            nWritten = snprintf(buffer, len, tpl, args);
        } while (nWritten >= len - 1);
        out = string(buffer);
        goto __FREE__;
        __ERROR__:
        {
        }
        __FREE__:
            if (buffer) {
                free(buffer);
                buffer = nullptr;
            }
        va_end(args);
        return nWritten;
    }

    inline string Format(const TCHAR *tpl, ...) {
        string out{};
        va_list args;
        va_start(args, tpl);
        Format(out, tpl, args);
        va_end(args);
        return out;
    }

    inline string Trim(const string& str) {
        size_t first = str.find_first_not_of(" \t\n\r\f\v");
        if (first == std::string::npos)
            return ""; // 字符串全是空白字符

        size_t last = str.find_last_not_of(" \t\n\r\f\v");
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
            auto ch = str[i];
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

    inline string Hexlify(const string &s) {
        static TCHAR HEX_TABLE[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
        string buffer;
        for (const auto ch: s) {
            buffer.push_back(HEX_TABLE[(ch >> 4) & 0x0f]);
            buffer.push_back(HEX_TABLE[ch & 0x0f]);
        }
        return buffer;
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
}

#endif //STRINGS_HPP_PNFK2EXVBOBKFYHHBIBEH3Z4
