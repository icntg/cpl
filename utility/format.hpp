#ifndef FORMAT_HPP
#define FORMAT_HPP

#include <string>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <cstdint>
#include <tchar.h>

using namespace std;

inline unsigned long format(string &out, const TCHAR *tpl, ...) {
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
    do {
    } while (false);
__FREE__:
    if (buffer) {
        free(buffer);
        buffer = nullptr;
    }
    va_end(args);
    return nWritten;
}


#endif //FORMAT_HPP
