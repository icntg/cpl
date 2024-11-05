#ifndef WIN32_H_COURTESY_DETAILS_GRADUATION_HEALTH_INSURANCE_JOURNAL_LIBRARY_MUSIC
#define WIN32_H_COURTESY_DETAILS_GRADUATION_HEALTH_INSURANCE_JOURNAL_LIBRARY_MUSIC

#include <windows.h>
#include <tchar.h>
#include <cstdio>
#include <string>
#include "_constant.hpp"

using namespace std;

inline string FormatError(const DWORD errorCode) {
    static TCHAR buffer[IFW$BUFSIZ]{};
    memset(buffer, 0, sizeof(buffer));
    FormatMessage(
        FORMAT_MESSAGE_FROM_SYSTEM,
        nullptr,
        errorCode,
        0,
        buffer,
        BUFSIZ << 2,
        nullptr
    );
    const size_t n = _tcslen(buffer);
    if (n >= 2 && buffer[n - 2] == _T('\r') && buffer[n - 1] == _T('\n')) {
        buffer[n - 2] = _T('\0');
    }
    return buffer;
}

#endif  // WIN32_H_COURTESY_DETAILS_GRADUATION_HEALTH_INSURANCE_JOURNAL_LIBRARY_MUSIC