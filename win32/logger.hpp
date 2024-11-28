#ifndef LOGGER_HPP_CRAVING_HIGHLIGHT_DIVERSE_VICTORY_PATIENCE_GALLERY_FORTIFY_ENCHANT_WINDOWS
#define LOGGER_HPP_CRAVING_HIGHLIGHT_DIVERSE_VICTORY_PATIENCE_GALLERY_FORTIFY_ENCHANT_WINDOWS

#include <string>
#include <windows.h>
#include "../utility/base.hpp"
#include "../utility/strings.hpp"

using namespace std;

namespace cpl {
    namespace win32 {
        namespace logger {
            constexpr auto EventID = 2186;
            class WinEvtLogger final : public base::ILogger {
            protected:
                HANDLE hEventSource{};
                LEVEL level = LEVEL::$TRACE;

            public:
                explicit WinEvtLogger(const string &name, const LEVEL &level = LEVEL::$TRACE) {
                    this->hEventSource = RegisterEventSource(nullptr, name.data());
                    this->level = level;
                }

                ~WinEvtLogger() override {
                    if (nullptr != hEventSource) {
                        DeregisterEventSource(hEventSource);
                    }
                }

                LEVEL GetLevel() override {
                    return level;
                }

                void SetLevel(LEVEL level) override {
                    this->level = level;
                }

                void Trace(const char *fmt, ...) override {
                    if (nullptr == hEventSource) {
                        return;
                    }
                    if (level < LEVEL::$TRACE) {
                        return;
                    }
                    string msg{};
                    va_list args{};
                    va_start(args, fmt);
                    strings::VFormat(msg, fmt, args);
                    va_end(args);

                    LPCSTR * lpStrings{};
                    LPCSTR lpStringBuf[1]{};
                    const auto p = msg.data();
                    memmove(lpStringBuf, p, sizeof(void *));
                    lpStrings = &lpStringBuf[0];

                    ReportEvent(hEventSource, EVENTLOG_INFORMATION_TYPE, 0, EventID, nullptr, 1, 0,
                           lpStrings, nullptr);
                }

                void Debug(const char *fmt, ...) override {
                    if (nullptr == hEventSource) {
                        return;
                    }
                    if (level < LEVEL::$DEBUG) {
                        return;
                    }
                    string msg{};
                    va_list args{};
                    va_start(args, fmt);
                    strings::VFormat(msg, fmt, args);
                    va_end(args);

                    LPCSTR * lpStrings{};
                    LPCSTR lpStringBuf[1]{};
                    const auto p = msg.data();
                    memmove(lpStringBuf, p, sizeof(void *));
                    lpStrings = &lpStringBuf[0];

                    ReportEvent(hEventSource, EVENTLOG_INFORMATION_TYPE, 0, EventID, nullptr, 1, 0,
                           lpStrings, nullptr);
                }

                void Info(const char *fmt, ...) override {
                    if (nullptr == hEventSource) {
                        return;
                    }
                    if (level < LEVEL::$INFO) {
                        return;
                    }
                    string msg{};
                    va_list args{};
                    va_start(args, fmt);
                    strings::VFormat(msg, fmt, args);
                    va_end(args);

                    LPCSTR * lpStrings{};
                    LPCSTR lpStringBuf[1]{};
                    const auto p = msg.data();
                    memmove(lpStringBuf, p, sizeof(void *));
                    lpStrings = &lpStringBuf[0];

                    ReportEvent(hEventSource, EVENTLOG_INFORMATION_TYPE, 0, EventID, nullptr, 1, 0,
                           lpStrings, nullptr);
                }

                void Success(const char *fmt, ...) override {
                    if (nullptr == hEventSource) {
                        return;
                    }
                    if (level < LEVEL::$INFO) {
                        return;
                    }
                    string msg{};
                    va_list args{};
                    va_start(args, fmt);
                    strings::VFormat(msg, fmt, args);
                    va_end(args);

                    LPCSTR * lpStrings{};
                    LPCSTR lpStringBuf[1]{};
                    const auto p = msg.data();
                    memmove(lpStringBuf, p, sizeof(void *));
                    lpStrings = &lpStringBuf[0];

                    ReportEvent(hEventSource, EVENTLOG_SUCCESS, 0, EventID, nullptr, 1, 0,
                           lpStrings, nullptr);
                }

                void Warn(const char *fmt, ...) override {
                    if (nullptr == hEventSource) {
                        return;
                    }
                    if (level < LEVEL::$WARN) {
                        return;
                    }
                    string msg{};
                    va_list args{};
                    va_start(args, fmt);
                    strings::VFormat(msg, fmt, args);
                    va_end(args);

                    LPCSTR * lpStrings{};
                    LPCSTR lpStringBuf[1]{};
                    const auto p = msg.data();
                    memmove(lpStringBuf, p, sizeof(void *));
                    lpStrings = &lpStringBuf[0];

                    ReportEvent(hEventSource, EVENTLOG_WARNING_TYPE, 0, EventID, nullptr, 1, 0,
                           lpStrings, nullptr);
                }

                void Error(const char *fmt, ...) override {
                    if (nullptr == hEventSource) {
                        return;
                    }
                    if (level < LEVEL::$ERROR) {
                        return;
                    }
                    string msg{};
                    va_list args{};
                    va_start(args, fmt);
                    strings::VFormat(msg, fmt, args);
                    va_end(args);

                    LPCSTR * lpStrings{};
                    LPCSTR lpStringBuf[1]{};
                    const auto p = msg.data();
                    memmove(lpStringBuf, p, sizeof(void *));
                    lpStrings = &lpStringBuf[0];

                    ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0, EventID, nullptr, 1, 0,
                           lpStrings, nullptr);
                }

                void Fatal(const char *fmt, ...) override {
                    if (nullptr == hEventSource) {
                        return;
                    }
                    string msg{};
                    va_list args{};
                    va_start(args, fmt);
                    strings::VFormat(msg, fmt, args);
                    va_end(args);

                    LPCSTR * lpStrings{};
                    LPCSTR lpStringBuf[1]{};
                    const auto p = msg.data();
                    memmove(lpStringBuf, p, sizeof(void *));
                    lpStrings = &lpStringBuf[0];

                    ReportEvent(hEventSource, EVENTLOG_ERROR_TYPE, 0, EventID, nullptr, 1, 0,
                           lpStrings, nullptr);
                }
            };
        }
    }
}



#endif //LOGGER_HPP_CRAVING_HIGHLIGHT_DIVERSE_VICTORY_PATIENCE_GALLERY_FORTIFY_ENCHANT_WINDOWS
