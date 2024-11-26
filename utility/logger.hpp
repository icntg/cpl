#ifndef LOGGER_HPP_CRAVING_HIGHLIGHT_DIVERSE_VICTORY_PATIENCE_GALLERY_FORTIFY_ENCHANT
#define LOGGER_HPP_CRAVING_HIGHLIGHT_DIVERSE_VICTORY_PATIENCE_GALLERY_FORTIFY_ENCHANT

#include <string>
#include <windows.h>
#include "base.hpp"

using namespace std;

namespace logger {
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

        LEVEL GetLevel() override;

        void SetLevel(LEVEL level) override;

        void Trace(const char *fmt, ...) override {
            if (nullptr == hEventSource) {
                return;
            }
            if (level < LEVEL::$TRACE) {
                return;
            }
        }

        void Debug(const char *fmt, ...) override {
            if (nullptr == hEventSource) {
                return;
            }
            if (level < LEVEL::$DEBUG) {
                return;
            }
        }

        void Info(const char *fmt, ...) override {
            if (nullptr == hEventSource) {
                return;
            }
            if (level < LEVEL::$INFO) {
                return;
            }
        }

        void Warn(const char *fmt, ...) override {
            if (nullptr == hEventSource) {
                return;
            }
            if (level < LEVEL::$WARN) {
                return;
            }
        }

        void Error(const char *fmt, ...) override {
            if (nullptr == hEventSource) {
                return;
            }
            if (level < LEVEL::$ERROR) {
                return;
            }
        }

        void Fatal(const char *fmt, ...) override {
            if (nullptr == hEventSource) {
                return;
            }
        }
    };
}

#endif //LOGGER_HPP_CRAVING_HIGHLIGHT_DIVERSE_VICTORY_PATIENCE_GALLERY_FORTIFY_ENCHANT
