#ifndef THREAD_HPP_APPLE_TREE_FLOWER_BIRD_CLOUD_RIVER_STONE_MUSIC
#define THREAD_HPP_APPLE_TREE_FLOWER_BIRD_CLOUD_RIVER_STONE_MUSIC

#include <process.h>
#include <windows.h>
#include <cstdio>

#include "api.hpp"

using namespace std;

// cpl has zero external-logger dependency. The legacy thread.hpp used
// ../../ccl-del/vendor/logger/log.h (a path outside this repo that no longer
// exists). Fatal thread-creation failures still need to surface a diagnostic
// before exit(), so we route them through OutputDebugStringA — the same native
// debug sink sys.hpp's LOG_D uses. No new dependency is introduced.
namespace cpl {
    namespace sys {
        namespace thread {
            inline void logFatal(_In_ const char *tpl, ...) {
                char buf[512]{};
                va_list args;
                va_start(args, tpl);
                _vsnprintf(buf, sizeof(buf) - 1, tpl, args);
                va_end(args);
                OutputDebugStringA(buf);
                OutputDebugStringA("\n");
            }
        }
    }
}
#define log_fatal cpl::sys::thread::logFatal

namespace cpl {
    namespace sys {
        namespace thread {
            typedef DWORD (CALLBACK *CallbackFunction)(LPVOID args);

            class Thread {
            protected:
                DWORD threadId{};
                HANDLE threadHandle{};
                CallbackFunction callback{};

            public:
                explicit Thread(CallbackFunction callback)
                    : callback(callback) {
                }

                ~Thread() {
                    if (nullptr != threadHandle && INVALID_HANDLE_VALUE != threadHandle) {
                        CloseHandle(threadHandle);
                        threadId = 0;
                    }
                }

                /**
                 * 使用CreateThread启动线程，可能会导致内存泄漏。
                 * 适用场景：一次性启动，无限循环的任务。
                 * 是否会引入InitializeCriticalSectionEx，未知。
                 */
                void Start() {
                    this->threadHandle = CreateThread(
                        nullptr,
                        0,
                        this->callback,
                        nullptr,
                        0,
                        &this->threadId
                    );
                    if (nullptr == this->threadHandle) {
                        const auto e = GetLastError();
                        log_fatal("[x] CreateThread failed 0x%lx:%s", e, FormatError(e).data());
                        exit(static_cast<int>(e));
                    }
                }

                /**
                 * 使用_beginthreadex启动线程，不会导致内存泄漏，但会引入InitializeCriticalSectionEx不兼容XP。
                 * 适用场景，需要频繁启动、关闭线程。
                 */
                void StartEx() {
                    this->threadHandle = reinterpret_cast<HANDLE>(_beginthreadex(
                        nullptr,
                        0,
                        reinterpret_cast<unsigned(CALLBACK *)(void *)>(this->callback),
                        nullptr,
                        0,
                        reinterpret_cast<unsigned *>(&this->threadId)
                    ));
                    if (this->threadHandle == INVALID_HANDLE_VALUE) {
                        if (EAGAIN == errno) {
                            log_fatal("[x] _beginthreadex failed: too many threads: %d", _doserrno);
                            exit(errno);
                        }
                        if (EINVAL == errno) {
                            log_fatal("[x] _beginthreadex failed: parameters or stack are error: %d", _doserrno);
                            exit(errno);
                        }
                        if (EACCES == errno) {
                            log_fatal("[x] _beginthreadex failed: resource is not enough: %d", _doserrno);
                            exit(errno);
                        }
                    }
                    if (this->threadHandle == nullptr) {
                        log_fatal("[x] _beginthreadex failed: unknown error: %d %d", errno, _doserrno);
                        exit(errno);
                    }
                }

                DWORD GetThreadId() const {
                    return threadId;
                }

                HANDLE &GetThreadHandle() {
                    return threadHandle;
                }
            };
        }
    }
}

#endif //THREAD_HPP_APPLE_TREE_FLOWER_BIRD_CLOUD_RIVER_STONE_MUSIC
