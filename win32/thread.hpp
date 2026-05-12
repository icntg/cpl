#ifndef THREAD_HPP_APPLE_TREE_FLOWER_BIRD_CLOUD_RIVER_STONE_MUSIC
#define THREAD_HPP_APPLE_TREE_FLOWER_BIRD_CLOUD_RIVER_STONE_MUSIC

#include <cerrno>
#include <process.h>

#include "../base.hpp"
#include "sys.hpp"

namespace cpl {
    namespace sys {
        namespace thread {
            class Errors final {
            public:
                static constexpr int64_t base = static_cast<int64_t>(0x31) << 32;
                static constexpr cpl::Error::CodeDef CreateThread_ = {base | 1};
                static constexpr cpl::Error::CodeDef BeginThreadEx = {base | 2};
            };

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

                Int32Result Start() {
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
                        auto es = strings::Format(
                            "[X] CreateThread failed [0x%lx][%s]" CPL_FILE_AND_LINE,
                            e,
                            FormatError(e).data()
                        );
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        return MakeErr(Errors::CreateThread_, es.value<>());
                    }
                    return 0;
                }

                Int32Result StartEx() {
                    this->threadHandle = reinterpret_cast<HANDLE>(_beginthreadex(
                        nullptr,
                        0,
                        reinterpret_cast<unsigned(CALLBACK *)(void *)>(this->callback),
                        nullptr,
                        0,
                        reinterpret_cast<unsigned *>(&this->threadId)
                    ));
                    if (this->threadHandle == INVALID_HANDLE_VALUE || this->threadHandle == nullptr) {
                        const auto e = GetLastError();
                        auto es = strings::Format(
                            "[X] _beginthreadex failed [errno=%d][dos=%lu][%s]" CPL_FILE_AND_LINE,
                            errno,
                            _doserrno,
                            FormatError(e).data()
                        );

                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        return MakeErr(Errors::BeginThreadEx, es.value<>());
                    }
                    return 0;
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

#endif // THREAD_HPP_APPLE_TREE_FLOWER_BIRD_CLOUD_RIVER_STONE_MUSIC
