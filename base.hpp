/*
 * Base header
 * Base classes
 * Platform-independent
 * Keep STL dependencies minimal
 */

#ifndef CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY
#define CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY

#include <cstdint>
#include <vector>
#include <string>
#include <system_error>
#include <array>
#include <algorithm>
#include <memory>
#include <functional>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <stdexcept>

#include "vendor/TartanLlama/expected/expected.hpp"

#ifndef _In_
#define _In_
#endif

#ifndef _Out_
#define _Out_
#endif

#ifndef _Inout_
#define _Inout_
#endif

#ifndef PASS
#define PASS do{}while(false)
#endif

#define bzero(ptr, size) memset(ptr, 0, size)

// Helper: stringify __LINE__ (standard macro technique)
#define CPL_STRINGIZE_IMPL_(x) #x
#define CPL_STRINGIZE_(x) CPL_STRINGIZE_IMPL_(x)

#define CPL_FILE_AND_LINE "<" __FILE__ ":" CPL_STRINGIZE_(__LINE__) ">"

namespace cpl {

    // gDebug: global debug flag. C++11 has no inline variables (C++17), so we
    // expose it via an inline accessor returning a function-local static ref
    // (Meyers singleton) — ODR-safe across TUs. Usage changes: gDebug -> gDebug().
    inline std::unique_ptr<bool> &gDebug() {
        static std::unique_ptr<bool> v{};
        return v;
    }

    // Minimal error dispatch model
    class Error {
    public:
        using X32 = struct {
            uint32_t h;
            uint32_t l;
        };

        using CodeDef /* Error Code Definition */ = union {
            int64_t i64;
            uint64_t u64;

            X32 x32;

            uint16_t u16[4];
            uint8_t u8[8];
        };

        // C++11 note: ODR-safe error code constants. We use a scoped enum
        // (enum : int64_t) rather than static constexpr data members. Enum
        // enumerators are pure compile-time constants with no address, so they
        // never trigger ODR-use link errors — critical for a header-only lib
        // where static constexpr members would need out-of-class definitions
        // (impossible across multiple TUs). Call sites use them as plain
        // values, identical to the old static-member syntax:
        //   Err(Error::InvalidArgument, "...")   // unchanged, no parentheses
        enum : int64_t {
            NullPointer = ENOENT,
            NoData = ENODATA,
            OutOfRange = ERANGE,
            OutOfMemory = ENOMEM,
            InvalidArgument = EINVAL,
            UnavailableAPI = EFAULT,
            FileOpen = EROFS,
        };

        CodeDef Code{};
        std::string Reason{};
#if defined(DEBUG) && DEBUG
        // For debugging
        std::vector<std::system_error> Errors{};
#endif

        Error() = default;

        explicit Error(const int64_t code, const char *reason = nullptr) {
            this->Code.i64 = code;
            if (reason) {
                this->Reason = reason;
            }
        }

        explicit Error(const CodeDef code, const char *reason = nullptr) {
            this->Code.i64 = code.i64;
            if (reason) {
                this->Reason = reason;
            }
        }

        Error &Append(const char *a) {
            this->Reason += a;
            return *this;
        }

        ~Error() = default;
    };

    template<typename T>
    using Result = tl::expected<T, Error>;
    using Int32Result = Result<int32_t>;
    // Rust-like
#define Ok(x) do {return x;} while(0);
    // Rust-like
    using Err = tl::unexpected<Error>;
    using Stream = std::vector<uint8_t>;

    inline tl::unexpected<Error> MakeErr(const int64_t e, const char *es) {
        return Err(Error(e, es));
    }

    inline tl::unexpected<Error> MakeErr(const Error::CodeDef e, const char *es) {
        return Err(Error(e, es));
    }

    inline tl::unexpected<Error> MakeErr(const int64_t e, const std::string &es) {
        return Err(Error(e, es.data()));
    }

    inline tl::unexpected<Error> MakeErr(const Error::CodeDef e, const std::string &es) {
        return Err(Error(e, es.data()));
    }

    // inline const char *ReasonPtr(const char *msg) {
    //     return msg == nullptr ? "" : msg;
    // }
    //
    // inline const char *ReasonPtr(const std::string &msg) {
    //     return msg.c_str();
    // }

    namespace base {
        template<typename F>
        class Defer {
            F f_;

        public:
            explicit Defer(F f) : f_(std::move(f)) {
            }

            ~Defer() {
                try {
                    f_();
                } catch (...) {
                    // Log or ignore exceptions
                    // Destructors must not throw
                }
            }

            // Disable copy (prevent multiple executions)
            Defer(const Defer &) = delete;

            Defer &operator=(const Defer &) = delete;

            // Allow move (optional but recommended)
            Defer(Defer &&) noexcept = default;

            Defer &operator=(Defer &&) noexcept = default;
        };

        // Helper function (C++11-friendly)
        template<typename F>
        Defer<F> MakeDefer(F &&f) {
            return cpl::base::Defer<F>(std::forward<F>(f));
        }

#define DEFER(...) cpl::base::MakeDefer([&]() noexcept { __VA_ARGS__; })

        class IContext {
        public:
            virtual Int32Result Load() = 0;

            virtual Int32Result Unload() = 0;

            virtual bool IsLoaded() {
                return false;
            }

            virtual ~IContext() = default;
        };

        /**
         * Lock interface
         * For implementation use
         */
        class ILock {
        public:
            virtual ~ILock() = default;

            virtual Int32Result Lock() = 0;

            virtual Int32Result Unlock() = 0;
        };

        template<typename T>
        class ISingleton {
        public:
            static T &Instance() {
                static T instance; // Thread-safe (C++11+), lazy init, auto destruction
                return instance;
            }

        protected:
            ISingleton() = default;

            ~ISingleton() = default;

        public:
            ISingleton(const ISingleton &) = delete;

            ISingleton &operator=(const ISingleton &) = delete;
        };

        namespace callback {
            using Identity = std::string;

            //             template<typename T>
            //             class Result {
            //             public:
            //                 int32_t RetCode{};
            // #if defined(DEBUG) && DEBUG
            //                 std::unique_ptr<T> Element{}; // Called object, if copyable.
            //                 base::callback::Identity Identity{};
            //                 std::unique_ptr<std::exception> Exception{};
            // #endif
            //             };

            template<typename T, typename R>
            class ICallback {
                Identity identity{};

            public:
                explicit ICallback(const Identity &identity) {
                    this->identity = identity;
                }

                virtual ~ICallback() = default;

                std::string GetIdentity() const {
                    return this->identity;
                }

                /**
                 * Based on return value; on success, use FilterType to decide whether to continue.
                 * @param obj Single object in iteration
                 * @return ERROR_SUCCESS / other
                 */
                virtual R Callback(T &obj) = 0;

                virtual bool ToBeContinued() {
                    return true;
                }
            };
        }

        namespace serialize {
            class ISerialize {
            public:
                virtual ~ISerialize() = default;

                virtual Result<Stream> Serialize() = 0;

                virtual Int32Result Unserialize(const Stream &in) = 0;
            };

            class ISerializeJSON {
            public:
                virtual ~ISerializeJSON() = default;

                virtual Result<std::string> ToJSON() = 0;

                virtual Int32Result FromJSON(const std::string &in) = 0;
            };
        }

        namespace log {
            // exLoggerFunc: pluggable logger sink (for LOG_D). C++11 has no inline
            // variables, so expose via inline accessor (Meyers singleton).
            // Usage: exLoggerFunc -> exLoggerFunc(); assignment exLoggerFunc() = fn;
            //        invocation exLoggerFunc()(msg).
            typedef void (*ExLoggerFunc)(const std::string &out);
            inline ExLoggerFunc &exLoggerFunc() {
                static ExLoggerFunc v = nullptr;
                return v;
            }

            template<typename Callable>
            void once(Callable &&logFunc) {
                static bool onlyOnce = true;
                if (onlyOnce) {
                    onlyOnce = false;
                    std::forward<Callable>(logFunc)();
                }
            }

            template<typename Callable>
            void limit(Callable &&logFunc, const uint32_t limit = 1800, const uint32_t timeout = 3600) {
                static uint32_t counter = 0;
                static time_t timestamp = time(nullptr);
                static bool first = true; // Always log on first call

                bool isTimeUp = false;
                bool isCounterOut = false;
                const auto currentTime = time(nullptr);


                if (currentTime - timestamp >= timeout) {
                    isTimeUp = true;
                }
                if (counter + 1 > limit) {
                    isCounterOut = true;
                }

                if (isTimeUp || isCounterOut || first) {
                    first = false;
                    std::forward<Callable>(logFunc)(isTimeUp, isCounterOut);
                    timestamp = currentTime;
                    counter = 0;
                }
            }
        }

        // namespace exc {
        //     class Category : public std::error_category {
        //     public:
        //         Category() = default;
        //
        //         ~Category() override = default;
        //
        //         const char *name() const noexcept override { return "cpl"; }
        //
        //         std::string message(const int ev) const override {
        //             switch (ev) {
        //                 default: return "Unknown error";
        //             }
        //         }
        //     };
        //
        //     class Exception : public std::system_error {
        //     protected:
        //         uint32_t mAppCode{}; // App-defined error code; used to control log frequency.
        //         std::array<char, 1024> mLoc{};
        //
        //     public:
        //         using std::system_error::system_error;
        //
        //         Exception() = delete;
        //
        //         explicit Exception(
        //             const uint32_t appCode,
        //             const int ErrVal,
        //             const std::error_category &ErrCat,
        //             const char *Message,
        //             const char *loc
        //         ) noexcept : system_error(ErrVal, ErrCat, Message),
        //                      mAppCode(appCode) {
        //             const auto copySize = (((strlen(loc)) < (sizeof(this->mLoc) - 1))
        //                                        ? (strlen(loc))
        //                                        : (sizeof(this->mLoc) - 1));
        //             memcpy(this->mLoc.data(), loc, copySize);
        //             this->mLoc[copySize] = '\0';
        //         }
        //
        //         explicit Exception(
        //             const uint32_t appCode,
        //             const int ErrVal,
        //             const std::error_category &ErrCat,
        //             const std::string &Message,
        //             const char *loc
        //         ) noexcept : system_error(ErrVal, ErrCat, Message),
        //                      mAppCode(appCode) {
        //             const auto copySize = (((strlen(loc)) < (sizeof(this->mLoc) - 1))
        //                                        ? (strlen(loc))
        //                                        : (sizeof(this->mLoc) - 1));
        //             memcpy(this->mLoc.data(), loc, copySize);
        //             this->mLoc[copySize] = '\0';
        //         }
        //
        //         ~Exception() noexcept override = default;
        //
        //         const char *what() const noexcept override {
        //             thread_local std::string buf;
        //             buf = std::system_error::what();
        //             if (strlen(this->mLoc.data()) > 0) {
        //                 buf.append(" ");
        //                 buf.append(this->mLoc.data());
        //             }
        //             return buf.c_str();
        //         }
        //
        //         uint32_t GetAppCode() const noexcept {
        //             return this->mAppCode;
        //         }
        //     };
        // }

        namespace stl {
            // DynamicUniquePtrCast is a safe downcast helper for std::unique_ptr,
            // with support for custom deleters, converting unique_ptr<Base> to unique_ptr<Derived>.
            template<typename Derived, typename Base, typename Deleter = std::default_delete<Derived> >
            std::unique_ptr<Derived, Deleter>
            DynamicUniquePtrCast(std::unique_ptr<Base, Deleter> &&base_ptr) {
                if (!base_ptr) {
                    return nullptr;
                }
                if (auto *derived = dynamic_cast<Derived *>(base_ptr.get())) {
                    base_ptr.release();
                    return std::unique_ptr<Derived, Deleter>(derived);
                }
                return nullptr; // base_ptr still owns the original object
            }
        }
    }
}


//
// #define DEF_EXC(ExcName) \
// class ExcName : public cpl::base::exc::Exception { \
// public: \
//     using Exception::Exception; \
//     ExcName() = delete; \
//     ~ExcName() noexcept override = default; \
// };
//
// #define TRW_EXC(excType, appCode, errVal, msg) \
// do { \
//     const char *loc = "<" __FILE__ ":" CPL__STRINGIZE(__LINE__) ">"; \
//     throw excType(appCode, errVal, cpl::base::exc::Category(), msg, loc); \
// } while(0)
//
// namespace cpl {
//     namespace base {
//         namespace exc {
//             DEF_EXC(ErrorNullPointer);
//
//             DEF_EXC(ErrorNoData);
//
//             DEF_EXC(ErrorOutOfRange);
//
//             DEF_EXC(ErrorOutOfMemory);
//
//             DEF_EXC(ErrorInvalidArgument);
//
//             DEF_EXC(ErrorApplicationProgrammingInterfaceUnavailable);
//
//             DEF_EXC(ErrorFileOpen);
//         }
//     }
// }

// #define MAKE_EXCEPTION(appErrCode, rawErrCode, cat, msg) \
//     cpl::base::exc::Exception(appErrCode, rawErrCode, cat, msg, std::string("{") + __FILE__ + ":" + std::to_string(__LINE__) + "}")

#endif //CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY
