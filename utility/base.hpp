#ifndef CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY
#define CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY

#include <cstdint>
#include <string>
#include <windows.h>

#ifndef PASS
#define PASS do{}while(false)
#endif

namespace cpl {
    namespace base {
        //单例模板
        //delete 与 default 来自于 c++ 11
        // 有一个缺陷，无法在其中使用智能指针…
        // 智能指针依赖AcquireSRWLockExclusive与ReleaseSRWLockExclusive这两个系统函数，
        // 而XP中没有这两个函数。如果需要兼容WindowsXP的话，需要避免使用智能指针。
        /*
        使用方式：
        class Logger final : public Singleton<Logger> {
            friend class Singleton<Logger>; // 父类可以调用子类的私有方法
        protected:
            Logger() {...}
        public:
            ~Logger() override {...}
        };
         */
        using namespace std;

        template<typename T>
        class ICritical {
        public:
            virtual ~ICritical() = default;

            virtual int32_t Enter() = 0;

            virtual int32_t Leave() = 0;

            virtual T GetValue() = 0;

            virtual void SetValue(T value) = 0;
        };

        /**
         * fclose等操作放在析构函数中会报错（isatty.cpp line 17 xxxx）
         * 使用 load / unload 手动加载/卸载。
         */
        class IContext {
        public:
            virtual int32_t Load() = 0;

            virtual int32_t Unload() = 0;

            virtual ~IContext() = default;
        };

        template<typename T>
        class Singleton {
            T *_instance = nullptr;
            PCRITICAL_SECTION _pcs = nullptr;

        public:
            static T &Instance(
                const PCRITICAL_SECTION pCriticalSection = nullptr
            ) {
                // C++11实现方式自带锁，会导致不兼容XP
                static T *instance = nullptr;
                if (nullptr == instance) {
                    if (nullptr != pCriticalSection) {
                        EnterCriticalSection(pCriticalSection);
                    }
                    if (nullptr == instance) {
                        instance = new T();
                        instance->_instance = instance; // 记录一下，释放时使用。
                        instance->_pcs = pCriticalSection; // 记录一下，释放时使用。
                    }
                    if (nullptr != pCriticalSection) {
                        LeaveCriticalSection(pCriticalSection);
                    }
                }
                return *instance;
            }

            /**
             * 实际上该方法不需要调用。
             * 由系统回收资源即可。
             */
            static void Destroy() {
                auto &t = Instance();
                auto pcs = t._pcs;
                if (nullptr != pcs) {
                    EnterCriticalSection(pcs);
                }
                if (nullptr != t._instance) {
                    delete t._instance;
                }
                if (nullptr != pcs) {
                    LeaveCriticalSection(pcs);
                }
                pcs = nullptr;
            }

            //    explicit Singleton(T &&) = delete;

            //    explicit Singleton(const T &) = delete;

            //    virtual Singleton &operator=(const T &) = delete;

        protected:
            Singleton() = default;

            virtual ~Singleton() = default;
        };

        template<typename T>
        class ISingletonContext : public Singleton<T>, IContext {
            T *_instance = nullptr;
            PCRITICAL_SECTION _pcs = nullptr;

        public:
            static T &Instance(
                const PCRITICAL_SECTION pCriticalSection = nullptr
            ) {
                // C++11实现方式自带锁，会导致不兼容XP
                static T *instance = nullptr;
                if (nullptr == instance) {
                    if (nullptr != pCriticalSection) {
                        EnterCriticalSection(pCriticalSection);
                    }
                    if (nullptr == instance) {
                        instance = new T();
                        instance->_pcs = pCriticalSection; // 记录一下，释放时使用。
                        instance->_instance = instance; // 记录一下，释放时使用。
                        instance->Load();
                    }
                    if (nullptr != pCriticalSection) {
                        LeaveCriticalSection(pCriticalSection);
                    }
                }
                return *instance;
            }

            /**
             * 实际上该方法不需要调用。
             * 由系统回收资源即可。
             */
            static void Destroy() {
                auto &t = Instance();
                auto pcs = t._pcs;
                if (nullptr != pcs) {
                    EnterCriticalSection(pcs);
                }
                if (nullptr != t._instance) {
                    t._instance->Unload();
                    delete t._instance;
                }
                if (nullptr != pcs) {
                    LeaveCriticalSection(pcs);
                }
                pcs = nullptr;
            }

            explicit ISingletonContext(T &&) = delete;

            explicit ISingletonContext(const T &) = delete;

            ISingletonContext &operator=(const T &) = delete;

        protected:
            ISingletonContext() = default;

            ~ISingletonContext() override = default;
        };


        namespace serialize {
            class ISerialize {
            public:
                virtual std::string Serialize() const = 0;

                virtual int32_t Deserialize(const std::string &s) = 0;

                virtual ~ISerialize() = default;
            };

            class ISerializeJson : public ISerialize {
            };
        }

        namespace callback {
            enum class FilterType {
                NONE, ANY, ALL,
            };

            template<typename T>
            class ICallback {
            protected:
                FilterType filterType{FilterType::NONE};

            public:
                virtual ~ICallback() = default;

                /**
                 * 根据返回值，如果成功，再根据 FilterType 判断是否需要继续。
                 * @param obj
                 * @return ERROR_SUCCESS / other
                 */
                virtual int32_t Callback(_In_ T obj) = 0;

                virtual bool ToBeContinued() = 0;
            };
        }


        class ILogger {
        public:
            enum class LEVEL {
                $TRACE = 0,
                $DEBUG = 10,
                $INFO = 20,
                $WARN = 30,
                $ERROR = 40,
                $FATAL = 50,
            };

            virtual ~ILogger() = default;

            virtual LEVEL GetLevel() = 0;

            virtual void SetLevel(LEVEL level) = 0;

            virtual void Trace(const char *fmt, ...) = 0;

            virtual void Debug(const char *fmt, ...) = 0;

            virtual void Info(const char *fmt, ...) = 0;

            virtual void Success(const char *fmt, ...) = 0;

            virtual void Warn(const char *fmt, ...) = 0;

            virtual void Error(const char *fmt, ...) = 0;

            virtual void Fatal(const char *fmt, ...) = 0;
        };
    }
}

#endif //CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY
