//#ifndef CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY
//#define CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY
//
//#include <cstdint>
//#include <string>
//#include <memory>
//#include <mutex>
//
//#ifndef PASS
//#define PASS do{}while(false)
//#endif
//
//#ifndef bzero
//    #define bzero ZeroMemory
//#endif
//
//namespace cpl {
//    namespace base {
//        //Singleton template
//        //delete and default come from c++ 11
//        // One defect: smart pointers cannot be used inside it...
//        // Smart pointers depend on the two system functions AcquireSRWLockExclusive and ReleaseSRWLockExclusive,
//        // and XP does not have them. To stay compatible with WindowsXP, avoid using smart pointers.
//        /*
//        Usage:
//        class Logger final : public Singleton<Logger> {
//            friend class Singleton<Logger>; // so that the parent class can call the private methods of the child class
//        protected:
//            Logger() {...}
//        public:
//            ~Logger() override {...}
//        };
//         */
//        using namespace std;
//
//        template<typename T>
//        class ICritical {
//        public:
//            virtual ~ICritical() = default;
//
//            virtual int32_t Enter() = 0;
//
//            virtual int32_t Leave() = 0;
//
//            virtual T GetValue() = 0;
//
//            virtual void SetValue(T value) = 0;
//        };
//
//        /**
//         * Putting fclose and the like in the destructor reports an error (isatty.cpp line 17 xxxx)
//         * Use load / unload to load/unload manually.
//         */
//        class IContext {
//        public:
//            virtual int32_t Load() = 0;
//
//            virtual int32_t Unload() = 0;
//
//            virtual ~IContext() = default;
//        };
//
//        template<typename T>
//        class Singleton {
//
//
//        public:
//            static unique_ptr<T> &Instance() {
//                static unique_ptr<T> instance{};
//                static mutex mutex{};
//                if (nullptr == instance) {
//                    mutex.lock();
//                    if (nullptr == instance) {
//                        instance = make_unique<T>(new T);
//                    }
//                    mutex.unlock();
//                }
//                return instance;
//            }
//
//        protected:
//            Singleton() = default;
//
//            virtual ~Singleton() = default;
//        };
//
//        template<typename T>
//        class ISingletonContext : public Singleton<T>, IContext {
//            T *_instance = nullptr;
//        protected:
//            PCRITICAL_SECTION _pcs = nullptr;
//
//        public:
//            static T &Instance(
//                    const BOOL bAutoLoad = TRUE,
//                    const PCRITICAL_SECTION pCriticalSection = nullptr
//            ) {
//                // The C++11 implementation has a built-in lock, which breaks XP compatibility
//                static T *instance = nullptr;
//                if (nullptr == instance) {
//                    if (nullptr != pCriticalSection) {
//                        EnterCriticalSection(pCriticalSection);
//                    }
//                    if (nullptr == instance) {
//                        instance = new T();
//                        instance->_pcs = pCriticalSection; // Record it here; used on release.
//                        instance->_instance = instance; // Record it here; used on release.
//                        if (bAutoLoad) {
//                            instance->Load();
//                        }
//                    }
//                    if (nullptr != pCriticalSection) {
//                        LeaveCriticalSection(pCriticalSection);
//                    }
//                }
//                return *instance;
//            }
//
//            /**
//             * In fact this method does not need to be called.
//             * Letting the system reclaim the resources is enough.
//             */
//            static void Destroy() {
//                auto &t = Instance();
//                auto pcs = t._pcs;
//                if (nullptr != pcs) {
//                    EnterCriticalSection(pcs);
//                }
//                if (nullptr != t._instance) {
//                    t._instance->Unload();
//                    delete t._instance;
//                }
//                if (nullptr != pcs) {
//                    LeaveCriticalSection(pcs);
//                }
//                pcs = nullptr;
//            }
//
//            explicit ISingletonContext(T &&) = delete;
//
//            explicit ISingletonContext(const T &) = delete;
//
//            ISingletonContext &operator=(const T &) = delete;
//
//        protected:
//            ISingletonContext() = default;
//
//            ~ISingletonContext() override = default;
//        };
//
//        namespace serialize {
//            class ISerialize {
//            public:
//                virtual string Serialize() = 0;
//
//                virtual int32_t Deserialize(const string &s) = 0;
//
//                virtual ~ISerialize() = default;
//            };
//
//            class ISerializeJson : public ISerialize {
//            public:
//                virtual string ToJson() = 0;
//
//                virtual int32_t FromJson(const string &s) = 0;
//
//                string Serialize() override {
//                    return this->ToJson();
//                }
//
//                int32_t Deserialize(const string &s) override {
//                    return this->FromJson(s);
//                }
//
//                ~ISerializeJson() override = default;
//            };
//        }
//
//        namespace callback {
//            enum class FilterType {
//                NONE, ANY, ALL,
//            };
//
//            template<typename T>
//            class ICallback {
//            protected:
//                FilterType filterType{FilterType::NONE};
//                vector<int32_t> resultList{};
//
//            public:
//                virtual ~ICallback() = default;
//
//                /**
//                 * Based on the return value: if successful, decide by FilterType whether to continue.
//                 * @param obj the single object being iterated
//                 * @return ERROR_SUCCESS / other
//                 */
//                virtual int32_t Callback(_In_ T obj) = 0;
//
//                virtual bool ToBeContinued() {
//                    return true;
//                };
//
//                virtual vector<int32_t> GetResultList() {
//                    return this->resultList;
//                }
//            };
//
//            template<typename T, typename R>
//            class ICallbackReturn : public ICallback<T> {
//            public:
//                /**
//                 * Based on the return value: if successful, decide by FilterType whether to continue.
//                 * @param obj the single object being iterated
//                 * @param results can hold the result of that single object
//                 * @return ERROR_SUCCESS / other
//                 */
//                virtual int32_t Callback(_In_ T obj, _Out_opt_ vector<R> *results) = 0;
//            };
//        }
//
//        class ILogger {
//        public:
//            enum class LEVEL {
//                $TRACE = 0,
//                $DEBUG = 10,
//                $INFO = 20,
//                $WARN = 30,
//                $ERROR = 40,
//                $FATAL = 50,
//            };
//
//            virtual ~ILogger() = default;
//
//            virtual LEVEL GetLevel() = 0;
//
//            virtual void SetLevel(LEVEL level) = 0;
//
//            virtual void Trace(const char *fmt, ...) = 0;
//
//            virtual void Debug(const char *fmt, ...) = 0;
//
//            virtual void Info(const char *fmt, ...) = 0;
//
//            virtual void Success(const char *fmt, ...) = 0;
//
//            virtual void Warn(const char *fmt, ...) = 0;
//
//            virtual void Error(const char *fmt, ...) = 0;
//
//            virtual void Fatal(const char *fmt, ...) = 0;
//        };
//    }
//}
//
//#endif //CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY
