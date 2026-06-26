#ifndef CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY
#define CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY

#include <cstdint>
#include <string>
#include <windows.h>

#ifndef PASS
#define PASS do{}while(false)
#endif

#ifndef bzero
#define bzero ZeroMemory
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
            virtual bool IsLoaded() = 0;

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

        protected:
            PCRITICAL_SECTION _pcs = nullptr;

        public:
            static T &Instance(
                const BOOL bAutoLoad = TRUE,
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
                        if (bAutoLoad) {
                            instance->Load();
                        }
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
                virtual string Serialize() = 0;

                virtual int32_t Deserialize(const string &s) = 0;

                virtual ~ISerialize() = default;
            };

            class ISerializeJson : public ISerialize {
            public:
                virtual string ToJson() = 0;

                virtual int32_t FromJson(const string &s) = 0;

                string Serialize() override {
                    return this->ToJson();
                }

                int32_t Deserialize(const string &s) override {
                    return this->FromJson(s);
                }

                ~ISerializeJson() override = default;
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
                vector<int32_t> resultList{};

            public:
                virtual ~ICallback() = default;

                /**
                 * 根据返回值，如果成功，再根据 FilterType 判断是否需要继续。
                 * @param obj 遍历中的单个对象
                 * @return ERROR_SUCCESS / other
                 */
                virtual int32_t Callback(_In_ T obj) = 0;

                virtual bool ToBeContinued() {
                    return true;
                };

                virtual vector<int32_t> GetResultList() {
                    return this->resultList;
                }
            };

            template<typename T, typename R>
            class ICallbackReturn : public ICallback<T> {
            public:
                /**
                 * 根据返回值，如果成功，再根据 FilterType 判断是否需要继续。
                 * @param obj 遍历中的单个对象
                 * @param results 可以存放该单个对象的结果
                 * @return ERROR_SUCCESS / other
                 */
                virtual int32_t Callback(_In_ T obj, _Out_opt_ vector<R> *results) = 0;
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

        namespace crypto {
            class IRandom {
            public:
                virtual ~IRandom() = default;

                virtual INT32 Rand(_In_ LPCVOID buffer, _In_ size_t size) = 0;

                virtual vector<uint8_t> Rand(_In_ size_t size) {
                    auto buffer = vector<uint8_t>();
                    buffer.resize(size);
                    this->Rand(buffer.data(), size);
                    return buffer;
                }
            };

            class IHash {
            public:
                virtual ~IHash() = default;

                virtual INT32 Update(_In_ const vector<BYTE> &data) = 0;

                virtual INT32 Summary(_Out_ vector<BYTE> &out) = 0;
            };

            class IAsync {
            public:
                virtual ~IAsync() = default;

                virtual INT32 Encrypt(
                    _Out_ vector<BYTE> &out,
                    _In_ const vector<BYTE> &publicKey,
                    _In_ const vector<BYTE> &cleared
                ) = 0;

                virtual INT32 Decrypt(
                    _Out_ vector<BYTE> &out,
                    _In_ const vector<BYTE> &privateKey,
                    _In_ const vector<BYTE> &encrypted
                ) = 0;

                virtual INT32 Sign(
                    _Out_ vector<BYTE> &out,
                    _In_ const vector<BYTE> &privateKey,
                    _In_ const vector<BYTE> &encrypted
                ) = 0;

                virtual INT32 Verify(
                    _Out_ BOOL &out,
                    _In_ const vector<BYTE> &publicKey,
                    _In_ const vector<BYTE> &data
                ) = 0;
            };

            class ISync {
            public:
                virtual ~ISync() = default;

                virtual INT32 Encrypt(
                    _Out_ vector<BYTE> &out,
                    _In_ const vector<BYTE> &cleared
                ) = 0;

                virtual INT32 Decrypt(
                    _Out_ vector<BYTE> &out,
                    _In_ const vector<BYTE> &encrypted
                ) = 0;
            };

            class ICryptoFactory {
            public:
                virtual ~ICryptoFactory() = default;

                virtual INT32 CreateHMACProvider(
                    _In_ const vector<BYTE> &key,
                    _Out_ IHash *&out
                ) = 0;

                virtual INT32 CreateSyncProvider(
                    _In_ const vector<BYTE> &key,
                    _Out_ ISync *&out
                ) = 0;
            };

            class ICrypto : public ISync {
            public:
                static INT32 EncodeLength(_Out_ vector<BYTE> &out, _In_ const int64_t length) {
                    int32_t retCode = 0;
                    // string s;
                    static int64_t _max_ = 1;
                    if (1 == _max_) {
                        _max_ = _max_ << 42;
                    }
                    if (length < 0 || length >= _max_) {
                        return EINVAL;
                    }
                    out.clear();
                    if (length < 128) {
                        out.push_back(static_cast<uint8_t>(length));
                        return 0;
                    }
                    uint8_t buffer[8] = {};
                    int idx = 0; {
                        int64_t n = length;

                        while (n > 0) {
                            const int64_t fn = n & 0x3f;
                            n = n >> 6;
                            int64_t v = static_cast<uint8_t>((0x80 | fn) & 0xbf);
                            buffer[idx] = v;
                            idx++;
                            const int64_t hlc = 8 - idx - 2;
                            if (n >= (1 << hlc)) {
                                continue;
                            }
                            const int64_t hh = ((1 << (idx + 1)) - 1) << (hlc + 1);
                            const int64_t hb = hh | n;
                            buffer[idx] = static_cast<uint8_t>(hb);
                            idx++;
                            break;
                        }
                    }
                    if (idx > 6) {
                        return EINVAL;
                    }
                    out.resize(idx);
                    for (auto i = 0; i < idx; i++) {
                        const auto j = idx - i - 1;
                        out[j] = buffer[i];
                    }
                    return 0;
                }

                static INT32 DecodeLength(_Out_ uint64_t &out, _Out_ size_t &nBytes, _In_ const vector<BYTE> &stream) {
                    if (stream.size() < 1) {
                        return EADDRNOTAVAIL;
                    }
                    const uint8_t header = stream[0];
                    if (stream[0] >> 7 == 0) {
                        out = header;
                        nBytes = 1;
                        return 0;
                    }
                    size_t n = 0;
                    for (size_t i = 0; i < 7; i++) {
                        const size_t rn = 7 - i;
                        if (((header >> rn) & 1u) == 0u) {
                            n = i;
                            break;
                        }
                    }
                    if (n == 0) {
                        return EINVAL;
                    }
                    if (stream.size() < n) {
                        return EINVAL;
                    }
                    int64_t tail = 0;
                    for (size_t i = 1; i < n; i++) {
                        if (stream[i] >> 6 != 2) {
                            return -static_cast<int64_t>(i) - 1;
                        }
                        tail = (tail << 6) | (stream[i] & 0x3f);
                    }
                    const uint8_t mask = (1 << (8 - n)) - 1;
                    const int64_t offset = 6 * (n - 1);
                    out = ((header & mask) << offset) | tail;
                    nBytes = n;
                    return 0;
                }
            };
        }
    }
}

#endif //CPL_BASE_H_UNDERSCORE_EXEMPLARY_CONVERSATION_NEIGHBORHOOD_DOCUMENTATION_STRATEGY_ANALYSIS_EXEMPLARY
