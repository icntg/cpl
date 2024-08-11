#ifndef BASE_7O35IAG3GPSZD6XSQPLM7KG2_H
#define BASE_7O35IAG3GPSZD6XSQPLM7KG2_H

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <windows.h>

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

template <typename T>
class Singleton
{
    T* _instance = nullptr;
    PCRITICAL_SECTION _pcs = nullptr;
public:
    static T& Instance(const PCRITICAL_SECTION pCriticalSection = nullptr)
    {
        // C++11实现方式自带锁，会导致不兼容XP
        static T* instance = nullptr;
        if (nullptr == instance)
        {
            if (nullptr != pCriticalSection)
            {
                EnterCriticalSection(pCriticalSection);

            }
            if (nullptr == instance)
            {
                instance = new T();
                instance->_instance = instance; // 记录一下，释放时使用。
                instance->_pcs = pCriticalSection; // 记录一下，释放时使用。
            }
            if (nullptr != pCriticalSection)
            {
                LeaveCriticalSection(pCriticalSection);
            }
        }
        return *instance;
    }

    /**
     * 实际上该方法不需要调用。
     * 由系统回收资源即可。
     */
    static void Destory()
    {
        auto& t = Instance();
        auto pcs = t._pcs;
        if (nullptr != pcs)
        {
            EnterCriticalSection(pcs);
        }
        if (nullptr != t._instance)
        {
            delete t._instance;
        }
        if (nullptr != pcs)
        {
            LeaveCriticalSection(pcs);
        }
        pcs = nullptr;
    }

    explicit Singleton(T&&) = delete;
    explicit Singleton(const T&) = delete;
    Singleton& operator=(const T&) = delete;

protected:
    Singleton() = default;
    virtual ~Singleton() = default;
};


class ISerialize
{
public:
    virtual std::string Serialize() =0;
    virtual int32_t Deserialize(const std::string& s) =0;
    virtual ~ISerialize() = default;
};

class ISerializeJson : public ISerialize
{
};

/**
 * fclose等操作放在析构函数中会报错（isatty.cpp line 17 xxxx）
 * 使用 load / unload 手动加载/卸载。
 */
class IContext
{
public:
    virtual int32_t Load() =0;
    virtual int32_t Unload() =0;
    virtual ~IContext() = default;
};

#endif //BASE_7O35IAG3GPSZD6XSQPLM7KG2_H
