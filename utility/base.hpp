#ifndef BASE_7O35IAG3GPSZD6XSQPLM7KG2_H
#define BASE_7O35IAG3GPSZD6XSQPLM7KG2_H

#include <cstdint>
#include <string>
#include <memory>

//单例模板
//delete 与 default 来自于 c++ 11
// 有一个缺陷，无法在其中使用智能指针…
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
template <typename T>
class Singleton
{
public:
    static T& GetInstance()
    {
        static T instance;
        return instance;
    }

    explicit Singleton(T&&) = delete;

    explicit Singleton(const T&) = delete;

    void operator=(const T&) = delete;

protected:
    Singleton() = default;

    virtual ~Singleton() = default;
};


class ISerialize
{
public:
    virtual std::string serialize() =0;
    virtual int32_t deserialize(const std::string& s) =0;
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
    virtual int32_t load() =0;
    virtual int32_t unload() =0;
    virtual ~IContext() = default;
};

#endif //BASE_7O35IAG3GPSZD6XSQPLM7KG2_H
