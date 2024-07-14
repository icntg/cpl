#ifndef BASE_7O35IAG3GPSZD6XSQPLM7KG2_H
#define BASE_7O35IAG3GPSZD6XSQPLM7KG2_H

#include <string>

//单例模板
//delete 与 default 来自于 c++ 11
template<typename T>
class Singleton {
public:
    static T &GetInstance() {
        static T instance;
        return instance;
    }

    explicit Singleton(T &&) = delete;

    explicit Singleton(const T &) = delete;

    void operator=(const T &) = delete;

protected:
    Singleton() = default;

    virtual ~Singleton() = default;
};


class ISerialize {
public:
    virtual std::string json_serialize()=0;
    virtual std::string text_serialize()=0;
    virtual ~ISerialize() = default;
};

#endif //BASE_7O35IAG3GPSZD6XSQPLM7KG2_H
