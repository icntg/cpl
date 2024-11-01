#ifndef IFW_FORMAT_HPP
#define IFW_FORMAT_HPP

#include <string>
#include <vector>
#include <string.h>
#include <stdarg.h>

using namespace std;

template <class T>
inline void ToString(std::string & ret, T && val)
{
    ret.append(std::to_string(std::forward<T>(val)));
}

inline void ToString(std::string & ret, const std::string & val)
{
    ret.append(val);
}

inline void ToString(std::string & ret, const char * val)
{
    ret.append(val);
}

template <int N>
struct SFormatN {
    static std::string Format(const char * fmt)
    {
        static_assert(false, "");
    }
};

template <>
struct SFormatN<0> {
    template <class ...ARGS>
    static std::string Format(const char * fmt, const std::tuple<ARGS...> &)
    {
        return fmt;
    }
};

template <class ...ARGS>
string format(const char *tpl, ...) {
// todo
// https://github.com/mmc1993/sformat/blob/master/src/sformat.h
    va_list args;
    va_start(args, tpl);
    va_arg(args, )
//    for (int i = 0; i < count; i++) {
//        printf("%d ", va_arg(args, int));
//    }
    va_end(args);
}

#endif //IFW_FORMAT_HPP
