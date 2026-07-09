// utility/base.hpp — thin re-export of the top-level base.hpp.
//
// Historically this header defined its own cpl::Error / IContext / ISerializeJson
// with a Win32-native (INT32 / _Out_) flavour. That duplicate cpl::Error clashed
// with the top-level base.hpp (identical include guard) whenever both were pulled
// into the same translation unit. Per "base.hpp 只保留一个", this file now
// simply re-exports the top-level base.hpp and only adds the legacy Win32-native
// aliases that win32/api.hpp (generated from sys.hpp) still references.
//
// api.hpp / sys.hpp keep their Win32-native call style (INT32 codes, _Out_
// parameters); they just consume the single authoritative cpl::Error / Result /
// IContext defined in the top-level base.hpp.

#ifndef CPL_UTILITY_BASE_HPP_REEXPORT
#define CPL_UTILITY_BASE_HPP_REEXPORT

#include "../base.hpp" // the single authoritative base header

#include <cstdint>
#include <string>
#include <windows.h>

#ifndef PASS
#define PASS do{}while(false)
#endif

#ifndef bzero
#define bzero ZeroMemory
#endif

// Cross-compiler attribute shim: api_gen.py emits the MSVC-specific
// __kernel_entry calling-convention annotation into api.hpp typedefs. MinGW gcc
// does not recognise it; no-op it on non-MSVC toolchains. (Note: __in/__out and
// other double-underscore SAL tokens are reserved for the implementation and
// MUST NOT be macro-defined — they are used internally by libstdc++. sys.hpp
// uses the _In_/_Out_ flavour instead, which base.hpp already no-ops.)
#ifndef _MSC_VER
#ifndef __kernel_entry
#define __kernel_entry
#endif
#endif

namespace cpl {
    namespace base {
        using namespace std;

        // Legacy Win32-native serialisation interface. The top-level base exposes
        // base::serialize::ISerializeJSON (ToJSON/FromJSON returning Result); the
        // hand-written api.hpp entities predate that and derive from
        // ISerializeJson with ToJson/FromJson returning string/int directly. Keep
        // this native interface available both as base::ISerializeJson and inside
        // base::serialize (for `using namespace cpl::base::serialize;` sites).
        class ISerializeJson {
        public:
            virtual ~ISerializeJson() = default;
            virtual string ToJson() = 0;
            virtual int32_t FromJson(const string &) = 0;
        };
        namespace serialize {
            using ISerializeJson = base::ISerializeJson;
        }
    }
}

#endif // CPL_UTILITY_BASE_HPP_REEXPORT
