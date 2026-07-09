// utility/strings.hpp — thin re-export of the top-level strings.hpp.
//
// Per "base.hpp 只保留一个", the duplicate cpl::Error / Format / etc. that this
// file used to define (with an identical include guard) is removed; it now just
// pulls in the authoritative top-level strings.hpp. win32/api.hpp derives its
// Format/Hex/Join/Unhex/Base64Encode string-returning shims from cpl::win32
// (defined inside api.hpp itself) so unqualified lookup resolves to the native
// string flavour the hand-written entities expect.

#ifndef CPL_UTILITY_STRINGS_HPP_REEXPORT
#define CPL_UTILITY_STRINGS_HPP_REEXPORT

#include "../strings.hpp" // the single authoritative strings header

#include <string>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <tchar.h>
#include <vector>

using namespace std;

#endif // CPL_UTILITY_STRINGS_HPP_REEXPORT
