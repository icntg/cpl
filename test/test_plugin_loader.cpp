// Tests for cpl::plugin (plugin_loader.hpp): the shared library loader behind the plugin ABI.
//
// No plugin library is linked into the test binary, so the plugin part of the contract
// (IfwPluginQuery and the API version check) is exercised through impl::QueryPlugin with a fake
// query function, and the loader itself on the system library of the running system.
#include "../vendor/doctest/doctest.hpp"
#include "../plugin_loader.hpp"

#include <cstring>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <windows.h>
#endif

using cpl::plugin::Loader;

template <typename T>
static T Must(cpl::Result<T> r) {
    REQUIRE(r.has_value());
    return std::move(r.value());
}

static int64_t CodeOf(const cpl::Error &error) {
    return error.Code.i64;
}

// Every reason of the loader ends with the CPL_FILE_AND_LINE of plugin_loader.hpp,
// that is with "<...plugin_loader.hpp:line>".
static bool EndsWithLocation(const cpl::Error &error) {
    const std::string &reason = error.Reason;
    const size_t open = reason.rfind('<');
    if (open == std::string::npos || reason.empty() || reason.back() != '>') {
        return false;
    }
    const size_t close = reason.size() - 1;
    // The last colon: a path of Windows has a colon after its drive letter.
    const size_t colon = reason.rfind(':', close);
    if (colon == std::string::npos || colon <= open + 1 || close <= colon + 1) {
        return false;
    }
    const std::string file = reason.substr(open + 1, colon - open - 1);
    const size_t header = file.rfind("plugin_loader.hpp");
    if (header == std::string::npos || header + std::strlen("plugin_loader.hpp") != file.size()) {
        return false;
    }
    for (size_t i = colon + 1; i < close; i++) {
        if (reason[i] < '0' || reason[i] > '9') {
            return false;
        }
    }
    return true;
}

TEST_SUITE("cpl::plugin::loader") {
#if defined(_WIN32)
    // kernel32.dll is the system library of the test on Windows.
    typedef DWORD (WINAPI *SystemSymbolFn)();
    static const char *const kSystemLibrary = "kernel32.dll";
    static const char *const kSystemSymbol = "GetCurrentProcessId";
    static const char *const kMissingLibrary = "C:\\no\\such\\dir\\cpl_test_missing_plugin.dll";
    // The reason carries the code of the failure in its text. The text of the system itself
    // depends on the language of Windows, so the test does not look at it.
    static const char *const kMissingLibraryText = "failed [0x7e]:";
#else
    // libc is the system library of the test on POSIX.
    typedef size_t (*SystemSymbolFn)(const char *);
    static const char *const kSystemSymbol = "strlen";
    static const char *const kMissingLibrary = "/no/such/dir/cpl_test_missing_plugin.so";
    // What dlerror() says about a file that does not exist.
    static const char *const kMissingLibraryText = "No such file or directory";
#endif

    // Opens the system library into `loader` and returns the name that worked.
    static std::string OpenSystemLibrary(Loader &loader) {
#if defined(_WIN32)
        REQUIRE(loader.Open(kSystemLibrary).has_value());
        return kSystemLibrary;
#else
        // musl, the system this suite is written for, ships the C library as libc.so;
        // glibc systems only have it under the soname libc.so.6.
        for (const char *const name : {"libc.so", "libc.so.6"}) {
            if (loader.Open(name).has_value()) {
                return name;
            }
        }
        REQUIRE_MESSAGE(false, "neither libc.so nor libc.so.6 could be opened");
        return std::string();
#endif
    }

    // Move assignment behind a function boundary, so that the compiler does not see which
    // objects it is called with.
    static void MoveAssign(Loader &to, Loader &from) {
        to = std::move(from);
    }

    // A stand-in for the IfwPluginQuery of a real plugin: it records what the host handed in
    // and answers the way the test asked.
    struct FakePlugin {
        IfwPluginInfo handedIn{}; // the struct as the host passed it
        int result{IFW_PLUGIN_OK}; // the value returned to the host
        uint32_t apiVersion{IFW_PLUGIN_API_VERSION}; // the version the fake plugin reports
    };
    static FakePlugin g_fake{};

    static int IFW_PLUGIN_CALL FakeQuery(IfwPluginInfo *out_info) {
        if (out_info == nullptr) {
            return IFW_PLUGIN_ERROR_INVALID_ARG;
        }
        g_fake.handedIn = *out_info;
        // Like the demo plugins: refuse a struct that is smaller than the one the plugin knows.
        if (out_info->cb < sizeof(IfwPluginInfo)) {
            return IFW_PLUGIN_ERROR_INVALID_ARG;
        }
        std::memset(out_info, 0, sizeof(*out_info));
        out_info->cb = static_cast<uint32_t>(sizeof(*out_info));
        out_info->plugin_api_version = g_fake.apiVersion;
        out_info->name = "fake-plugin";
        out_info->version = "9.9.9";
        out_info->flags = 0x5a5a5a5au;
        return g_fake.result;
    }

    TEST_CASE("IFW_PLUGIN_API_VERSION is 0x00010002") {
        CHECK_EQ(IFW_PLUGIN_API_VERSION, 0x00010002u);
    }

    TEST_CASE("EntrySymbolNames gives the name of the ABI and, on 32-bit x86 Windows, the decorated name") {
        // MSVC exports a stdcall function of a 32-bit x86 library under a decorated name when
        // the build has no module definition file. Both entry points of a plugin take one
        // pointer, so the decoration ends in the size of a pointer.
        const std::vector<std::string> names = cpl::plugin::EntrySymbolNames("IfwPluginQuery");
        REQUIRE(names.size() >= 1);
        CHECK(names[0] == "IfwPluginQuery");
#if defined(_WIN32) && defined(_M_IX86)
        REQUIRE(names.size() == 2);
        CHECK(names[1] == "_IfwPluginQuery@4");
#else
        CHECK(names.size() == 1);
#endif
    }

    TEST_CASE("EntrySymbol resolves an exported symbol and names the name of the ABI when none exists") {
        Loader loader{};
        OpenSystemLibrary(loader);
        const auto symbol = cpl::plugin::EntrySymbol<SystemSymbolFn>(loader, kSystemSymbol);
        REQUIRE(symbol.has_value());

        // No form of the name exists in the system library. The reason names the name of the
        // ABI, not a decorated form of it.
        const auto missing = cpl::plugin::EntrySymbol<SystemSymbolFn>(loader, "CplNoSuchEntryPoint");
        REQUIRE_FALSE(missing.has_value());
        CHECK(missing.error().Reason.find("CplNoSuchEntryPoint") != std::string::npos);
        CHECK(missing.error().Reason.find("_CplNoSuchEntryPoint@") == std::string::npos);
    }

    TEST_CASE("Open and Symbol resolve a symbol of the system library") {
        Loader loader{};
        CHECK_FALSE(loader.IsOpen());
        CHECK(loader.Path().empty());

        const std::string library = OpenSystemLibrary(loader);
        CHECK(loader.IsOpen());
        CHECK_EQ(loader.Path(), library);

        const auto symbol = loader.Symbol<SystemSymbolFn>(kSystemSymbol);
        REQUIRE(symbol.has_value());
#if defined(_WIN32)
        CHECK_EQ(symbol.value()(), GetCurrentProcessId());
#else
        CHECK_EQ(symbol.value()("plugin_loader"), static_cast<size_t>(13));
#endif

        // Close releases the library and empties the loader.
        loader.Close();
        CHECK_FALSE(loader.IsOpen());
        CHECK(loader.Path().empty());
    }

    TEST_CASE("Symbol fails when no library is open") {
        Loader loader{};

        // Before Open.
        auto symbol = loader.Symbol<SystemSymbolFn>(kSystemSymbol);
        CHECK_FALSE(symbol.has_value());
        CHECK_EQ(CodeOf(symbol.error()), static_cast<int64_t>(cpl::Error::InvalidArgument));
        CHECK(EndsWithLocation(symbol.error()));

        // After Close.
        OpenSystemLibrary(loader);
        loader.Close();
        symbol = loader.Symbol<SystemSymbolFn>(kSystemSymbol);
        CHECK_FALSE(symbol.has_value());
        CHECK_EQ(CodeOf(symbol.error()), static_cast<int64_t>(cpl::Error::InvalidArgument));
        CHECK(EndsWithLocation(symbol.error()));
    }

    TEST_CASE("Open rejects an empty path") {
        Loader loader{};
        const auto r0 = loader.Open("");
        CHECK_FALSE(r0.has_value());
        CHECK_EQ(CodeOf(r0.error()), static_cast<int64_t>(cpl::Error::InvalidArgument));
        CHECK(EndsWithLocation(r0.error()));
        CHECK_FALSE(loader.IsOpen());
        CHECK(loader.Path().empty());
    }

    TEST_CASE("Open of a missing library fails with the text of the system") {
        Loader loader{};
        const auto r0 = loader.Open(kMissingLibrary);
        CHECK_FALSE(r0.has_value());
        CHECK_EQ(CodeOf(r0.error()), static_cast<int64_t>(cpl::Error::FileOpen));
        // The reason carries the path, what the system said about it, and the location.
        CHECK(r0.error().Reason.find(kMissingLibrary) != std::string::npos);
        CHECK(r0.error().Reason.find(kMissingLibraryText) != std::string::npos);
        CHECK(EndsWithLocation(r0.error()));
        // A failed Open leaves nothing behind.
        CHECK_FALSE(loader.IsOpen());
        CHECK(loader.Path().empty());
    }

    TEST_CASE("Open fails while a library is open") {
        Loader loader{};
        const std::string library = OpenSystemLibrary(loader);

        const auto second = loader.Open(kMissingLibrary);
        CHECK_FALSE(second.has_value());
        CHECK_EQ(CodeOf(second.error()), static_cast<int64_t>(cpl::Error::InvalidArgument));
        CHECK(EndsWithLocation(second.error()));
        // The library that is already open is untouched.
        CHECK(loader.IsOpen());
        CHECK_EQ(loader.Path(), library);
        CHECK(loader.Symbol<SystemSymbolFn>(kSystemSymbol).has_value());
    }

    TEST_CASE("Symbol of a missing symbol fails and keeps the library open") {
        Loader loader{};
        const std::string library = OpenSystemLibrary(loader);

        const char *missing = "cpl_test_symbol_that_does_not_exist";
        const auto symbol = loader.Symbol<SystemSymbolFn>(missing);
        CHECK_FALSE(symbol.has_value());
        CHECK_EQ(CodeOf(symbol.error()), static_cast<int64_t>(cpl::Error::UnavailableAPI));
        CHECK(symbol.error().Reason.find(missing) != std::string::npos);
        CHECK(EndsWithLocation(symbol.error()));

        // An empty name is rejected as well.
        const auto empty = loader.Symbol<SystemSymbolFn>("");
        CHECK_FALSE(empty.has_value());
        CHECK_EQ(CodeOf(empty.error()), static_cast<int64_t>(cpl::Error::InvalidArgument));

        // The library stays open and keeps resolving.
        CHECK(loader.IsOpen());
        CHECK_EQ(loader.Path(), library);
        CHECK(loader.Symbol<SystemSymbolFn>(kSystemSymbol).has_value());
    }

    TEST_CASE("Close is safe to call twice") {
        Loader loader{};
        // A loader that never opened.
        loader.Close();
        CHECK_FALSE(loader.IsOpen());
        loader.Close();
        CHECK_FALSE(loader.IsOpen());

        // A loader that opened.
        OpenSystemLibrary(loader);
        loader.Close();
        loader.Close();
        CHECK_FALSE(loader.IsOpen());
        CHECK(loader.Path().empty());

        // The loader is reusable afterwards.
        OpenSystemLibrary(loader);
        CHECK(loader.IsOpen());
        CHECK(loader.Symbol<SystemSymbolFn>(kSystemSymbol).has_value());
    }

    TEST_CASE("move semantics transfer the handle and leave the source closed") {
        Loader source{};
        const std::string library = OpenSystemLibrary(source);

        // Move construction: the target owns the handle, the source owns nothing.
        Loader owner = std::move(source);
        CHECK(owner.IsOpen());
        CHECK_EQ(owner.Path(), library);
        CHECK(owner.Symbol<SystemSymbolFn>(kSystemSymbol).has_value());
        CHECK_FALSE(source.IsOpen());
        CHECK(source.Path().empty());
        CHECK_FALSE(source.Symbol<SystemSymbolFn>(kSystemSymbol).has_value());

        // Move assignment: the target receives the handle, the source is closed again.
        Loader receiver{};
        receiver = std::move(owner);
        CHECK(receiver.IsOpen());
        CHECK_EQ(receiver.Path(), library);
        CHECK(receiver.Symbol<SystemSymbolFn>(kSystemSymbol).has_value());
        CHECK_FALSE(owner.IsOpen());
        CHECK(owner.Path().empty());

        // Move assignment onto an open loader replaces its library.
        Loader replaced{};
        REQUIRE(replaced.Open(library).has_value());
        replaced = std::move(receiver);
        CHECK(replaced.IsOpen());
        CHECK_EQ(replaced.Path(), library);
        CHECK(replaced.Symbol<SystemSymbolFn>(kSystemSymbol).has_value());
        CHECK_FALSE(receiver.IsOpen());

        // Self move assignment leaves the loader untouched. The assignment goes through a
        // function: written as `x = std::move(x)` the compiler warns about the self move.
        MoveAssign(replaced, replaced);
        CHECK(replaced.IsOpen());
        CHECK_EQ(replaced.Path(), library);

        // A moved-from loader is fully usable again, and closing it leaves the other alone.
        REQUIRE(source.Open(library).has_value());
        source.Close();
        CHECK(replaced.IsOpen());
        CHECK(replaced.Symbol<SystemSymbolFn>(kSystemSymbol).has_value());
    }

    TEST_CASE("LoadPlugin rejects a library that is not a plugin and closes the loader") {
        Loader loader{};
        // The system library is not an ifw plugin: it does not export the entry points.
        const std::string library = OpenSystemLibrary(loader);
        loader.Close();

        const auto entry = cpl::plugin::LoadPlugin(loader, library);
        CHECK_FALSE(entry.has_value());
        CHECK_EQ(CodeOf(entry.error()), static_cast<int64_t>(cpl::Error::UnavailableAPI));
        // The reason names the entry point that was missing.
        CHECK(entry.error().Reason.find(IFW_PLUGIN_QUERY_SYMBOL) != std::string::npos);
        CHECK(EndsWithLocation(entry.error()));
        // On any failure the loader is closed again.
        CHECK_FALSE(loader.IsOpen());
        CHECK(loader.Path().empty());
    }

    TEST_CASE("LoadPlugin of a missing library fails and closes the loader") {
        Loader loader{};
        const auto entry = cpl::plugin::LoadPlugin(loader, kMissingLibrary);
        CHECK_FALSE(entry.has_value());
        CHECK_EQ(CodeOf(entry.error()), static_cast<int64_t>(cpl::Error::FileOpen));
        CHECK(entry.error().Reason.find(kMissingLibraryText) != std::string::npos);
        CHECK(EndsWithLocation(entry.error()));
        CHECK_FALSE(loader.IsOpen());
        CHECK(loader.Path().empty());
    }

    TEST_CASE("LoadPlugin closes a loader that was already open") {
        Loader loader{};
        OpenSystemLibrary(loader);
        REQUIRE(loader.IsOpen());

        const auto entry = cpl::plugin::LoadPlugin(loader, kMissingLibrary);
        CHECK_FALSE(entry.has_value());
        CHECK_EQ(CodeOf(entry.error()), static_cast<int64_t>(cpl::Error::InvalidArgument));
        CHECK(EndsWithLocation(entry.error()));
        CHECK_FALSE(loader.IsOpen());
        CHECK(loader.Path().empty());
    }

    TEST_CASE("QueryPlugin hands the plugin the values the host expects") {
        g_fake = FakePlugin{};
        const auto info = Must(cpl::plugin::impl::QueryPlugin(&FakeQuery));

        // The host filled in the size of the struct and the API version it speaks, nothing else.
        CHECK_EQ(g_fake.handedIn.cb, static_cast<uint32_t>(sizeof(IfwPluginInfo)));
        CHECK_EQ(g_fake.handedIn.plugin_api_version, IFW_PLUGIN_API_VERSION);
        CHECK(g_fake.handedIn.name == nullptr);
        CHECK(g_fake.handedIn.version == nullptr);
        CHECK_EQ(g_fake.handedIn.flags, 0u);

        // The answer of the plugin is passed through.
        CHECK_EQ(info.cb, static_cast<uint32_t>(sizeof(IfwPluginInfo)));
        CHECK_EQ(info.plugin_api_version, IFW_PLUGIN_API_VERSION);
        CHECK_EQ(std::string(info.name), std::string("fake-plugin"));
        CHECK_EQ(std::string(info.version), std::string("9.9.9"));
        CHECK_EQ(info.flags, 0x5a5a5a5au);
    }

    TEST_CASE("QueryPlugin rejects a failed IfwPluginQuery") {
        g_fake = FakePlugin{};
        g_fake.result = IFW_PLUGIN_ERROR_INTERNAL;

        const auto info = cpl::plugin::impl::QueryPlugin(&FakeQuery);
        CHECK_FALSE(info.has_value());
        // The code of the plugin is the error code.
        CHECK_EQ(CodeOf(info.error()), static_cast<int64_t>(IFW_PLUGIN_ERROR_INTERNAL));
        // The reason carries the returned value and the expected one.
        CHECK(info.error().Reason.find("returned [3]") != std::string::npos);
        CHECK(info.error().Reason.find("expected [0]") != std::string::npos);
        CHECK(EndsWithLocation(info.error()));
    }

    TEST_CASE("QueryPlugin rejects a plugin built for another API version") {
        g_fake = FakePlugin{};
        g_fake.apiVersion = 0x00010001u; // the version of the previous plugin layout

        const auto info = cpl::plugin::impl::QueryPlugin(&FakeQuery);
        CHECK_FALSE(info.has_value());
        CHECK_EQ(CodeOf(info.error()), static_cast<int64_t>(IFW_PLUGIN_ERROR_INCOMPATIBLE_API));
        // The reason carries the reported version and the expected one.
        CHECK(info.error().Reason.find("reported [0x00010001]") != std::string::npos);
        CHECK(info.error().Reason.find("expected [0x00010002]") != std::string::npos);
        CHECK(EndsWithLocation(info.error()));
    }
}
