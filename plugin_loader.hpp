/*
 * plugin_loader
 * Shared library loader for the ifw plugin ABI
 * Platform-independent: dlopen on POSIX, LoadLibraryA on Windows
 *
 * The two entry points of a plugin are resolved under the name of the ABI (IfwPluginQuery,
 * IfwPluginRun). On the 32-bit x86 target of Windows, MSVC exports a function of the stdcall
 * convention under a decorated name (_IfwPluginQuery@4) when the build of the plugin has no
 * module definition file. The host accepts both forms, so that a plugin needs no such file.
 */

#ifndef CPL_PLUGIN_LOADER_HPP_STATIONARY_LANTERN_HARBOR_WHISPER_GRANITE_ORBIT
#define CPL_PLUGIN_LOADER_HPP_STATIONARY_LANTERN_HARBOR_WHISPER_GRANITE_ORBIT

#include <cstdint>
#include <string>
#include <vector>

#include "base.hpp"
#include "plugins.hpp"
#include "strings.hpp"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#endif

namespace cpl {
    namespace plugin {
        namespace impl {
#if defined(_WIN32)
            // The system message of a Win32 error code (the text behind GetLastError()),
            // without its trailing line break. Empty when Windows cannot describe the code.
            inline std::string Win32ErrorText(const DWORD code) {
                char buffer[512] = {};
                const DWORD written = FormatMessageA(
                    FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    nullptr,
                    code,
                    0,
                    buffer,
                    static_cast<DWORD>(sizeof(buffer)),
                    nullptr
                );
                size_t size = static_cast<size_t>(written);
                while (size > 0 && (buffer[size - 1] == '\n' || buffer[size - 1] == '\r' ||
                                    buffer[size - 1] == ' ')) {
                    size--;
                }
                return std::string(buffer, size);
            }
#endif

            // Calls IfwPluginQuery on a resolved query function and checks the answer.
            // `query` must not be null.
            //
            // Before the call the struct is zeroed and filled with what the host expects, the same
            // preparation as the loader of the Windows client: cb = sizeof(IfwPluginInfo), so the
            // plugin knows how much it may write, and plugin_api_version = IFW_PLUGIN_API_VERSION,
            // the version the host speaks.
            inline Result<IfwPluginInfo> QueryPlugin(const ifw_plugin_query_fn query) {
                IfwPluginInfo info{};
                info.cb = static_cast<uint32_t>(sizeof(IfwPluginInfo));
                info.plugin_api_version = IFW_PLUGIN_API_VERSION;

                const int queryResult = query(&info);
                if (queryResult != IFW_PLUGIN_OK) {
                    auto es = cpl::strings::Format(
                        "[X] IfwPluginQuery failed: returned [%d], expected [%d]" CPL_FILE_AND_LINE,
                        queryResult,
                        static_cast<int>(IFW_PLUGIN_OK)
                    );
                    if (!es) {
                        return cpl::Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    // The code of the plugin is kept as the error code (IfwPluginResult).
                    return cpl::MakeErr(static_cast<int64_t>(queryResult), es.value());
                }
                if (info.plugin_api_version != IFW_PLUGIN_API_VERSION) {
                    auto es = cpl::strings::Format(
                        "[X] plugin api version mismatch: reported [0x%08x], expected [0x%08x]"
                        CPL_FILE_AND_LINE,
                        info.plugin_api_version,
                        IFW_PLUGIN_API_VERSION
                    );
                    if (!es) {
                        return cpl::Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return cpl::MakeErr(static_cast<int64_t>(IFW_PLUGIN_ERROR_INCOMPATIBLE_API), es.value());
                }
                return info;
            }
        }

        // Owns one open shared library: a dlopen handle on POSIX, a module handle on Windows.
        // Not copyable; movable. The destructor closes the library when it is still open.
        // A loader is not synchronized: threads share one only behind an external lock.
        class Loader {
        public:
            Loader() = default;

            ~Loader();

            Loader(const Loader &) = delete;

            Loader &operator=(const Loader &) = delete;

            Loader(Loader &&other) noexcept;

            Loader &operator=(Loader &&other) noexcept;

            // Opens the library: dlopen(path, RTLD_NOW | RTLD_LOCAL) on POSIX, LoadLibraryA on Windows.
            // Fails when a library is already open (call Close() first) or the path is empty.
            Int32Result Open(const std::string &path);

            // Resolves a symbol. Fails when no library is open or the symbol does not exist.
            // Fn is a function pointer type, for example ifw_plugin_query_fn.
            // The pointer stays valid only while the loader stays open.
            template<typename Fn>
            Result<Fn> Symbol(const char *name) {
                if (!this->IsOpen()) {
                    return cpl::MakeErr(cpl::Error::InvalidArgument,
                                        "[X] plugin loader cannot resolve a symbol: no library is open"
                                        CPL_FILE_AND_LINE);
                }
                if (name == nullptr || name[0] == '\0') {
                    return cpl::MakeErr(cpl::Error::InvalidArgument,
                                        "[X] plugin loader symbol name is empty" CPL_FILE_AND_LINE);
                }
#if defined(_WIN32)
                const FARPROC symbol = GetProcAddress(static_cast<HMODULE>(this->handle_), name);
                if (symbol == nullptr) {
                    const DWORD code = GetLastError();
                    auto es = cpl::strings::Format(
                        "[X] GetProcAddress [%s] failed [0x%lx]: %s" CPL_FILE_AND_LINE,
                        name,
                        static_cast<unsigned long>(code),
                        impl::Win32ErrorText(code).c_str()
                    );
                    if (!es) {
                        return cpl::Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return cpl::MakeErr(cpl::Error::UnavailableAPI, es.value());
                }
                return reinterpret_cast<Fn>(symbol);
#else
                // Clear any pending error first, so that dlerror() below reports on this lookup only.
                (void)dlerror();
                void *const symbol = dlsym(this->handle_, name);
                const char *text = dlerror();
                if (text != nullptr || symbol == nullptr) {
                    auto es = cpl::strings::Format(
                        "[X] dlsym [%s] failed: %s" CPL_FILE_AND_LINE,
                        name,
                        text != nullptr ? text : "symbol not found"
                    );
                    if (!es) {
                        return cpl::Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return cpl::MakeErr(cpl::Error::UnavailableAPI, es.value());
                }
                return reinterpret_cast<Fn>(symbol);
#endif
            }

            // Closes the library when open. Safe to call twice.
            void Close();

            bool IsOpen() const;

            // The path given to Open(); empty while no library is open.
            const std::string &Path() const;

        private:
            // The raw handle keeps the class layout identical on every platform.
            void *handle_{nullptr};
            std::string path_{};
        };

        inline Loader::~Loader() {
            this->Close();
        }

        inline Loader::Loader(Loader &&other) noexcept
            : handle_(other.handle_), path_(std::move(other.path_)) {
            // The source is left closed, so its destructor will not close the moved handle.
            other.handle_ = nullptr;
            other.path_.clear();
        }

        inline Loader &Loader::operator=(Loader &&other) noexcept {
            if (this != &other) {
                // Close the library this object owns before taking the one of the source.
                this->Close();
                this->handle_ = other.handle_;
                this->path_ = std::move(other.path_);
                other.handle_ = nullptr;
                other.path_.clear();
            }
            return *this;
        }

        inline Int32Result Loader::Open(const std::string &path) {
            if (this->IsOpen()) {
                return cpl::MakeErr(cpl::Error::InvalidArgument,
                                    "[X] plugin loader already has an open library" CPL_FILE_AND_LINE);
            }
            if (path.empty()) {
                return cpl::MakeErr(cpl::Error::InvalidArgument,
                                    "[X] plugin loader open path is empty" CPL_FILE_AND_LINE);
            }
            // The path is stored before the library is opened: the string assignment is the only
            // step that can throw (std::bad_alloc), and at this point no handle is owned yet.
            this->path_ = path;
#if defined(_WIN32)
            const HMODULE handle = LoadLibraryA(this->path_.c_str());
            if (handle == nullptr) {
                const DWORD code = GetLastError();
                auto es = cpl::strings::Format(
                    "[X] LoadLibraryA [%s] failed [0x%lx]: %s" CPL_FILE_AND_LINE,
                    this->path_.c_str(),
                    static_cast<unsigned long>(code),
                    impl::Win32ErrorText(code).c_str()
                );
                if (!es) {
                    this->path_.clear();
                    return cpl::Err(es.error().Append(CPL_FILE_AND_LINE));
                }
                this->path_.clear();
                return cpl::MakeErr(cpl::Error::FileOpen, es.value());
            }
            this->handle_ = static_cast<void *>(handle);
#else
            void *const handle = dlopen(this->path_.c_str(), RTLD_NOW | RTLD_LOCAL);
            if (handle == nullptr) {
                const char *text = dlerror();
                auto es = cpl::strings::Format(
                    "[X] dlopen [%s] failed: %s" CPL_FILE_AND_LINE,
                    this->path_.c_str(),
                    text != nullptr ? text : "unknown error"
                );
                if (!es) {
                    this->path_.clear();
                    return cpl::Err(es.error().Append(CPL_FILE_AND_LINE));
                }
                this->path_.clear();
                return cpl::MakeErr(cpl::Error::FileOpen, es.value());
            }
            this->handle_ = handle;
#endif
            return 0;
        }

        inline void Loader::Close() {
            // Forget the handle before releasing it, so that a second call has nothing left to do.
            void *const handle = this->handle_;
            this->handle_ = nullptr;
            this->path_.clear();
            if (handle == nullptr) {
                return;
            }
#if defined(_WIN32)
            (void)FreeLibrary(static_cast<HMODULE>(handle));
#else
            (void)dlclose(handle);
#endif
        }

        inline bool Loader::IsOpen() const {
            return this->handle_ != nullptr;
        }

        inline const std::string &Loader::Path() const {
            return this->path_;
        }

        // EntrySymbolNames gives the names under which an entry point of a plugin can be
        // exported, in the order in which the host looks for them. The first name is the name of
        // the ABI. On the 32-bit x86 target of Windows a function of the stdcall convention is
        // exported under a decorated name when the build of the plugin has no module definition
        // file: the underscore, the name, and the number of bytes of the arguments. Both entry
        // points of a plugin take one pointer.
        inline std::vector<std::string> EntrySymbolNames(const char *name) {
            std::vector<std::string> names;
            names.push_back(name);
#if defined(_WIN32) && defined(_M_IX86)
            names.push_back(std::string("_") + name + "@" + std::to_string(sizeof(void *)));
#endif
            return names;
        }

        // EntrySymbol resolves an entry point of a plugin under every name of EntrySymbolNames().
        // When no name exists, the error names the name of the ABI.
        template<typename Fn>
        inline Result<Fn> EntrySymbol(Loader &loader, const char *name) {
            const std::vector<std::string> names = EntrySymbolNames(name);
            Result<Fn> symbol = loader.Symbol<Fn>(names[0].c_str());
            if (symbol) {
                return symbol;
            }
            const Error failure = symbol.error();
            for (size_t index = 1; index < names.size(); index++) {
                symbol = loader.Symbol<Fn>(names[index].c_str());
                if (symbol) {
                    return symbol;
                }
            }
            return cpl::Err(failure);
        }

        // One loaded plugin: the two entry points and the answer of IfwPluginQuery.
        // The strings in info are owned by the plugin: they stay valid only while the
        // Loader that loaded them stays open.
        struct PluginEntry {
            ifw_plugin_query_fn query = nullptr;
            ifw_plugin_run_fn run = nullptr;
            IfwPluginInfo info{};
        };

        // Opens the plugin, resolves both symbols, calls IfwPluginQuery and checks that the plugin
        // was built for IFW_PLUGIN_API_VERSION. On any failure the loader is closed again.
        // On success the loader stays open: it owns the code behind the returned pointers.
        inline Result<PluginEntry> LoadPlugin(Loader &loader, const std::string &path) {
            // RAII: the loader is closed again on every exit, including an exception thrown on the
            // way (a string allocation), unless the plugin was loaded successfully.
            bool loaded = false;
            const auto closeOnExit = cpl::base::MakeDefer([&]() noexcept {
                if (!loaded) {
                    loader.Close();
                }
            });

            const auto rOpen = loader.Open(path);
            if (!rOpen) {
                return cpl::Err(rOpen.error());
            }

            // Step 1: the two entry points. libc, or any other library that is not an ifw plugin,
            // is rejected here.
            const auto query = EntrySymbol<ifw_plugin_query_fn>(loader, IFW_PLUGIN_QUERY_SYMBOL);
            if (!query) {
                return cpl::Err(query.error());
            }
            const auto run = EntrySymbol<ifw_plugin_run_fn>(loader, IFW_PLUGIN_RUN_SYMBOL);
            if (!run) {
                return cpl::Err(run.error());
            }

            // Step 2: let the plugin describe itself and check its API version.
            const auto info = impl::QueryPlugin(query.value());
            if (!info) {
                return cpl::Err(info.error());
            }

            PluginEntry entry{};
            entry.query = query.value();
            entry.run = run.value();
            entry.info = info.value();
            loaded = true;
            return entry;
        }
    }
}

#endif //CPL_PLUGIN_LOADER_HPP_STATIONARY_LANTERN_HARBOR_WHISPER_GRANITE_ORBIT
