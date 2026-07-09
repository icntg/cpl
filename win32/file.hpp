#ifndef CPL_FILE_HPP
#define CPL_FILE_HPP

#include <cstdio>
#include <string>
#include <sys/stat.h>

#include "sys.hpp"
#include "../base.hpp"

namespace cpl {
    namespace sys {
        namespace file {
            class Errors final {
            public:
                static constexpr int64_t base = static_cast<int64_t>(0x20) << 32;
                static constexpr cpl::Error::CodeDef Open = {base | 1};
                static constexpr cpl::Error::CodeDef Read = {base | 2};
                static constexpr cpl::Error::CodeDef Seek = {base | 3};
                static constexpr cpl::Error::CodeDef Tell = {base | 4};
                static constexpr cpl::Error::CodeDef CreateFileA = {base | 5};
                static constexpr cpl::Error::CodeDef CreateFileMappingA = {base | 6};
                static constexpr cpl::Error::CodeDef MapViewOfFile = {base | 7};
                static constexpr cpl::Error::CodeDef UnmapViewOfFile = {base | 8};
            };

            inline Result<int64_t> GetFileSize(const std::string &filename) {
                struct stat st{};
                if (0 == stat(filename.data(), &st)) {
                    return static_cast<int64_t>(st.st_size);
                }

                FILE *fp{};
                const auto defer = cpl::base::MakeDefer([&]() {
                    if (fp) {
                        fclose(fp);
                        fp = nullptr;
                    }
                });

                const auto r00 = fopen_s(&fp, filename.data(), "rb");
                if (ERROR_SUCCESS != r00 || nullptr == fp) {
                    auto es = strings::Format(
                        "[X] fopen_s [%s] failed [%ld]" CPL_FILE_AND_LINE,
                        filename.data(),
                        r00
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Error::FileOpen, es.value<>());
                }
                if (0 != _fseeki64(fp, 0, SEEK_END)) {
                    auto es = strings::Format(
                        "[X] _fseeki64 [%s] failed" CPL_FILE_AND_LINE,
                        filename.data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::Seek, es.value<>());
                }
                const auto size = _ftelli64(fp);
                if (size < 0) {
                    auto es = strings::Format(
                        "[X] _ftelli64 [%s] failed: %lld" CPL_FILE_AND_LINE,
                        filename.data(),
                        size
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::Tell, es.value<>());
                }
                return size;
            }

            inline Result<Stream> ReadFile(_In_ const std::string &filename) {
                FILE *fp{};
                Stream content{};

                const auto defer = cpl::base::MakeDefer([&]() {
                    if (fp) {
                        fclose(fp);
                        fp = nullptr;
                    }
                });

                const auto r0 = fopen_s(&fp, filename.data(), "rb");
                if (r0 != 0 || fp == nullptr) {
                    auto es = strings::Format(
                        "[X] fopen_s [%s] failed: %ld" CPL_FILE_AND_LINE,
                        filename.data(),
                        r0
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::Open, es.value<>());
                }

                if (0 != _fseeki64(fp, 0, SEEK_END)) {
                    auto es = strings::Format(
                        "[X] _fseeki64 [%s] failed" CPL_FILE_AND_LINE,
                        filename.data()
                    );

                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::Seek, es.value<>());
                }

                const auto fileSize = _ftelli64(fp);
                if (fileSize < 0) {
                    auto es = strings::Format(
                        "[X] _ftelli64 [%s] failed: %lld" CPL_FILE_AND_LINE,
                        filename.data(),
                        fileSize
                    );

                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::Tell, es.value<>());
                }
                if (0 != _fseeki64(fp, 0, SEEK_SET)) {
                    auto es = strings::Format(
                        "[X] _fseeki64 reset [%s] failed" CPL_FILE_AND_LINE,
                        filename.data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::Seek, es.value<>());
                }

                content.resize(static_cast<size_t>(fileSize));
                if (fileSize == 0) {
                    return content;
                }

                const auto bytesRead = fread(content.data(), 1, static_cast<size_t>(fileSize), fp);
                if (bytesRead != static_cast<size_t>(fileSize)) {
                    auto es = strings::Format(
                        "[X] fread [%s] failed: %lu/%lld" CPL_FILE_AND_LINE,
                        filename.data(),
                        static_cast<uint32_t>(bytesRead),
                        fileSize
                    );

                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::Read, es.value<>());
                }
                return content;
            }

            class FileMappingContext final : public base::IContext {
            protected:
                std::string filename{};

                Int32Result Load() override {
                    const auto fsize = GetFileSize(filename);
                    if (!fsize) {
                        return Err(fsize.error());
                    }
                    MappedFileSize = static_cast<size_t>(fsize.value());

                    FileHandle = CreateFileA(
                        filename.data(),
                        GENERIC_READ,
                        FILE_SHARE_READ,
                        nullptr,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        nullptr
                    );
                    if (INVALID_HANDLE_VALUE == FileHandle) {
                        const auto e = GetLastError();
                        auto es = cpl::strings::Format(
                            "[X] CreateFileA [%s] failed: [0x%lu] %s" CPL_FILE_AND_LINE,
                            filename.data(),
                            e,
                            FormatError(e).data()
                        );
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        return MakeErr(Errors::CreateFileA, es.value<>());
                    }

                    MappingHandle = CreateFileMappingA(
                        FileHandle,
                        nullptr,
                        PAGE_READONLY,
                        0,
                        0,
                        nullptr
                    );
                    if (nullptr == MappingHandle) {
                        const auto e = GetLastError();
                        auto es = cpl::strings::Format(
                            "[X] CreateFileMappingA failed: [0x%lx][%s]" CPL_FILE_AND_LINE,
                            e,
                            FormatError(e).data()
                        );

                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        return MakeErr(Errors::CreateFileMappingA, es.value<>());
                    }

                    MappedFileAddress = MapViewOfFile(
                        MappingHandle,
                        FILE_MAP_READ,
                        0,
                        0,
                        0
                    );
                    if (nullptr == MappedFileAddress) {
                        const DWORD e = GetLastError();
                        auto es = cpl::strings::Format(
                            "[X] MapViewOfFile failed: [0x%lx][%s]" CPL_FILE_AND_LINE,
                            e,
                            FormatError(e).data()
                        );

                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        return MakeErr(Errors::MapViewOfFile, es.value<>());
                    }
                    return 0;
                }

                Int32Result Unload() override {
                    if (nullptr != MappedFileAddress) {
                        const BOOL unmapResult = UnmapViewOfFile(MappedFileAddress);
                        if (!unmapResult) {
                            const auto e = GetLastError();
                            auto es = cpl::strings::Format(
                                "[X] UnmapViewOfFile failed: [0x%lx][%s]" CPL_FILE_AND_LINE,
                                e,
                                FormatError(e).data()
                            );

                            if (!es) {
                                return Err(es.error().Append(CPL_FILE_AND_LINE));
                            }
                            return MakeErr(Errors::UnmapViewOfFile, es.value<>());
                        }
                        MappedFileAddress = nullptr;
                        MappedFileSize = 0;
                    }
                    if (nullptr != MappingHandle) {
                        CloseHandle(MappingHandle);
                        MappingHandle = nullptr;
                    }
                    if (INVALID_HANDLE_VALUE != FileHandle) {
                        CloseHandle(FileHandle);
                        FileHandle = INVALID_HANDLE_VALUE;
                    }
                    return 0;
                }

            public:
                HANDLE FileHandle = INVALID_HANDLE_VALUE;
                HANDLE MappingHandle = nullptr;
                void *MappedFileAddress = nullptr;
                size_t MappedFileSize = 0;

                bool IsLoaded() override {
                    return MappedFileAddress != nullptr;
                }

                explicit FileMappingContext(const std::string &filename)
                    : filename(filename) {
                    (void) this->Load();
                }

                ~FileMappingContext() override {
                    (void) this->Unload();
                }
            };
        }
    }
}

#endif // CPL_FILE_HPP
