#ifndef CPL_WIN32_SERVICE_HPP_BUFFER_AROUND_BUFFER_BORDER_ANIMAL_BREATH_BRIGHT_ACTIVE
#define CPL_WIN32_SERVICE_HPP_BUFFER_AROUND_BUFFER_BORDER_ANIMAL_BREATH_BRIGHT_ACTIVE

#include <string>

#include "../base.hpp"
#include "../strings.hpp"
#include "sys.hpp"

namespace cpl {
    namespace sys {
        namespace service {
            class Errors final {
            public:
                static constexpr int64_t base = static_cast<int64_t>(0x50) << 32;
                static constexpr cpl::Error::CodeDef OpenSCManager_ = {base | 1};
                static constexpr cpl::Error::CodeDef CreateService_ = {base | 2};
                static constexpr cpl::Error::CodeDef ChangeServiceConfig_ = {base | 3};
                static constexpr cpl::Error::CodeDef StartService_ = {base | 4};
                static constexpr cpl::Error::CodeDef OpenService_ = {base | 5};
                static constexpr cpl::Error::CodeDef QueryServiceStatus_ = {base | 6};
                static constexpr cpl::Error::CodeDef ControlService_ = {base | 7};
                static constexpr cpl::Error::CodeDef DeleteService_ = {base | 8};
            };

            inline Int32Result Install(
                const std::wstring &ServiceName,
                const std::wstring &DisplayName,
                const std::wstring &ExecutePath
            ) {
                SC_HANDLE scmHandle{};
                SC_HANDLE serviceHandle{};

                const auto defer = cpl::base::MakeDefer([&]() {
                    if (serviceHandle) {
                        CloseServiceHandle(serviceHandle);
                        serviceHandle = nullptr;
                    }
                    if (scmHandle) {
                        CloseServiceHandle(scmHandle);
                        scmHandle = nullptr;
                    }
                });

                scmHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
                if (!scmHandle) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] OpenSCManagerW error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::OpenSCManager_, es.value<>());
                }

                serviceHandle = CreateServiceW(
                    scmHandle,
                    ServiceName.data(),
                    DisplayName.data(),
                    SERVICE_ALL_ACCESS,
                    SERVICE_WIN32_OWN_PROCESS,
                    SERVICE_AUTO_START,
                    SERVICE_ERROR_NORMAL,
                    ExecutePath.data(),
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr,
                    nullptr
                );
                if (!serviceHandle) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] CreateServiceW error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::CreateService_, es.value<>());
                }

                SERVICE_FAILURE_ACTIONS failureActions{};
                SC_ACTION restartAction{};
                restartAction.Type = SC_ACTION_RESTART;
                restartAction.Delay = 10000;
                failureActions.dwResetPeriod = 0;
                failureActions.cActions = 1;
                failureActions.lpsaActions = &restartAction;

                if (!ChangeServiceConfig2W(serviceHandle, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions)) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] ChangeServiceConfig2W error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::ChangeServiceConfig_, es.value<>());
                }

                if (!StartServiceW(serviceHandle, 0, nullptr)) {
                    const auto e = GetLastError();
                    if (e != ERROR_SERVICE_ALREADY_RUNNING) {
                        auto es = strings::Format(
                            "[X] StartServiceW error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                            sys::FormatError(e).data()
                        );
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        return MakeErr(Errors::StartService_, es.value<>());
                    }
                }

                return 0;
            }

            inline Int32Result Uninstall(const std::wstring &ServiceName) {
                SC_HANDLE scmHandle{};
                SC_HANDLE serviceHandle{};

                const auto defer = cpl::base::MakeDefer([&]() {
                    if (serviceHandle) {
                        CloseServiceHandle(serviceHandle);
                        serviceHandle = nullptr;
                    }
                    if (scmHandle) {
                        CloseServiceHandle(scmHandle);
                        scmHandle = nullptr;
                    }
                });

                scmHandle = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
                if (!scmHandle) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] OpenSCManagerW error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::OpenSCManager_, es.value<>());
                }

                serviceHandle = OpenServiceW(scmHandle, ServiceName.data(),
                                             SERVICE_STOP | DELETE | SERVICE_QUERY_STATUS);
                if (!serviceHandle) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] OpenService_ error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::OpenService_, es.value<>());
                }

                SERVICE_STATUS_PROCESS ssp{};
                DWORD bytesNeeded{};
                if (!QueryServiceStatusEx(
                    serviceHandle,
                    SC_STATUS_PROCESS_INFO,
                    reinterpret_cast<LPBYTE>(&ssp),
                    sizeof(SERVICE_STATUS_PROCESS),
                    &bytesNeeded
                )) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] QueryServiceStatusEx error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::QueryServiceStatus_, es.value<>());
                }

                if (ssp.dwCurrentState != SERVICE_STOPPED) {
                    if (!ControlService(serviceHandle, SERVICE_CONTROL_STOP,
                                        reinterpret_cast<LPSERVICE_STATUS>(&ssp))) {
                        const auto e = GetLastError();
                        auto es = strings::Format(
                            "[X] ControlService error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                            sys::FormatError(e).data()
                        );
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        return MakeErr(Errors::ControlService_, es.value<>());
                    }
                    for (int i = 0; i < 60; i++) {
                        Sleep(1000);
                        if (!QueryServiceStatusEx(
                            serviceHandle,
                            SC_STATUS_PROCESS_INFO,
                            reinterpret_cast<LPBYTE>(&ssp),
                            sizeof(SERVICE_STATUS_PROCESS),
                            &bytesNeeded
                        )) {
                            break;
                        }
                        if (ssp.dwCurrentState == SERVICE_STOPPED) {
                            break;
                        }
                    }
                }

                if (!DeleteService(serviceHandle)) {
                    const auto e = GetLastError();
                    auto es = strings::Format(
                        "[X] DeleteService error [0x%lx][%s]" CPL_FILE_AND_LINE, e,
                        sys::FormatError(e).data()
                    );
                    if (!es) {
                        return Err(es.error().Append(CPL_FILE_AND_LINE));
                    }
                    return MakeErr(Errors::DeleteService_, es.value<>());
                }
                return 0;
            }

            class WindowsService;

            class IServiceEventLoop {
                friend class WindowsService;

            protected:
                mutable WindowsService *mService{};
                mutable HANDLE stopEvent{};

            public:
                virtual ~IServiceEventLoop() = default;

                virtual void EventLoop() = 0;
            };

            class WindowsService {
            protected:
                static IServiceEventLoop *wrapper;
                std::wstring serviceName{};
                SERVICE_STATUS serviceStatus{};
                SERVICE_STATUS_HANDLE serviceStatusHandle{};

            public:
                virtual ~WindowsService() = default;

                explicit WindowsService(const std::wstring &serviceName, IServiceEventLoop *_wrapper) {
                    this->serviceName = serviceName;
                    WindowsService::wrapper = _wrapper;
                    WindowsService::wrapper->mService = this;
                }

                virtual Int32Result Run() {
                    const SERVICE_TABLE_ENTRYW serviceTable[] = {
                        {const_cast<LPWSTR>(serviceName.data()), ServiceMainWrapper},
                        {nullptr, nullptr}
                    };

                    if (StartServiceCtrlDispatcherW(serviceTable) == FALSE) {
                        const auto e = GetLastError();
                        auto es = strings::Format(
                            "[X] StartServiceCtrlDispatcherW failed [0x%lx][%s]" CPL_FILE_AND_LINE,
                            e, FormatError(e).data()
                        );
                        if (!es) {
                            return Err(es.error().Append(CPL_FILE_AND_LINE));
                        }
                        fprintf(stderr, "%s\n", es.value<>().data());
                        return MakeErr(e, es.value<>());
                    }
                    return ERROR_SUCCESS;
                }

                static void WINAPI ServiceMainWrapper(DWORD argc, LPWSTR *argv) {
                    if (wrapper && wrapper->mService) {
                        wrapper->mService->ServiceMain(argc, argv);
                    }
                }

                virtual void ServiceMain(DWORD argc, LPWSTR *argv) {
                    const auto r0 = RegisterServiceCtrlHandlerW(serviceName.data(), ControlHandlerWrapper);
                    if (!r0) {
                        const auto e = GetLastError();
                        fprintf(stderr, "[X] RegisterServiceCtrlHandler failed 0x%lx:%s\n", e, FormatError(e).data());
                        return;
                    }
                    serviceStatusHandle = r0;

                    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
                    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
                    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
                    serviceStatus.dwWin32ExitCode = NO_ERROR;
                    serviceStatus.dwServiceSpecificExitCode = 0;
                    serviceStatus.dwCheckPoint = 0;
                    serviceStatus.dwWaitHint = 0;
                    SetServiceStatus(serviceStatusHandle, &serviceStatus);

                    if (wrapper) {
                        wrapper->stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
                        if (!wrapper->stopEvent) {
                            serviceStatus.dwCurrentState = SERVICE_STOPPED;
                            SetServiceStatus(serviceStatusHandle, &serviceStatus);
                            return;
                        }
                    }

                    serviceStatus.dwCurrentState = SERVICE_RUNNING;
                    SetServiceStatus(serviceStatusHandle, &serviceStatus);

                    if (wrapper) {
                        wrapper->EventLoop();
                    }

                    serviceStatus.dwCurrentState = SERVICE_STOPPED;
                    SetServiceStatus(serviceStatusHandle, &serviceStatus);
                }

                static void WINAPI ControlHandlerWrapper(const DWORD controlCode) {
                    if (wrapper && wrapper->mService) {
                        wrapper->mService->ControlHandler(controlCode);
                    }
                }

                virtual void ControlHandler(const DWORD controlCode) {
                    switch (controlCode) {
                        case SERVICE_CONTROL_STOP:
                        case SERVICE_CONTROL_SHUTDOWN:
                            serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
                            SetServiceStatus(serviceStatusHandle, &serviceStatus);
                            SetEvent(wrapper->stopEvent);
                            serviceStatus.dwCurrentState = SERVICE_STOPPED;
                            SetServiceStatus(serviceStatusHandle, &serviceStatus);
                            break;
                        default:
                            break;
                    }
                }
            };
        };

        service::IServiceEventLoop *service::WindowsService::wrapper{};
    }
}

#endif // CPL_WIN32_SERVICE_HPP_BUFFER_AROUND_BUFFER_BORDER_ANIMAL_BREATH_BRIGHT_ACTIVE
