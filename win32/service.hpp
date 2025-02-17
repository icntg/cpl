#ifndef CPL_WIN32_SERVICE_HPP_BUFFER_AROUND_BUFFER_BORDER_ANIMAL_BREATH_BRIGHT_ACTIVE
#define CPL_WIN32_SERVICE_HPP_BUFFER_AROUND_BUFFER_BORDER_ANIMAL_BREATH_BRIGHT_ACTIVE

#include <windows.h>
#include <cstdint>
#include <string>

#include "api.hpp"

using namespace std;

namespace cpl {
    namespace win32 {
        namespace service {
            class $Status {
            public:
                wstring serviceName{};
                SERVICE_STATUS serviceStatus{};
                SERVICE_STATUS_HANDLE serviceStatusHandle{};
            };

            class $Wrapper {
            protected:
                $Status status{};
                void (WINAPI *funcServiceCtrlHandler)(DWORD controlCode){};
                void (WINAPI *funcServiceMain)(DWORD argc, LPWSTR *argv){};
                void (*funcEventLoop)(){};

            public:
                void ServiceMain(DWORD argc, LPWSTR* argv) {
                    if (nullptr == funcServiceCtrlHandler) {
                        fprintf(stderr, "[x] ERROR_INVALID_FUNCTION 0x%lx:%s\n", ERROR_INVALID_FUNCTION, FormatError(ERROR_INVALID_FUNCTION).data());
                        return;
                    }
                    const auto r0= RegisterServiceCtrlHandlerW(status.serviceName.data(), funcServiceCtrlHandler);
                    if (!r0) {
                        const auto e = GetLastError();
                        fprintf(stderr, "[x] RegisterServiceCtrlHandler failed 0x%lx:%s\n", e, FormatError(e).data());
                        return;
                    }
                    status.serviceStatusHandle = r0;

                    status.serviceStatus.dwCurrentState = SERVICE_START_PENDING;
                    SetServiceStatus(status.serviceStatusHandle, &status.serviceStatus);

                    {
                        // todo 初始化可以放在这里。
                    }
                    // 初始化完成，服务开始运行
                    status.serviceStatus.dwCurrentState = SERVICE_RUNNING;
                    SetServiceStatus(status.serviceStatusHandle, &status.serviceStatus);

                    // 调用用户提供的事件循环函数
                    if (funcEventLoop) {
                        funcEventLoop();
                    }

                    // 服务停止
                    status.serviceStatus.dwCurrentState = SERVICE_STOPPED;
                    SetServiceStatus(status.serviceStatusHandle, &status.serviceStatus);
                }
            };

            class WindowsService {
            protected:
                $Status status{};
                $Wrapper wrapper{};

                $Status* (*funcGetInstance)(){};
            public:
                virtual int32_t Run() = 0;
                virtual int32_t Stop() = 0;
            };


            class IService {
            protected:
                static IService *instance;

                wstring serviceName{};
                SERVICE_STATUS serviceStatus{};
                SERVICE_STATUS_HANDLE serviceStatusHandle{};
                HANDLE stopEvent = nullptr;
                BOOL isRunning = FALSE;

                void (WINAPI *funcServiceCtrlHandler)(DWORD controlCode){};

                void (WINAPI *funcLoop)(DWORD argc, LPWSTR *argv){};

            public:
                virtual ~IService() = default;

                IService(
                    const wstring &serviceName,
                    void (WINAPI *funcServiceCtrlHandler)(DWORD),
                    void (WINAPI *funcLoop)(DWORD, LPWSTR *)
                ) {
                    this->serviceName = serviceName;
                    this->funcServiceCtrlHandler = funcServiceCtrlHandler;
                    this->funcLoop = funcLoop;
                }

                const wstring &ServiceName() const {
                    return this->serviceName;
                }

                SERVICE_STATUS &ServiceStatus() {
                    return this->serviceStatus;
                }

                inline SERVICE_STATUS_HANDLE &ServiceStatusHandle() {
                    return this->serviceStatusHandle;
                }

                HANDLE &StopEvent() {
                    return this->stopEvent;
                }

                BOOL &IsRunning() {
                    return this->isRunning;
                }

                static IService *GetInstance() {
                    return instance;
                }

                static void SetInstance(IService &instance) {
                    IService::instance = &instance;
                }

                static int32_t Install(
                    const wstring &serviceName,
                    const wstring &displayName,
                    const wstring &description,
                    const wstring &binPath) {
                    int32_t retCode = ERROR_SUCCESS;
                    SC_HANDLE scmHandle = nullptr;
                    SC_HANDLE serviceHandle = nullptr;
                    SERVICE_DESCRIPTIONW sd{};

                    scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
                    if (!scmHandle) {
                        const auto e = GetLastError();
                        fprintf(stderr, "[x] OpenSCManager failed 0x%lx:[%s]\n", e, FormatError(e).data());
                        retCode = static_cast<int32_t>(e);
                        goto __ERROR__;
                    }

                    serviceHandle = CreateServiceW(
                        scmHandle,
                        serviceName.data(),
                        displayName.data(),
                        SERVICE_ALL_ACCESS,
                        SERVICE_WIN32_OWN_PROCESS,
                        SERVICE_AUTO_START,
                        SERVICE_ERROR_NORMAL,
                        binPath.data(),
                        nullptr,
                        nullptr,
                        nullptr,
                        nullptr,
                        nullptr);
                    if (!serviceHandle) {
                        const auto e = GetLastError();
                        fprintf(stderr, "[x] CreateService failed 0x%lx:[%s]\n", e, FormatError(e).data());
                        retCode = static_cast<int32_t>(e);
                        goto __ERROR__;
                    }
                    sd.lpDescription = const_cast<LPWSTR>(description.data());
                    ChangeServiceConfig2(serviceHandle, SERVICE_CONFIG_DESCRIPTION, &sd);
                    fprintf(stdout, "[!] Service installed successfully!\n");
                    goto __FREE__;

                __ERROR__:
                    PASS;
                __FREE__:
                    if (!serviceHandle) {
                        CloseServiceHandle(serviceHandle);
                    }
                    if (!scmHandle) {
                        CloseServiceHandle(scmHandle);
                    }
                    return retCode;
                }

                static int32_t Uninstall(const wstring &name) {
                    int32_t retCode = ERROR_SUCCESS;
                    SC_HANDLE scmHandle{};
                    SC_HANDLE serviceHandle{};

                    scmHandle = OpenSCManager(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
                    if (!scmHandle) {
                        const auto e = GetLastError();
                        fprintf(stderr, "[x] OpenSCManager failed 0x%lx:[%s]\n", e, FormatError(e).data());
                        retCode = static_cast<int32_t>(e);
                        goto __ERROR__;
                    }

                    serviceHandle = OpenServiceW(scmHandle, name.data(), DELETE);
                    if (!serviceHandle) {
                        const auto e = GetLastError();
                        fprintf(stderr, "[x] OpenServiceW failed 0x%lx:[%s]\n", e, FormatError(e).data());
                        retCode = static_cast<int32_t>(e);
                        goto __ERROR__;
                    } {
                        const auto r0 = DeleteService(serviceHandle);
                        if (!r0) {
                            const auto e = GetLastError();
                            fprintf(stderr, "[x] DeleteService failed 0x%lx:[%s]\n", e, FormatError(e).data());
                            retCode = static_cast<int32_t>(e);
                            goto __ERROR__;
                        }
                        fprintf(stdout, "[!] Service uninstalled successfully!\n");
                    }
                    goto __FREE__;
                __ERROR__:
                    PASS;
                __FREE__:
                    if (!serviceHandle) {
                        CloseServiceHandle(serviceHandle);
                    }
                    if (!scmHandle) {
                        CloseServiceHandle(scmHandle);
                    }
                    return retCode;
                }

                // 服务控制处理函数
                static void WINAPI DefaultServiceCtrlHandler(DWORD controlCode) {
                    auto ptrInstance = IService::GetInstance();
                    if (nullptr == ptrInstance) {
                        fprintf(stderr, "[x] Service Instance does not exist\n");
                        return;
                    }
                    auto instance = *ptrInstance;

                    switch (controlCode) {
                        case SERVICE_CONTROL_STOP:
                        case SERVICE_CONTROL_SHUTDOWN:
                            instance.serviceStatus.dwCurrentState = SERVICE_STOP_PENDING;
                            SetServiceStatus(instance.serviceStatusHandle, &instance.serviceStatus);
                            SetEvent(instance.stopEvent); // 通知服务停止
                            break;
                        default:
                            break;
                    }
                }

                static void WINAPI DefaultLoop(DWORD argc, LPWSTR *argv) {
                    auto ptrInstance = IService::GetInstance();
                    if (nullptr == ptrInstance) {
                        fprintf(stderr, "[x] Service Instance does not exist\n");
                        return;
                    }
                    auto instance = *ptrInstance;
                    auto serviceStatusHandle = instance.ServiceStatusHandle();
                    auto serviceStatus = instance.ServiceStatus();
                    auto stopEvent = instance.StopEvent();
                    // 注册服务控制处理函数
                    serviceStatusHandle = RegisterServiceCtrlHandlerW(instance.ServiceName().data(),
                                                                      DefaultServiceCtrlHandler);
                    if (!serviceStatusHandle) {
                        const auto e = GetLastError();
                        fprintf(stderr, "[x] RegisterServiceCtrlHandler failed 0x%lx:%s\n", e, FormatError(e).data());
                        return;
                    }

                    // 初始化服务状态
                    serviceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
                    serviceStatus.dwCurrentState = SERVICE_START_PENDING;
                    serviceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
                    serviceStatus.dwWin32ExitCode = NO_ERROR;
                    serviceStatus.dwServiceSpecificExitCode = 0;
                    serviceStatus.dwCheckPoint = 0;
                    serviceStatus.dwWaitHint = 0;
                    SetServiceStatus(serviceStatusHandle, &serviceStatus);

                    // 创建停止事件
                    stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
                    if (!stopEvent) {
                        serviceStatus.dwCurrentState = SERVICE_STOPPED;
                        SetServiceStatus(serviceStatusHandle, &serviceStatus);
                        return;
                    }

                    // 标记服务为运行状态
                    serviceStatus.dwCurrentState = SERVICE_RUNNING;
                    SetServiceStatus(serviceStatusHandle, &serviceStatus);

                    // 主循环：每隔 1 秒钟处理事件
                    while (WaitForSingleObject(stopEvent, 1000) == WAIT_TIMEOUT) {
                        // 获取当前时间
                        // auto now = std::chrono::system_clock::now();
                        // std::time_t now_time = std::chrono::system_clock::to_time_t(now);
                        // std::string timeStr = std::ctime(&now_time);
                        // timeStr.pop_back(); // 去掉换行符

                        // // 写入文件
                        // std::ofstream logFile("C:\\test.log", std::ios::app);
                        // if (logFile.is_open())
                        // {
                        //     logFile << timeStr << std::endl;
                        //     logFile.close();
                        // }
                    }

                    // 清理资源
                    CloseHandle(stopEvent);

                    // 标记服务为停止状态
                    serviceStatus.dwCurrentState = SERVICE_STOPPED;
                    SetServiceStatus(serviceStatusHandle, &serviceStatus);
                }

                virtual int32_t DefaultStartTemplate() {
                    // 服务表
                    const SERVICE_TABLE_ENTRYW serviceTable[] = {
                        {
                            const_cast<LPWSTR>(this->serviceName.data()),
                            static_cast<LPSERVICE_MAIN_FUNCTIONW>(DefaultLoop)
                        },
                        {nullptr, nullptr}
                    };

                    // 启动服务
                    if (!StartServiceCtrlDispatcherW(serviceTable)) {
                        const auto e = GetLastError();
                        fprintf(stderr, "[x] StartServiceCtrlDispatcherW failed 0x%lx:%s\n", e, FormatError(e).data());
                        return static_cast<int32_t>(e);
                    }
                    return ERROR_SUCCESS;
                }

                virtual int32_t Start() = 0;

                virtual int32_t Stop() = 0;
            };
        }
    }
}

#endif // CPL_WIN32_SERVICE_HPP_BUFFER_AROUND_BUFFER_BORDER_ANIMAL_BREATH_BRIGHT_ACTIVE
