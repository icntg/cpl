#ifndef HARDWARE_HPP_RAINBOW_MOUNTAIN_PEAK_FLAME_ECHO_CLOUDY_MIRROR_STEEL
#define HARDWARE_HPP_RAINBOW_MOUNTAIN_PEAK_FLAME_ECHO_CLOUDY_MIRROR_STEEL

#include "../utility/base.hpp"
#include <cstdint>
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <string>

#include "api.hpp"

#pragma comment(lib, "setupapi.lib")
#pragma comment(lib, "cfgmgr32.lib")

using namespace std;

namespace cpl {
    namespace win32 {
        namespace hardware {
            // 函数：禁用设备
            inline int32_t DisableDevice(const wstring &deviceId) {
                int32_t retCode = ERROR_SUCCESS;
                DEVINST devInst{};
                HDEVINFO deviceInfoSet = INVALID_HANDLE_VALUE;
                SP_DEVINFO_DATA deviceInfoData{};
                // 定位硬件
                {
                    const auto r0 = CM_Locate_DevNodeW(&devInst, const_cast<DEVINSTID_W>(deviceId.data()),
                                                       CM_LOCATE_DEVNODE_NORMAL);
                    if (r0 != CR_SUCCESS) {
                        fprintf(stderr, "[x] CM_Locate_DevNodeW failed %lu", r0);
                        retCode = static_cast<int32_t>(r0);
                        goto __ERROR__;
                    }
                }
                // 禁用设备
                {
                    const auto r0 = CM_Disable_DevNode(devInst, 0); // 0 表示不递归禁用子设备
                    if (r0 != CR_SUCCESS) {
                        fprintf(stderr, "[x] CM_Disable_DevNode failed %lu", r0);
                        retCode = static_cast<int32_t>(r0);
                        goto __ERROR__;
                    }
                }
                // 获取设备信息集
                {
                    //
                    deviceInfoSet = SetupDiGetClassDevsW(
                        nullptr,                   // 所有设备类
                        nullptr,
                        nullptr,
                        DIGCF_ALLCLASSES | DIGCF_PRESENT
                    );
                    if (INVALID_HANDLE_VALUE == deviceInfoSet) {
                        const auto e = GetLastError();
                        fprintf(stderr, "[x] SetupDiGetClassDevs failed 0x%lx:%s", e, FormatError(e).data());
                        retCode = static_cast<int32_t>(e);
                        goto __ERROR__;
                    }
                }
                // 通知系统设备状态更改
                {
                    deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
                    DWORD index = 0;
                    while (SetupDiEnumDeviceInfo(deviceInfoSet, index++, &deviceInfoData)) {
                        WCHAR currentDeviceId[MAX_DEVICE_ID_LEN];
                        if (CM_Get_Device_IDW(devInst, currentDeviceId, MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS) {
                            if (deviceId == currentDeviceId) {
                                // 找到目标设备，通知系统属性更改
                                if (!SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, deviceInfoSet, &deviceInfoData)) {
                                    // std::wcerr << L"通知系统属性更改失败。" << std::endl;
                                    SetupDiDestroyDeviceInfoList(deviceInfoSet);
                                    return false;
                                }
                                break;
                            }
                        }
                    }

                    const auto r0 = SetupDiCallClassInstaller(DIF_PROPERTYCHANGE, deviceInfoSet, nullptr);
                    if (!r0) {
                        const auto e = GetLastError();
                        fprintf(stderr, "[x] SetupDiCallClassInstaller failed %lu", r0);
                        retCode = static_cast<int32_t>(e);
                        goto __ERROR__;
                    }
                }


                // std::wcout << L"成功禁用设备: " << deviceId << std::endl;

                goto __FREE__;
            __ERROR__:
                PASS;
            __FREE__:
                if (deviceInfoSet != INVALID_HANDLE_VALUE) {
                    CloseHandle(deviceInfoSet);
                }
                return retCode;
            }
        }
    }
}


// int main() {
//     HDEVINFO deviceInfoSet = SetupDiGetClassDevs(
//         &GUID_DEVCLASS_NET,     // 网络适配器类GUID
//         NULL,
//         NULL,
//         DIGCF_PRESENT | DIGCF_PROFILE
//     );
//
//     if (deviceInfoSet == INVALID_HANDLE_VALUE) {
//         std::cerr << "无法获取设备信息集。" << std::endl;
//         return 1;
//     }
//
//     SP_DEVINFO_DATA deviceInfoData = {};
//     deviceInfoData.cbSize = sizeof(SP_DEVINFO_DATA);
//     DWORD index = 0;
//
//     while (SetupDiEnumDeviceInfo(deviceInfoSet, index++, &deviceInfoData)) {
//         DWORD requiredSize = 0;
//         // 获取设备实例ID的长度
//         SetupDiGetDeviceRegistryProperty(
//             deviceInfoSet,
//             &deviceInfoData,
//             SPDRP_PHYSICAL_DEVICE_OBJECT_NAME, // 可以根据需要选择不同的属性
//             NULL,
//             NULL,
//             0,
//             &requiredSize
//         );
//
//         std::vector<BYTE> buffer(requiredSize);
//         if (SetupDiGetDeviceRegistryProperty(
//             deviceInfoSet,
//             &deviceInfoData,
//             SPDRP_PHYSICAL_DEVICE_OBJECT_NAME, // 或使用其他属性如 SPDRP_FRIENDLYNAME
//             NULL,
//             buffer.data(),
//             requiredSize,
//             NULL
//         )) {
//             // 这里需要解析设备名称并确定目标网卡
//             // 为了简化，假设我们已知设备ID
//             // 实际应用中，你可能需要根据设备的友好名称或其他属性来识别
//
//             // 示例：假设我们要禁用的设备ID包含特定字符串
//             std::wstring deviceName(reinterpret_cast<wchar_t*>(buffer.data()));
//             if (deviceName.find(L"以太网") != std::wstring::npos) { // 根据实际情况修改
//                 // 获取完整的设备ID
//                 WCHAR deviceId[MAX_DEVICE_ID_LEN];
//                 if (CM_Get_Device_ID(devInfoData.DevInst, deviceId, MAX_DEVICE_ID_LEN, 0) == CR_SUCCESS) {
//                     DisableDevice(deviceId);
//                 }
//             }
//         }
//     }
//
//     SetupDiDestroyDeviceInfoList(deviceInfoSet);
//     return 0;
// }

#endif //HARDWARE_HPP_RAINBOW_MOUNTAIN_PEAK_FLAME_ECHO_CLOUDY_MIRROR_STEEL
