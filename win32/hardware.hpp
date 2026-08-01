#ifndef HARDWARE_HPP_RAINBOW_MOUNTAIN_PEAK_FLAME_ECHO_CLOUDY_MIRROR_STEEL
#define HARDWARE_HPP_RAINBOW_MOUNTAIN_PEAK_FLAME_ECHO_CLOUDY_MIRROR_STEEL

#include "../utility/base.hpp"
#include "../strings.hpp"
#include <cstdint>
#include <windows.h>
#include <setupapi.h>
#include <cfgmgr32.h>
#include <string>
#include <vector>
#include <functional>

#include "api.hpp"

// CM_*/SetupDi* 通过 cpl::sys::api 动态加载（见 sys.hpp 的 CfgMgr32/SetupAPI
// namespace）。不再静态链接 setupapi.lib/cfgmgr32.lib —— 这两个 lib 在
// v141_xp 的 x86 SDK 目录缺失，动态加载兼容性更好。

using namespace std;

namespace cpl {
    namespace win32 {
        namespace hardware {

            // ── 设备信息结构 ──────────────────────────────────────────
            // UsbDeviceInfo holds the properties of one present device that
            // can be used for keyword and VID/PID matching.
            struct UsbDeviceInfo {
                wstring hardwareId;   // SPDRP_HARDWAREID, e.g. "USB\VID_0A12&PID_0001&..."
                wstring description;  // SPDRP_DEVICEDESC, e.g. "Generic Bluetooth Radio"
                wstring className;    // SPDRP_CLASS, e.g. "Bluetooth"
                wstring friendlyName; // SPDRP_FRIENDLYNAME (may be empty on XP)
                DEVINST devInst;      // for CM_Disable_DevNode
            };

            // ── 禁用设备（修复版） ────────────────────────────────────
            // Disable a device by its DEVINST handle.  Uses
            // CM_Disable_DevNode with CM_DISABLE_PERSISTENT so the disable
            // survives reboot (safer for security scenarios than flag 0).
            // Returns CR_SUCCESS (0) on success, or a ConfigMgr error code.
            inline int32_t DisableDeviceByDevInst(DEVINST devInst,
                                                  bool persistent = true) {
                const auto &cm = cpl::sys::api::API::Instance().CfgMgr32;
                if (!cm.CM_Disable_DevNode) {
                    return static_cast<int32_t>(CR_FAILURE);
                }
                const DWORD flags = persistent ? 1ul /*CM_DISABLE_PERSISTENT*/ : 0ul;
                return static_cast<int32_t>(cm.CM_Disable_DevNode(devInst, flags));
            }

            // Disable a device by its instance ID string (legacy interface,
            // kept for backward compatibility).  Internally locates the
            // DEVINST then calls DisableDeviceByDevInst.
            inline int32_t DisableDevice(const wstring &deviceId) {
                const auto &cm = cpl::sys::api::API::Instance().CfgMgr32;
                if (!cm.CM_Locate_DevNodeW) {
                    return static_cast<int32_t>(CR_FAILURE);
                }
                DEVINST devInst{};
                const auto r0 = cm.CM_Locate_DevNodeW(
                    &devInst,
                    const_cast<DEVINSTID_W>(deviceId.data()),
                    CM_LOCATE_DEVNODE_NORMAL);
                if (r0 != CR_SUCCESS) {
                    return static_cast<int32_t>(r0);
                }
                return DisableDeviceByDevInst(devInst);
            }

            // ── 枚举所有在线设备 ─────────────────────────────────────
            // EnumeratePresentDevices iterates all present devices via
            // SetupDiGetClassDevsW(DIGCF_ALLCLASSES|DIGCF_PRESENT) and
            // invokes the callback with each device's UsbDeviceInfo.
            // The callback can return false to stop enumeration early.
            inline void EnumeratePresentDevices(
                const function<bool(const UsbDeviceInfo &)> &callback) {

                const auto &sa = cpl::sys::api::API::Instance().SetupAPI;
                if (!sa.SetupDiGetClassDevsW || !sa.SetupDiEnumDeviceInfo
                    || !sa.SetupDiGetDeviceRegistryPropertyW
                    || !sa.SetupDiDestroyDeviceInfoList) {
                    return; // SetupAPI 不可用，跳过枚举
                }

                HDEVINFO hDevInfo = sa.SetupDiGetClassDevsW(
                    nullptr, nullptr, nullptr,
                    DIGCF_ALLCLASSES | DIGCF_PRESENT);
                if (hDevInfo == INVALID_HANDLE_VALUE) return;

                SP_DEVINFO_DATA devInfo{};
                devInfo.cbSize = sizeof(devInfo);

                for (DWORD i = 0; sa.SetupDiEnumDeviceInfo(hDevInfo, i, &devInfo); ++i) {
                    UsbDeviceInfo info{};
                    info.devInst = devInfo.DevInst;

                    // SPDRP_HARDWAREID (REG_MULTI_SZ — take first entry)
                    {
                        WCHAR buf[512]{};
                        DWORD needed = 0;
                        if (sa.SetupDiGetDeviceRegistryPropertyW(
                            hDevInfo, &devInfo, SPDRP_HARDWAREID,
                            nullptr, reinterpret_cast<PBYTE>(buf), sizeof(buf), &needed)) {
                            info.hardwareId = buf;  // first string of MULTI_SZ
                        }
                    }
                    // SPDRP_DEVICEDESC
                    {
                        WCHAR buf[256]{};
                        if (sa.SetupDiGetDeviceRegistryPropertyW(
                            hDevInfo, &devInfo, SPDRP_DEVICEDESC,
                            nullptr, reinterpret_cast<PBYTE>(buf), sizeof(buf), nullptr)) {
                            info.description = buf;
                        }
                    }
                    // SPDRP_CLASS
                    {
                        WCHAR buf[256]{};
                        if (sa.SetupDiGetDeviceRegistryPropertyW(
                            hDevInfo, &devInfo, SPDRP_CLASS,
                            nullptr, reinterpret_cast<PBYTE>(buf), sizeof(buf), nullptr)) {
                            info.className = buf;
                        }
                    }
                    // SPDRP_FRIENDLYNAME (often empty on XP)
                    {
                        WCHAR buf[256]{};
                        if (sa.SetupDiGetDeviceRegistryPropertyW(
                            hDevInfo, &devInfo, SPDRP_FRIENDLYNAME,
                            nullptr, reinterpret_cast<PBYTE>(buf), sizeof(buf), nullptr)) {
                            info.friendlyName = buf;
                        }
                    }

                    if (!callback(info)) break;
                }

                sa.SetupDiDestroyDeviceInfoList(hDevInfo);
            }

            // ── 从 HardwareID 提取 VID/PID ──────────────────────────
            // Extract VID and PID from a hardware ID string like
            // "USB\VID_0483&PID_572B&REV_0100".  Returns true on success.
            inline bool ExtractVidPid(const wstring &hwId,
                                      uint16_t &vid, uint16_t &pid) {
                // Case-insensitive search for "VID_XXXX"
                auto findHex = [&](const wstring &tag, uint16_t &out) -> bool {
                    // Convert hwId to lower for searching
                    wstring lower = hwId;
                    for (auto &c : lower) c = static_cast<wchar_t>(towlower(c));
                    wstring lowerTag = tag;
                    for (auto &c : lowerTag) c = static_cast<wchar_t>(towlower(c));
                    auto pos = lower.find(lowerTag);
                    if (pos == wstring::npos) return false;
                    pos += lowerTag.size();
                    if (pos + 4 > lower.size()) return false;
                    // Parse 4 hex digits
                    wchar_t hex[5]{};
                    for (int i = 0; i < 4; ++i) hex[i] = lower[pos + i];
                    out = static_cast<uint16_t>(wcstoul(hex, nullptr, 16));
                    return true;
                };
                bool foundVid = findHex(L"VID_", vid);
                bool foundPid = findHex(L"PID_", pid);
                return foundVid;  // VID is mandatory; PID is optional
            }

            // ── wstring 大小写不敏感包含查找 ─────────────────────────
            inline bool WStringContainsCI(const wstring &haystack,
                                          const wstring &needle) {
                if (needle.empty()) return false;
                wstring h = haystack, n = needle;
                for (auto &c : h) c = static_cast<wchar_t>(towlower(c));
                for (auto &c : n) c = static_cast<wchar_t>(towlower(c));
                return h.find(n) != wstring::npos;
            }

            // ── 按关键字禁用设备 ─────────────────────────────────────
            // Scan all present devices; if the description, class name, or
            // friendly name contains any of the keywords (case-insensitive
            // substring match), disable the device.  Returns the number of
            // devices disabled.
            // Each keyword match also invokes the reportCallback so the
            // caller can upload a warning.
            inline int32_t DisableDevicesByKeyword(
                const vector<string> &keywords,
                const function<void(const UsbDeviceInfo &)> &reportCallback = nullptr) {

                if (keywords.empty()) return 0;

                // Convert keywords to wstring for matching
                vector<wstring> wKeywords;
                for (const auto &kw : keywords) {
                    if (kw.empty()) continue;
                    wKeywords.emplace_back(kw.begin(), kw.end());
                }

                int32_t disabled = 0;
                EnumeratePresentDevices([&](const UsbDeviceInfo &info) {
                    // Build searchable text: description + className + friendlyName
                    wstring text = info.description + L" " + info.className + L" " + info.friendlyName;
                    for (const auto &wk : wKeywords) {
                        if (WStringContainsCI(text, wk)) {
                            const auto rc = DisableDeviceByDevInst(info.devInst);
                            if (rc == 0 /*CR_SUCCESS*/) {
                                ++disabled;
                                if (reportCallback) reportCallback(info);
                            }
                            break;  // one match per device is enough
                        }
                    }
                    return true;  // continue enumeration
                });
                return disabled;
            }

            // ── 按 VID:PID 禁用设备 ──────────────────────────────────
            // Scan all present devices; if the hardware ID's VID and PID
            // match any entry in vidPidList (format "VID:PID", e.g.
            // "0483:572B"), disable the device.  If a PID is omitted
            // ("0483" alone), match by VID only.  Returns count disabled.
            inline int32_t DisableDevicesByVidPid(
                const vector<string> &vidPidList,
                const function<void(const UsbDeviceInfo &)> &reportCallback = nullptr) {

                if (vidPidList.empty()) return 0;

                // Parse "VID:PID" or "VID" entries into (vid, hasPid, pid)
                struct VidPidRule { uint16_t vid; bool hasPid; uint16_t pid; };
                vector<VidPidRule> rules;
                for (const auto &entry : vidPidList) {
                    VidPidRule r{};
                    r.hasPid = false;
                    auto colonPos = entry.find(':');
                    if (colonPos == string::npos) {
                        // VID only
                        r.vid = static_cast<uint16_t>(
                            strtoul(entry.c_str(), nullptr, 16));
                    } else {
                        string vidStr = entry.substr(0, colonPos);
                        string pidStr = entry.substr(colonPos + 1);
                        r.vid = static_cast<uint16_t>(
                            strtoul(vidStr.c_str(), nullptr, 16));
                        if (!pidStr.empty()) {
                            r.pid = static_cast<uint16_t>(
                                strtoul(pidStr.c_str(), nullptr, 16));
                            r.hasPid = true;
                        }
                    }
                    if (r.vid != 0) rules.push_back(r);
                }

                if (rules.empty()) return 0;

                int32_t disabled = 0;
                EnumeratePresentDevices([&](const UsbDeviceInfo &info) {
                    if (info.hardwareId.empty()) return true;
                    uint16_t devVid = 0, devPid = 0;
                    if (!ExtractVidPid(info.hardwareId, devVid, devPid)) return true;
                    for (const auto &r : rules) {
                        if (devVid == r.vid) {
                            if (!r.hasPid || devPid == r.pid) {
                                const auto rc = DisableDeviceByDevInst(info.devInst);
                                if (rc == 0) {
                                    ++disabled;
                                    if (reportCallback) reportCallback(info);
                                }
                                break;
                            }
                        }
                    }
                    return true;  // continue
                });
                return disabled;
            }

        } // namespace hardware
    } // namespace win32
} // namespace cpl

#endif //HARDWARE_HPP_RAINBOW_MOUNTAIN_PEAK_FLAME_ECHO_CLOUDY_MIRROR_STEEL
