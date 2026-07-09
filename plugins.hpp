#ifndef _CPL_PLUGIN_HPP_CONSIDERATE_ADVANTAGE_UNIVERSAL_DISCOVERY_TECHNICAL_MEMORIAL_EQUIPMENT_MOTIVATION
#define _CPL_PLUGIN_HPP_CONSIDERATE_ADVANTAGE_UNIVERSAL_DISCOVERY_TECHNICAL_MEMORIAL_EQUIPMENT_MOTIVATION

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "base.hpp"
#include "naion.hpp"
#include "strings.hpp"
#include "vendor/nlohmann/json/json.hpp"

#if defined(_MSC_VER)
#define IFW_PLUGIN_CALL __stdcall
#define IFW_PLUGIN_EXPORT __declspec(dllexport)
#else
#define IFW_PLUGIN_CALL
#define IFW_PLUGIN_EXPORT
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    IFW_PLUGIN_OK = 0,
    IFW_PLUGIN_ERROR_INVALID_ARG = 1,
    IFW_PLUGIN_ERROR_INCOMPATIBLE_API = 2,
    IFW_PLUGIN_ERROR_INTERNAL = 3,
    IFW_PLUGIN_ERROR_NOT_IMPLEMENTED = 4,
} IfwPluginResult;

typedef enum {
    IFW_PLUGIN_LOG_TRACE = 0,
    IFW_PLUGIN_LOG_DEBUG = 1,
    IFW_PLUGIN_LOG_INFO = 2,
    IFW_PLUGIN_LOG_WARN = 3,
    IFW_PLUGIN_LOG_ERROR = 4,
} IfwPluginLogLevel;

typedef int(IFW_PLUGIN_CALL *ifw_plugin_log_fn)(int level, const char *msg);

// Event types carried by plugin -> afw -> receiver reports.
// Values MUST stay aligned with udp_receiver `warning_type` (existing 1/2/3);
// extend only, never renumber existing values.
typedef enum {
    IFW_EVENT_HEARTBEAT        = 0,  // afw core heartbeat (not produced by plugins)
    IFW_EVENT_WARN_OUTBOUND_V6 = 1,  // outbound: IPv6 default route  (was warning_type 1)
    IFW_EVENT_WARN_OUTBOUND_AD = 2,  // outbound: illegal adapter name (was warning_type 2)
    IFW_EVENT_WARN_OUTBOUND_V4 = 3,  // outbound: IPv4 default route  (was warning_type 3)
    IFW_EVENT_WARN_USB         = 4,  // illegal USB device
    IFW_EVENT_WARN_CASCADE     = 5,  // illegal cascade (rogue DHCP server)
    IFW_EVENT_WARN_WEAKPASS    = 6,  // weak password hit
    IFW_EVENT_SUBNET_SCAN      = 7,  // subnet device probe (bulk, goes via HTTP)
} IfwEventType;

// Plugin -> afw reporting callbacks. afw performs naion CSM encryption and
// routes the event to the matching receiver service. Plugins only produce
// (event_type, payload). UDP payloads must fit the naion CSM client->server
// application budget (<=856 bytes); larger data must go via send_http.
typedef int(IFW_PLUGIN_CALL *ifw_plugin_send_udp_fn)(uint32_t event_type,
                                                     const void *payload,
                                                     uint32_t len);
typedef int(IFW_PLUGIN_CALL *ifw_plugin_send_http_fn)(uint32_t event_type,
                                                      const void *payload,
                                                      uint32_t len);

typedef struct IfwPluginHostApi {
    uint32_t cb;
    uint32_t api_version;
    ifw_plugin_send_udp_fn  send_udp;   // small / time-critical -> UDP
    ifw_plugin_send_http_fn send_http;  // large / bulk          -> HTTP
} IfwPluginHostApi;

typedef struct IfwPluginInfo {
    uint32_t cb;
    uint32_t plugin_api_version;
    const char *name;
    const char *version;
    uint32_t flags;
} IfwPluginInfo;

typedef struct IfwPluginContext {
    uint32_t cb;
    uint32_t host_api_version;
    const char *plugin_path;
    const char *config_json;
    ifw_plugin_log_fn log;
    uint32_t flags;
    const IfwPluginHostApi *host_api;  // afw-injected host capabilities (replaces reserved)
} IfwPluginContext;

typedef int(IFW_PLUGIN_CALL *ifw_plugin_query_fn)(IfwPluginInfo *out_info);
typedef int(IFW_PLUGIN_CALL *ifw_plugin_run_fn)(const IfwPluginContext *ctx);

#pragma pack(push, 1)
typedef struct IfwPluginTrailer {
    char magic[8];
    uint16_t package_version;
    uint16_t flags;
    uint32_t cfg_offset;
    uint32_t cfg_size;
    uint32_t reserved0;
    uint32_t reserved1;
} IfwPluginTrailer;
#pragma pack(pop)

#define IFW_PLUGIN_API_VERSION 0x00010001u  // bumped: reserved -> host_api (IfwPluginHostApi)
#define IFW_PLUGIN_QUERY_SYMBOL "IfwPluginQuery"
#define IFW_PLUGIN_RUN_SYMBOL "IfwPluginRun"
#define IFW_PLUGIN_PACKAGE_VERSION 0x0001u
#define IFW_PLUGIN_SIGNATURE_BYTES 64u
#define IFW_PLUGIN_TRAILER_MAGIC "IFWPLG01"

#ifdef __cplusplus
}

namespace cpl {
    namespace plugins {
        using std::string;

        struct PackageInfo {
            string path{};
            string configJson{};
            IfwPluginTrailer trailer{};
        };

        enum class RunMode {
            Once,
            Repeat,
            Manual,
        };

        enum class RunAs {
            System,
            ServiceUser,
            ActiveUser,
            LimitedUser,
        };

        enum class FailureAction {
            Log,
            Disable,
            Retry,
            Alert,
        };

        struct RuntimeConfig {
            string name{};
            string description{};
            string version{};
            bool enabled{true};
            RunMode runMode{RunMode::Repeat};
            RunAs runAs{RunAs::System};
            bool allowParallel{false};
            uint32_t intervalSeconds{300};
            uint32_t startupDelaySeconds{10};
            uint32_t jitterSeconds{0};
            uint32_t timeoutSeconds{60};
            uint32_t maxRetries{0};
            uint32_t retryDelaySeconds{30};
            FailureAction onFailure{FailureAction::Log};
            string argsJson{"{}"};
        };

        inline RunMode ParseRunMode(string value) {
            cpl::strings::Lower(value);
            if (value == "once") {
                return RunMode::Once;
            }
            if (value == "manual") {
                return RunMode::Manual;
            }
            return RunMode::Repeat;
        }

        inline RunAs ParseRunAs(string value) {
            cpl::strings::Lower(value);
            if (value == "active_user" || value == "user") {
                return RunAs::ActiveUser;
            }
            if (value == "service_user") {
                return RunAs::ServiceUser;
            }
            if (value == "limited_user") {
                return RunAs::LimitedUser;
            }
            return RunAs::System;
        }

        inline FailureAction ParseFailureAction(string value) {
            cpl::strings::Lower(value);
            if (value == "disable") {
                return FailureAction::Disable;
            }
            if (value == "retry") {
                return FailureAction::Retry;
            }
            if (value == "alert") {
                return FailureAction::Alert;
            }
            return FailureAction::Log;
        }

        inline cpl::Result<RuntimeConfig> ParseRuntimeConfig(const string &configJson) {
            try {
                RuntimeConfig cfg{};
                const auto j = nlohmann::json::parse(configJson);
                cfg.name = j.value("name", "");
                cfg.description = j.value("description", "");
                cfg.version = j.value("version", "");
                cfg.enabled = j.value("enabled", true);
                cfg.runMode = ParseRunMode(j.value("run_mode", "repeat"));
                cfg.runAs = ParseRunAs(j.value("run_as", "system"));
                cfg.allowParallel = j.value("allow_parallel", false);
                cfg.intervalSeconds = j.value("interval_seconds", 300U);
                cfg.startupDelaySeconds = j.value("startup_delay_seconds", 10U);
                cfg.jitterSeconds = j.value("jitter_seconds", 0U);
                cfg.timeoutSeconds = j.value("timeout_seconds", 60U);
                cfg.maxRetries = j.value("max_retries", 0U);
                cfg.retryDelaySeconds = j.value("retry_delay_seconds", 30U);
                cfg.onFailure = ParseFailureAction(j.value("on_failure", "log"));
                if (j.find("args") != j.end()) {
                    cfg.argsJson = (*j.find("args")).dump();
                }
                if (cfg.intervalSeconds == 0) {
                    cfg.intervalSeconds = 300;
                }
                if (cfg.retryDelaySeconds == 0) {
                    cfg.retryDelaySeconds = 30;
                }
                return cfg;
            } catch (...) {
                return cpl::MakeErr(cpl::Error::InvalidArgument(), "[X] plugin runtime cfg parse failed" CPL_FILE_AND_LINE);
            }
        }

        inline cpl::Result<PackageInfo> LoadPackageConfigFromBytes(
            const uint8_t *fileData,
            const size_t fileSize,
            const void *caPublicKey,
            const size_t caPublicKeySize,
            string path = {}
        ) {
            if (fileData == nullptr || caPublicKey == nullptr) {
                return cpl::MakeErr(cpl::Error::NullPointer(), "[X] plugin package input is null" CPL_FILE_AND_LINE);
            }
            cpl::naion::EPK ca{};
            if (caPublicKeySize != ca.size()) {
                return cpl::MakeErr(cpl::Error::InvalidArgument(), "[X] plugin CA public key size invalid" CPL_FILE_AND_LINE);
            }

            constexpr size_t minPackageSize = sizeof(IfwPluginTrailer) + IFW_PLUGIN_SIGNATURE_BYTES;
            if (fileSize <= minPackageSize) {
                return cpl::MakeErr(cpl::Error::OutOfRange(), "[X] plugin package is too small" CPL_FILE_AND_LINE);
            }

            const size_t signatureOffset = fileSize - IFW_PLUGIN_SIGNATURE_BYTES;
            const size_t trailerOffset = signatureOffset - sizeof(IfwPluginTrailer);
            const auto *trailer = reinterpret_cast<const IfwPluginTrailer *>(fileData + trailerOffset);
            if (std::memcmp(trailer->magic, IFW_PLUGIN_TRAILER_MAGIC, sizeof(trailer->magic)) != 0) {
                return cpl::MakeErr(cpl::Error::InvalidArgument(), "[X] plugin trailer magic mismatch" CPL_FILE_AND_LINE);
            }
            if (trailer->package_version != IFW_PLUGIN_PACKAGE_VERSION) {
                return cpl::MakeErr(cpl::Error::InvalidArgument(), "[X] plugin package version mismatch" CPL_FILE_AND_LINE);
            }
            if (trailer->cfg_offset >= trailerOffset || trailer->cfg_size == 0) {
                return cpl::MakeErr(cpl::Error::OutOfRange(), "[X] plugin cfg offset/size invalid" CPL_FILE_AND_LINE);
            }
            if (static_cast<size_t>(trailer->cfg_offset) + static_cast<size_t>(trailer->cfg_size) != trailerOffset) {
                return cpl::MakeErr(cpl::Error::OutOfRange(), "[X] plugin cfg range does not match trailer offset" CPL_FILE_AND_LINE);
            }

            std::memcpy(ca.data(), caPublicKey, ca.size());
            const auto verifyCode = naion_sign_ed25519_verify_detached(
                fileData + signatureOffset,
                fileData,
                signatureOffset,
                ca.data()
            );
            if (verifyCode != 0) {
                return cpl::MakeErr(cpl::naion::Errors::CryptoSignVerifyDetached, "[X] plugin signature verify failed" CPL_FILE_AND_LINE);
            }

            const auto cfgPtr = reinterpret_cast<const char *>(fileData + trailer->cfg_offset);
            string configJson(cfgPtr, cfgPtr + trailer->cfg_size);
            try {
                (void)nlohmann::json::parse(configJson);
            } catch (...) {
                return cpl::MakeErr(cpl::Error::InvalidArgument(), "[X] plugin cfg is not valid JSON" CPL_FILE_AND_LINE);
            }

            PackageInfo out{};
            out.path = std::move(path);
            out.configJson = std::move(configJson);
            out.trailer = *trailer;
            return out;
        }

        inline cpl::Result<PackageInfo> LoadPackageConfig(
            const string &pluginPath,
            const void *caPublicKey,
            const size_t caPublicKeySize
        ) {
            FILE *fp = nullptr;
            const auto deferFile = cpl::base::MakeDefer([&] {
                if (fp) {
                    std::fclose(fp);
                    fp = nullptr;
                }
            });

#if defined(_MSC_VER)
            const auto rOpen = fopen_s(&fp, pluginPath.data(), "rb");
            if (rOpen != 0 || fp == nullptr) {
                return cpl::MakeErr(rOpen == 0 ? cpl::Error::FileOpen().i64 : rOpen, "[X] fopen_s plugin failed" CPL_FILE_AND_LINE);
            }
#else
            fp = std::fopen(pluginPath.data(), "rb");
            if (fp == nullptr) {
                return cpl::MakeErr(cpl::Error::FileOpen(), "[X] fopen plugin failed" CPL_FILE_AND_LINE);
            }
#endif

            if (std::fseek(fp, 0, SEEK_END) != 0) {
                return cpl::MakeErr(cpl::Error::OutOfRange(), "[X] fseek plugin end failed" CPL_FILE_AND_LINE);
            }
            const auto fileSizeLong = std::ftell(fp);
            if (fileSizeLong <= 0) {
                return cpl::MakeErr(cpl::Error::OutOfRange(), "[X] ftell plugin failed" CPL_FILE_AND_LINE);
            }
            if (std::fseek(fp, 0, SEEK_SET) != 0) {
                return cpl::MakeErr(cpl::Error::OutOfRange(), "[X] fseek plugin begin failed" CPL_FILE_AND_LINE);
            }

            const auto fileSize = static_cast<size_t>(fileSizeLong);
            std::vector<uint8_t> fileData(fileSize);
            const auto rRead = std::fread(fileData.data(), 1, fileData.size(), fp);
            if (rRead != fileData.size()) {
                return cpl::MakeErr(cpl::Error::OutOfRange(), "[X] fread plugin failed" CPL_FILE_AND_LINE);
            }

            return LoadPackageConfigFromBytes(
                fileData.data(),
                fileData.size(),
                caPublicKey,
                caPublicKeySize,
                pluginPath
            );
        }
    }
}
#endif

#endif // _CPL_PLUGIN_HPP_CONSIDERATE_ADVANTAGE_UNIVERSAL_DISCOVERY_TECHNICAL_MEMORIAL_EQUIPMENT_MOTIVATION
