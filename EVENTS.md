# afw 插件事件契约（EVENTS.md）

权威源：`cpl/plugins.hpp`（`IfwEventType` / `IfwPluginHostApi`）。本文档化事件类型、payload 约束与上报通道。

## 事件类型（IfwEventType）

| 值 | 名称 | 含义 | 传输 |
|---|---|---|---|
| 0 | `HEARTBEAT` | afw 核心心跳（非插件产生） | UDP |
| 1 | `WARN_OUTBOUND_V6` | 违规外连-IPv6 默认路由 | UDP |
| 2 | `WARN_OUTBOUND_AD` | 违规外连-非法网卡名 | UDP |
| 3 | `WARN_OUTBOUND_V4` | 违规外连-IPv4 默认路由 | UDP |
| 4 | `WARN_USB` | 违规 USB 设备 | UDP |
| 5 | `WARN_CASCADE` | 违规级连（私接 DHCP） | UDP |
| 6 | `WARN_WEAKPASS` | 弱口令命中 | UDP |
| 7 | `SUBNET_SCAN` | 子网设备探测结果 | HTTP（大数据） |

> 值 1/2/3 与 `ifw_udp_receiver` 现有 `warning_type`（1/2/3）严格对齐——**禁止改编号，只能扩展**。

## Payload 约束
- **UDP 方向**：受 naion CSM client→server 预算限制，application payload ≤ **856 字节**。用 `#pragma pack(push,1)` 紧凑二进制。
- **HTTP 方向**（大数据，如 `SUBNET_SCAN` 全量、详细取证）：走 `send_http`，无 856B 限制。
- 大字段（IP 列表、长文本）**只放摘要 + ID 走 UDP**，详情走 HTTP。

## 各事件 payload 结构
> ⏳ 具体字段在 `ifw/client/windows/src/_event.hpp`（及 Linux 对应头）落细。原则：固定头 + 变长字段，UDP 类每个 ≤856B。

- `HEARTBEAT` / `WARN_OUTBOUND_*` (1/2/3)：沿用现有 udp_receiver 的 29B 心跳 / 30B 告警布局（`client_protocol_version / app_version / config_version / client_unix_time / mac[6] / adapter_score` + warning_type）。
- `WARN_USB` (4)：待定（VID/PID/设备描述/序列号等）。
- `WARN_CASCADE` (5)：待定（违规 DHCP 服务器的 IP/MAC/server identifier/offer 摘要）。
- `WARN_WEAKPASS` (6)：待定（命中用户名/弱口令标识，**绝不含真实 NTLM hash**）。
- `SUBNET_SCAN` (7)：HTTP，全量 IP+MAC 设备列表。

## 上报通道
插件通过 `ctx->host_api->send_udp(event_type, payload, len)` 或 `send_http(...)` 上报。naion CSM 加密、路由到对应接收服务、重试由 afw 统一处理；插件只产生事件。

## 数据拉取（待定）
弱口令等插件需从服务端拉取数据集（走 HTTP 下行）。Host API 的 `get_resource` / `fetch` 回调形式待 Phase 0A 后续或 Phase 0C 确定。
