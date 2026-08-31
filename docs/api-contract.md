# Mirage-rs Web API 契约

> **用途**: 独立前端 (UI 控制 + 监控界面) 项目对接本后端的契约基线。盘点 mirage 现有 (由内置 WebUI 使用的) HTTP API,
> 供未来把 UI 拆成独立仓库时照此实现。**这是现状快照, 不是新设计** —— 现网 WebUI 已在用这套。

版本: 对应 mirage-rs `v0.10.6`(盘点日 2026-08-30)。此文档随 API 变更同步更新, 与代码同仓。

---

## 1. 传输 / 鉴权 / 现状缺口

- **传输**: HTTP/1.1, JSON。由 mirage 内置 axum 服务 (`gui.enabled=true`, 默认 `127.0.0.1:9090`)。仅在 `gui` 编译特性 (默认开) 下存在。
- **后端为纯 API** (v0.10.8+): 已**不再内嵌前端页面** —— UI 独立为 [Mirage-console](https://github.com/zdgt0226/Mirage-console), 经 `/api/v1` + Bearer + CORS 对接。裸后端根路径 `/` 返回**公开指引 JSON** (`{service, api, ui, note}`, 无鉴权、无敏感数据), 而非页面。
- **鉴权** (`gui.token` 配了才启用; 不配 = 无鉴权, 仅适合 localhost):
  - Token 三种载体, 按优先级: `Authorization: Bearer <token>` → `mirage_token` cookie → `?token=`(**仅 `/` 根路径接受**, `/api/*` 不接受 —— token 进 URL 会落历史/Referer/反代日志)。
  - 常量时间比较 (防时序侧信道) + 认证失败按源 IP 限流 (防字典爆破)。
  - **CSRF**: `Bearer` header 天然抗 CSRF; cookie 会被浏览器跨站自动携带故需防护。**独立前端 (跨 origin) 一律用 `Authorization: Bearer`。**
- **响应约定**: 监控类直接返数据对象; 控制/读写类带 `status: "success"|"error"` 信封 (见各 endpoint)。HTTP 状态码目前基本恒 200, 成败看 body 的 `status` (改进点见 §5)。

### 独立前端对接现状
1. **CORS** ✅ 已支持 (v0.10.7) —— 配 `gui.cors_origins`: `[]` 默认不发 ACAO (仅同源, 向后兼容); `["https://ui.example.com", ...]` 精确白名单; `["*"]` 任意 origin。放行 `GET/POST/OPTIONS` + `Authorization`/`Content-Type` 头, 预检 OPTIONS 由后端在鉴权前直接应答。Bearer 鉴权非 cookie 故不配 `Allow-Credentials`。
2. **版本前缀** ✅ 已加 (v0.10.7) —— 所有 endpoint 同时挂在 `/api/*` (向后兼容内置 WebUI) 与 **`/api/v1/*`** (独立前端用此冻结契约)。鉴权中间件对两前缀一致生效。
3. **契约无机读格式** 🟡 —— 无 OpenAPI/JSON Schema。本文档是人读契约; 若前端要生成类型, 后续可补 OpenAPI。

---

## 2. 共享数据类型

```jsonc
// ConnSnapshot (连接快照)
{ "id": 0, "target": "example.com:443", "inbound": "tp", "outbound": "proxy",
  "proto": "tcp", "process": "curl"|null, "source": "10.0.0.2"|null,
  "age_ms": 1234, "up": 512, "down": 8192, "closed": false }

// OutboundStat (出站聚合)
{ "tag": "proxy", "up": 0, "down": 0, "conns": 0, "live": 0 }

// DomainStat (域名排行项)
{ "host": "example.com", "conns": 0, "up": 0, "down": 0 }

// DeviceStat (设备/来源项)
{ "ip": "10.0.0.2", "conns": 0, "up": 0, "down": 0, "idle_ms": 500 }
```
> 字节数 `up`/`down`、`conns` 均为 u64。`cookie` (bpf tunnels) 是 **字符串化的 u64** (避开 JS 2^53 精度), 前端用 `BigInt(string)` 接。

---

## 3. 监控 endpoint (只读, GET)

| # | Path | 响应 schema |
|---|---|---|
| 1 | `/api/overview` | `{ up, down, connections, bpf_success, bpf_fallback, xdp_attached, engine_online, tunnel_count, brutal_cc_active, mode: "server"\|"client" }` — 顶部汇总卡 + 运行模式 (前端据此分服务端/客户端视图) |
| 2 | `/api/connections` | `{ active: [ConnSnapshot], recent_closed: [ConnSnapshot] }` — 活跃 + 最近关闭 (环形, ≤300) |
| 3 | `/api/stats` | `{ outbounds: [OutboundStat], rules: [{index, outbound, hits}], default: {outbound, hits} }` — per-出站流量 + per-规则命中 |
| 4 | `/api/domains` | `{ domains: [DomainStat] }` — top-30 by 流量 |
| 5 | `/api/devices` | `{ devices: [DeviceStat] }` — 客户端=LAN 设备 / 服务端=连接的客户端 |
| 6 | `/api/history` | `{ up: [n...], down: [n...], bpf_success: [n...] }` — 过去 120s 每秒采样的速率数组 |
| 7 | `/api/logs` | `{ logs: [string...] }` — 内存日志缓冲 (Terminal 面板) |
| 8 | `/api/bpf/tunnels` | `{ tunnels: [{ cookie: "str", remote: "host:port", rtt_ms, cwnd, retrans, data_segs }] }` — eBPF sockops TCP 指标 (仅 eBPF 客户端有; 服务端/lite 空) |

---

## 4. 控制 / 读写 endpoint

### 4.1 客户端管理 (服务端有意义)
- **GET `/api/clients`** → `{ clients: [{ ip, conns, up, down, idle_ms, blocked: bool, version: "x.y.z"|null }], blocked: [ip...] }`
- **POST `/api/clients/block`** `{ ip: "1.2.3.4", blocked: true }` → `{ status:"success", ip, blocked }` | `{ status:"error", message:"invalid IP" }` — 屏蔽/解屏蔽。**鉴权+CSRF**。

### 4.2 出站组切换 (Selector/Urltest)
- **GET `/api/proxies`** → `{ proxies: [{ tag, type: "Selector"|"UrlTest", children: [{ tag, latency_rtt_ms, latency_http_ms }], selected: "tag" }] }`
- **POST `/api/proxies/select`** `{ group: "auto", target: "node-hk" }` → `{ status:"success", message }` | `{ status:"error", message:"Group or target not found" }`。**鉴权+CSRF**。仅 `Selector` 组可手切。

### 4.3 路由规则读写
- **GET `/api/rules`** → `{ status:"success", rules: <routing.rules 数组>, outbounds: [tag...] }` | `{ status:"error", message }`
- **POST `/api/rules?dry_run=0|1`** body `{ rules: <数组> }` → 写响应 (见下)。**鉴权+CSRF**。整份候选 config 结构+语义校验, 拒绝会写坏的提交; 原子写 + 触发热重载。

### 4.4 用户策略 / 设备分配读写
- **GET `/api/profiles`** → `{ status:"success", profiles: {...}, device_profiles: [...], outbounds: [tag...] }` | error
- **POST `/api/profiles?dry_run=0|1`** body `{ profiles: {...}, device_profiles: [...] }` → 写响应 (见下)。**鉴权+CSRF**。同 rules 的校验+原子写模式。

#### 写响应 (rules / profiles POST 通用)
```jsonc
// 成功写入
{ "status": "success", "written": true, "issues": [ "告警字符串..." ] }
// dry-run (只校验不写)
{ "status": "success", "dry_run": true, "written": false, "issues": [...] }
// 失败 (未写盘, 原 config 未动)
{ "status": "error", "stage": "read"|"serialize"|"validate"|"write", "message": "..." }
```
> `issues` = 语义告警 (如规则引用不存在的出站), 成功也可能非空 (热重载会看到同样告警)。
> rules/profiles 两端点共用 `config.json` + 同名 `.tmp`, 后端已用 `CONFIG_WRITE_LOCK` 串行化, 前端并发保存安全。

---

## 5. 独立前端落地建议

- **实时数据**: 现无 WebSocket/SSE, 前端**轮询**。建议节奏: `/api/overview` `/api/connections` ~2s; `/api/history` ~1-2s (它本身是每秒采样的窗口); `/api/stats` `/api/domains` `/api/devices` ~5s; `/api/logs` 按需。想更顺再上 **SSE** (单向、CORS 友好、比 WS 简单) —— v1 不必。
- **鉴权**: 统一 `Authorization: Bearer <gui.token>`。别用 cookie/query。
- **模式分支**: 读 `/api/overview.mode` 决定渲染服务端视图 (clients/domains/history) 还是客户端视图 (devices/LAN)。
- **后端改造** (拆分前): ✅ CORS (`gui.cors_origins`) + ✅ `/api/v1/*` 前缀 已在 v0.10.7 完成。剩余可选:
  1. (可选) 让 HTTP 状态码反映成败 (4xx/5xx), 而非恒 200 看 body `status`
  2. (可选) 补 OpenAPI 供前端生成类型

## 6. 端点速查
```
GET  /api/overview          GET  /api/connections     GET  /api/stats
GET  /api/domains           GET  /api/devices         GET  /api/history
GET  /api/logs              GET  /api/bpf/tunnels
GET  /api/clients           POST /api/clients/block
GET  /api/proxies           POST /api/proxies/select
GET  /api/rules             POST /api/rules?dry_run=
GET  /api/profiles          POST /api/profiles?dry_run=
```
