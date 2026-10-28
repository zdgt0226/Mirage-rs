# Mirage-rs

![Mirage-rs](https://img.shields.io/badge/Language-Rust-f74c00.svg) ![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg) ![Version](https://img.shields.io/badge/Version-v0.16.2-10b981.svg)

基于 **Rust** 与 **Tokio** 重写的高性能、抗审查代理引擎。提供内核级 eBPF 加速、TLS 指纹仿真伪装与内置 Web 看板。

> **定位**: 面向自建跨境线路的个人与小团队（墙外 VPS + Linux 网关），主打「零配置 eBPF 透明网关」与抗被动识别。

> ⚠️ **安全与运行声明 (务必先读)**:
> - 🔴 **v0.15 协议断代 (BREAKING)**: 握手 token 绑定 `ClientHello.random`，会话密钥混入服务端新鲜随机数（防重放），修复 cipher agility 协商 ChaCha 时的 nonce 复用。**与 v0.14 及更早版本（含 Android 客户端）互不兼容，必须两端同时升级**，无兼容开关。版本兼容矩阵与迁移步骤参见 [`docs/version-compatibility.md`](docs/version-compatibility.md)，协议设计见 [`docs/protocol-freshness-design.md`](docs/protocol-freshness-design.md)。
> - **未经专业安全审计**: 加密分帧 (ChaCha20-Poly1305) 与握手认证自研，仅经 LLM 复核与真机验证，**没有**独立安全公司审计，请勿用于生命安全级场景。
> - **前向保密 (PFS) 可选 (默认关闭)**: 默认会话密钥由共享口令+双方随机数派生。两端配置 `"pfs": true` 可开启一次性 X25519 ECDH（公钥搭 fake-TLS random 传输，零指纹变化），口令泄露亦无法解密历史录包。**两端必须同开**。PFS 只保护会话内容，**不防口令被猜**：抓到一次握手即可离线逐个试口令，所以无论是否开启 PFS，均应使用高强度随机口令（启动时对少于 16 个字符的服务端口令给出提示）。
> - **多用户凭据与配额限速 (`mirage_server.users[]`)**: 支持多用户独立口令、per-user 密钥隔离、用量统计、独立限速与按月配额（超额静默回落伪装站，存量连接即断）。改密/删用户在下一数据块或超时内断开会话（QUIC 10s、UDP mux/直连 300s、TCP 1800s）。Console 可通过 `/api/users` 动态管理（绝不回显密码）。不配 `users` 即单共享口令。口令为唯一凭据，无二次因子。
> - **服务端出站防 SSRF / 内部网络隔离**: 服务端直连出站默认拦截回环 (`127.0.0.0/8`, `::1`)、链路本地 (`169.254.0.0/16`, `fe80::/10`)、常见云元数据地址 (AWS `fd00:ec2::254`、阿里云 `100.100.100.200`、Azure WireServer `168.63.129.16`) 及本机网卡自身地址；RFC1918 私网默认放行。如需访问本机/链路本地需显式开启 `"allow_local_targets": true`。
> - **负责任使用**: 本工具用于保护合法流量的隐私与可达性，请自行评估并在遵守当地法律法规的前提下使用。
> - **运行环境要求**: **Linux 内核 ≥ 5.10**（eBPF 透明网关依赖 `sk_lookup` 5.9+ / `sk_assign` 5.7+ / XDP DNS）。轻量/SOCKS 模式及服务端不需要 eBPF，常规较新 Linux 均可运行。

---

## 核心特性

* **极致传输与伪装**: TLS 1.3 ClientHello 字节级仿真（Chrome/Firefox/Android-Conscrypt 多 Profile 轮换）、TCP Brutal 拥塞控制、无锁化异步架构。支持 `mirage tls-capture` / API 抓取真浏览器指纹模板（`client_hello_template`），精准复刻 JA3/JA4。
* **可选前向保密 (PFS)**: 两端开启 `"pfs": true` 启用一次性 X25519 ECDH，公钥复用 fake-TLS random 字段交换，零指纹变化。
* **多用户凭据与配额限速**: `mirage_server.users[]` 支持独立口令、流量/连接统计、独立限速 (`rate_limit_kbps`) 与按月配额 (`quota_gb`, `quota_reset_day`)。超额自动断连并回落伪装，API 动态管理。
* **eBPF 透明网关**: 基于 `sk_lookup` / `tc_divert` 实现内核级透明代理，内置抗风暴 DNS 与 Fake-IP 加速；支持 Fake-IP ICMP echo 本地反射（LAN 客户端 ping 被代理域名可通）。无 eBPF 环境自动回落。
* **全场景出站与服务端路由**: 支持直连、WireGuard 与 Shadowsocks (SIP004/SIP022) 出站及多上游中转；服务端支持基于完整 RouterEngine 的出站选路（多上游分流与全局落地双模式、惰性域名解析、user 用户条件规则）与配置原子热重载。
* **高维路由引擎**: 支持按域名、GeoIP/GeoSite、IP CIDR、进程名 (`process_name`)、源设备/网段 (`source_ip_cidr`) 分流。支持裸 IP SNI 嗅探与 SOCKS5 UDP 逐包路由。
* **智能 DNS 解析**: Fake-IP 引擎（支持 `fakeip.exclude` 排除）+ DNS 规则层 (`advanced_dns.rules` 分流/静态解析/拦截) + 灰域名自适应分类 (`auto_classify`) + 可选局域网 53 端口劫持与 IP 版本策略。
* **Geo 规则自动更新**: `geo_sources` 多源下载校验 + 文件变动监视热重载（新 `.dat` 落地即刻重建路由，无需重启）+ 完整性自检。
* **内置 Web 看板**: Mirage Console 现代控制台（暗/亮主题、中/英双语），提供流量监控、连接管理、规则可视化编辑（含 dry_run 预检与拖拽排序）。按服务端/客户端提供专用视图（LAN 设备管理/客户端管理）。
* **供应链完整性**: Release 二进制 (SHA256SUMS) 与多架构容器镜像 (`ghcr.io`) 均通过 **cosign keyless** (Sigstore OIDC + Rekor) 签名与透明日志审计。

---

## 安装部署

### 一键安装 (推荐)

alpha.4+ 起提供交互式安装向导 `install.sh`（需 root 权限），自动完成：
- 下载最新预编译二进制至 `/usr/local/bin/mirage-rs`（双通道 SHA256 校验）。
- 探测公网 IP、端口占用与 Brutal 内核模块（可选 v2 按客户端分组限速 / v1.0.3 兼容老内核）。
- 生成配置文件并注册 systemd 服务（完整版 `mirage-rs-{server,client}`，轻量版 `mirage-rs-lite-{server,client}`）。
- 交互配置 GUI 端口、SNI 伪装、Brutal 速率、Geo 分流策略与可选 Shadowsocks 上游。
- 非回环监听时强制设置入站认证密码，防止开放代理。
- 服务端配置完成后直接输出 `mirage://` 节点 URI 与二维码，客户端一步导入。

```bash
# 一键运行 (1=服务端 / 2=客户端 / 3=同机 / 4=更新二进制 / 5=显示节点 / 6=卸载)
# 选完 1/2/3 后会再问一次「部署形态」: 完整版 or 轻量版
curl -fsSL https://raw.githubusercontent.com/zdgt0226/Mirage-rs/main/install.sh | sudo bash
# 或先 clone 再看内容:
git clone https://github.com/zdgt0226/Mirage-rs.git && cd Mirage-rs
sudo bash install.sh
```

服务状态管理: `sudo systemctl status mirage-rs-{server,client}` (轻量版对应 `mirage-rs-lite-{server,client}`)。

> **手动下载 Releases 二进制**: glibc 版需 glibc ≥ 2.34，旧版系统（如 Debian 11 / CentOS 8）请选择 `-musl` 版；`install.sh` 默认下载 musl 版。

### 容器镜像 (多架构 amd64/arm64)

```bash
docker run --rm -v /etc/mirage-rs:/etc/mirage-rs \
  ghcr.io/zdgt0226/mirage-rs:latest server -c /etc/mirage-rs/config_server.json
```

### 验证产物签名 (cosign keyless)

Release 发布的 `SHA256SUMS` 与容器镜像由 CI 通过 **cosign keyless**（Sigstore OIDC 身份验证，透明日志 Rekor）签名，无需长期公钥即可完成独立审计：

```bash
# 校验和签名 (下载 SHA256SUMS + SHA256SUMS.cosign.bundle 后)
cosign verify-blob --bundle SHA256SUMS.cosign.bundle \
  --certificate-identity-regexp '^https://github.com/zdgt0226/Mirage-rs/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  SHA256SUMS
sha256sum -c SHA256SUMS --ignore-missing

# 容器镜像签名
cosign verify ghcr.io/zdgt0226/mirage-rs:latest \
  --certificate-identity-regexp '^https://github.com/zdgt0226/Mirage-rs/\.github/workflows/release\.yml@refs/tags/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

### 从源码构建

```bash
cargo build --release                             # 纯用户态版 (默认, 含 Web 看板, 无需 clang)
cargo build --release --features ebpf             # 含 eBPF 透明网关 (需 clang + llvm)
cargo build --release --no-default-features        # headless: 剔掉整个 Web 看板 (无 axum/HTTP 面)
# headless + ebpf: cargo build --release --no-default-features --features ebpf
cargo build --release --features quic              # 含 QUIC 实验传输 (transport:"quic"; ⚠️ P0 不隐蔽)
```

- **Web 看板编译特性 (`gui`)**: 默认开启。纯服务端或无面板环境可用 `--no-default-features` 剔除，消除 HTTP 监听攻击面并减小二进制体积。
- **eBPF 特性依赖**: `--features ebpf` 需系统安装 `clang`、`llvm` 与 `libbpf-dev`。默认用户态构建无需 clang。

---

## 部署形态

### 轻量模式 (SOCKS5 隧道)

若仅需「本机 SOCKS5 → 全量走隧道」而无需分流、DNS 劫持、透明代理与看板，可使用轻量模式。轻量模式与完整版使用同一二进制与协议伪装，彼此完全互通。

| 特性维度 | 完整版 (Full Gateway) | 轻量版 (Lite Mode) |
| :--- | :--- | :--- |
| **典型定位** | 局域网透明网关 / 规则分流代理 | 本机极简 SOCKS5 代理客户端 / VPS 服务端 |
| **内核门槛** | 依赖 Linux ≥ 5.10 (eBPF 模块) | 无内核版本门槛 (纯用户态) |
| **分流与 DNS** | GeoIP/GeoSite 分流、Fake-IP 引擎 | 全量转发，无规则分流与独立 DNS |
| **传输协议** | TCP + UDP (含 UDP mux / QUIC) | 仅 TCP (SOCKS5 UDP 请求规范返回 0x07 拒绝) |
| **加密与伪装** | TLS 仿真、握手认证、Brutal、PFS、回落 | 完全一致 (零阉割) |
| **管理界面** | Mirage Console Web 看板 | 仅 CLI / 配置文件 |

手动运行命令:

```bash
mirage-rs lite-server -c lite_server.json    # 墙外 VPS
mirage-rs lite-client -c lite_client.json    # 本机
```

配置为极简平铺格式。完整注释模板参见 [`templates/lite_server.jsonc`](templates/lite_server.jsonc) 与 [`templates/lite_client.jsonc`](templates/lite_client.jsonc):

```jsonc
// lite_server.json —— 仅 password 必填, 其余都有默认值
{
  "listen": "0.0.0.0",
  "port": 443,                    // 端口可自由自定义, 不限于 443
  "password": "你的密码",
  "sni": "www.apple.com"
}

// lite_client.json —— server / server_port / password 必填
{
  "listen": "127.0.0.1", "port": 1080,      // 本地 SOCKS5, 默认值可省
  "server": "1.2.3.4", "server_port": 443,  // server_port 须与服务端 port 一致
  "password": "你的密码",
  "sni": "www.apple.com",                    // 须与服务端一致
  // 监听 0.0.0.0 时强烈建议设置, 否则是开放代理:
  "auth": { "username": "u", "password": "p" }
}
```

> **注意**: 服务端端口 443 伪装效果最佳，非 root 运行需授予 `CAP_NET_BIND_SERVICE` 或改用 >1024 端口。客户端 `server_port` 必须与服务端 `port` 一致。

---

### 服务端出站与路由 (中转站与多落地)

Mirage 服务端顶层 `outbounds` 与 `routing` 完整生效，复用客户端的高性能 `RouterEngine`。无需额外全局开关，仅靠配置即可自然表达两种常见拓扑：

```text
客户端 ──(Mirage 隧道)──▶ Mirage 服务端 ──(路由分流: Direct / SS / WG)──▶ 多上游出口 / 目标
```

- **模式一（直连为主，按规则分流到上游）**：`default_outbound: "direct"`，将特定流媒体、域名或指定用户路由至 Shadowsocks 或 WireGuard 落地机；
- **模式二（全量走落地，特定流量拉回直连）**：`default_outbound: "<某上游 tag>"`，所有客户端流量默认经落地机出海，通过规则将特定流量拉回 direct 直连。

#### 模式一配置示例 (直连为主 + 按规则分流)

```jsonc
{
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    {
      "type": "shadowsocks",
      "tag": "ss-hk",
      "server": "192.0.2.10",
      "server_port": 8388,
      "password": "ss-password-16B",
      "method": "aes-256-gcm",
      "udp": "block"            // block(默认) | direct: SS UDP 未实现, 默认丢弃防从本机泄露
    },
    {
      "type": "wireguard",
      "tag": "wg-jp",
      "endpoint": "192.0.2.20:51820",
      "private_key": "<base64>",
      "peer_public_key": "<base64>",
      "address": "10.0.0.2/32"  // WG 出站 UDP 全量隧道转发
    }
  ],
  "routing": {
    "default_outbound": "direct",
    "rules": [
      { "outbound": "ss-hk", "geosite": ["netflix"] },
      { "outbound": "wg-jp", "domain_suffix": ["jp.example"] },
      { "outbound": "ss-hk", "user": ["vip-user"] }
    ]
  }
}
```

#### 模式二配置示例 (全量走落地 + 特定流量拉回直连)

```jsonc
{
  "outbounds": [
    { "type": "direct", "tag": "direct" },
    {
      "type": "wireguard",
      "tag": "wg-landing",
      "endpoint": "192.0.2.30:51820",
      "private_key": "<base64>",
      "peer_public_key": "<base64>",
      "address": "10.0.0.2/32"
    }
  ],
  "routing": {
    "default_outbound": "wg-landing",
    "rules": [
      { "outbound": "direct", "geoip": ["cn"] },
      { "outbound": "direct", "domain_suffix": ["local.example"] },
      { "outbound": "direct", "port": [22, 80, 443] }
    ]
  }
}
```

#### 关键机制与运维要点

- **选路优先级**: 单个入站上的旧 `upstream` 字段（按接入端口指定）享有最高优先级，**不经路由**（严格保持向后兼容）；否则走服务端路由；未配置 `routing` 段时等价于全部 direct。
- **用户维度分流**: `Rule` 支持新增 `user: Vec<String>` 条件匹配命中的用户名（单用户固定为 "default"，多用户为各用户名，客户端无用户信息时不匹配）。
- **域名惰性解析**: 仅当匹配到 IP 类规则（`ip_cidr` / `geoip`）且目标为域名时才会触发 DNS 解析，避免对常规域名做无意义前置解析。
- **Fail-Closed 故障绝不回退**: 上游连接失败时直接报错断连，**绝不静默回退 direct**，避免悄悄换成中转机出口 IP 导致落地判定失败或泄露真实 IP。
- **QUIC 传输行为**: QUIC 传输经路由若命中非 direct 出站将以限频告警直接拒绝该流（建议改用 TCP 传输或调整路由）。
- **原子热重载**: 运行时修改 `outbounds` 与 `routing` 自动生效，通过 `ArcSwapOption` 原子替换，老连接维持，新连接即刻使用新配置，无需重启服务。
- **管理与工具**:
  - `install.sh` 主菜单 `9) 管理服务端出口与路由`：提供出站增删、设置默认出口、分流规则增删（支持多条件类型与目标出站选择）、旧入站 `upstream` 一键迁移至独立出站（原子改写、备份 `.bak`、`check -c` 闸门与热重载即时生效）。
  - 主菜单 `5) 查看服务端节点信息`：若配置了 WG 出站，展示 endpoint、隧道内 IP 及通过 `mirage-rs wg-pubkey` 派生的本机公钥（隐藏私钥）。
  - WireGuard 密钥工具：`mirage-rs wg-keygen [--psk]` 生成公私钥对与 PSK，`mirage-rs wg-pubkey` 从私钥推导公钥。

---

### 干净设备接入 (WireGuard 入站)

移动设备通过系统原生 WireGuard 连接家庭网关，网关利用 eBPF 透明拦截并将流量送入 Mirage 隧道出海。移动端仅保留标准 VPN 配置，无任何代理工具痕迹：

```
[手机 原生 WireGuard] ──家域内 WG(不跨 GFW)──▶ [家中网关: wg0 + eBPF 透明 + Mirage] ──▶ 海外
```

- **一键配置**: 在已配置透明网关的机器上运行 `install.sh` 选 `7) 家庭 WireGuard 服务端 (干净设备接入)`，自动创建 `wg0` (`10.7.0.1/24`) 与 NAT，并生成 peer 配置文件与二维码 (`/etc/wireguard/peer-<名字>.conf`)，支持多次追加设备。
- **实现原理**: 透明拦截按 Fake-IP 目标匹配而非 `SO_MARK`。`sk_lookup` 挂载于 netns 且不绑定特定网卡，`wg0` 接收的目的地为 Fake-IP 的报文自动触发透明代理，国内流量正常转发。
- **关键前提**: 移动端 DNS 必须指向网关地址 (`10.7.0.1`)，不能改用公共 DNS，否则域名无法解析为 Fake-IP。
- **已知限制**: 少数绕过 DNS 的裸 IP 直连流量从 `wg0` 接入时不会被拦截（`tc_divert` 绑定物理网卡）。

---

## 配置说明

### 服务端配置示例 (`/etc/mirage-rs/config_server.json`)

<details>
<summary>点击展开查看: 服务端完整配置示例</summary>

```json
{
  "schema_version": 1,
  "log_level": "info",
  "log_file": "/var/log/mirage-rs/server.log",
  "inbounds": [
    {
      "type": "mirage_server",
      "tag": "mirage-in",
      "listen": "0.0.0.0",
      "port": 443,
      "password": "your-strong-password",
      "camouflage_host": "www.cloudflare.com",
      "brutal_rate_mbps": 50
    }
  ],
  "outbounds": [
    { "type": "direct", "tag": "direct" }
  ],
  "gui": {
    "enabled": true,
    "listen": "127.0.0.1:9090"
  },
  "routing": {
    "default_outbound": "direct",
    "rules": []
  },
  "tuning": {
    "geodata_dir": "/etc/mirage-rs/geosite"
  }
}
```

</details>

### 关键配置要点

- **伪装域名 (`camouflage_host`)**: 必须与客户端严格一致。建议选取与 VPS 同 ASN 或同 IP 段的真实 HTTPS 站点以抵御 SNI 与 IP 归属一致性检查，可运行 `tools/find_camouflage.py` 扫描本地 ASN 获取候选。
- ⚠️ **Web 看板安全 (`gui`)**: `gui.listen` 默认为 `127.0.0.1`。若绑定 `0.0.0.0` 开放至局域网或公网，**必须配置 `gui.token`**（API 请求通过 Bearer token / Cookie / URL 参数校验，带常量时间比对防时序攻击；未设 token 时仅允许 IP/localhost 访问以防 DNS rebinding）。
- **出口 UDP 被阻断的 VPS**: 若 VPS 无法向外发送 UDP 53 数据包，配置 `"tuning": {"dns_tcp_resolver": "1.1.1.1"}` 强制进程级域名解析走 TCP。
- **UDP 多路复用 (`tuning.udp_mux`)**: 网关存在大量并发 UDP（如 QUIC/游戏）时，开启 `"tuning": {"udp_mux": true}` 可将并发流散列复用到少量共享隧道（默认 4 条），突破连接池带机量瓶颈（实测并发能力提升 22.5×，需服务端同步开启）。高并发下建议调大服务端 `LimitNOFILE`。老服务端不认 mux，相关 UDP 流回落 TCP；代价是同隧道内跨流队头阻塞（可调大 `udp_mux_tunnels` 分摊）。
- 详细客户端与网关配置示例参见 `templates/` 目录中的注释版模板。

---

## CLI 用法

### 常用子命令

```bash
# 校验 / 格式化配置 (启动前闸门; check 挑未知字段+悬空引用, format 保留键序不吞字段)
mirage-rs check  -c config.json
mirage-rs format -c config.json

# 导入单个节点 URI (交互问 tag, 不撞现有; --test 测活, --require-live 不通则不导, --group 建 urltest 组)
mirage-rs import -c config.json "mirage://密码@host:443?sni=www.apple.com"

# 订阅批量导入: 来源可为 URL 或本地文件; 内容可为 mirage:// 列表 或 export 的 JSON 片段
mirage-rs subscribe -c config.json https://example.com/sub    # 远程 mirage:// 列表 (--group 建组)
mirage-rs subscribe -c config.json share.json                 # 合并本地 JSON 片段
mirage-rs subscribe -c config.json --routing share.json       # 连路由规则一起并 (侵入, 默认不并)

# 导出配置片段 (subscribe 的反向): 交互选节点 + 匹配的组/路由/geo → 可分享 JSON
mirage-rs export -c config.json -o share.json                 # 无 -o 则写 stdout (提示走 stderr)

# 测节点可用性 (完整 Mirage 握手+认证, 非裸 TCP; 显 RTT + [国家码]; 默认穿隧道 HTTP 探测)
mirage-rs test -c config.json                                 # --tag 只测某个; --no-http 关探测

# 交互式配置管理 (节点增删改查 / 协议参数 / 多用户管理 / 待保存改动 diff / 校验与热重载/重启辅助)
mirage-rs config -c config.json
```

> **出站组类型**: 支持 `urltest` (低延迟自动优选)、`fallback` (故障转移)、`selector` (手动指定)、`load_balance` (轮询负载均衡)。`test` 与 `--group` 建组会读取 `geoip.dat` 校验节点地域并在混杂时发出告警。

### 配置文件生效策略

| 配置维度 | 改动项目 | 生效策略 | 说明与机制依据 |
| :--- | :--- | :--- | :--- |
| **路由 (Routing)** | `rules` 增删改、`default_outbound` 切换、`profiles` / `device_profiles` 策略、`geo_alias` | **自动热重载** | `config_watcher` 监听文件写入，约 1 秒内重建 `RouterEngine`，已有连接不中断 |
| **用户与凭据** | `mirage_server` 的 `users` 增删改、密码变动、`rate_limit_kbps` 限速、流量配额及主密码 | **自动热重载** | 动态热替换凭据注册表与限额器；删除或改密后立即吊销对应存量会话 |
| **Geo 规则数据** | `tuning.geo_sources`、`tuning.geo_update_days` 及本地 `.dat` 文件更新 | **自动热重载** | 重建更新调度器，新 `.dat` 文件落地自动重编路由规则集 |
| **出站 (Outbounds)** | 增删节点、修改端口/密钥/伪装/传输方式/连接池/组成员 | **需重启服务** | 防止在途连接断裂与连接池任务泄漏，热重载保持既有出站不变 |
| **入站 (Inbounds)** | 监听端口 `port` / `listen`、`transport`、PFS、伪装站、Brutal、`allow_local_targets`、增删入站 | **需重启服务** | 监听 socket 与传输栈在启动阶段绑定，修改后需重启释放或接管端口 |
| **核心调优 (Tuning)** | `tls_padding`、`cipher_agility`、`ebpf_mode`、`dns_tcp_resolver`、`client_hello_guard` | **需重启服务** | 加密策略与系统级解析器在进程启动初始化阶段生效 |

> `mirage-rs config` 严格按照上表规则判定：仅热重载项自动生效，其余项给出明确重启提示。`mirage://` 链接仅包含密码/地址/端口/SNI 四项，若服务端启用了 `pfs`、`transport: "quic"`、`tls_padding` 或 `cipher_agility`，客户端导入后需手动匹配相应参数。

---

## 路线图 (Roadmap)

> 图例: `[x]` 已完成并发布 · `[~]` 进行中 / 部分完成 · `[ ]` 计划中 / 候选池。

### ✅ 已完成

- [x] **透明网关与传输加速**: eBPF 透明网关全链路跑通 (TCP + UDP + 隧道 + 回源)；TCP Brutal 拥塞控制支持 group_id（按客户端 IP 分组共享带宽，v1 模块自动回落）；MSS clamp 内联 `tc_divert` 自动按 MTU 下发防 PMTU 黑洞。
- [x] **TLS 仿真与抗识别**: TLS 1.3 ClientHello 字节级仿真（三 Profile 轮换 + 后量子 key_share）；指纹捕获与回放（`mirage tls-capture` 提取真浏览器指纹存入 `client_hello_template`）；定长填充整形 (`tls_padding_scheme` 抹除握手 burst 指纹）。
- [x] **安全与认证体系**: 协议新鲜性加固（v0.15 断代：双随机 master salt 派生 + token tag 绑定 random，防重放与伪造）；可选前向保密 PFS（一次性 X25519 ECDH + Elligator2 编码消除特征）；入站认证（SOCKS5/HTTP 认证防开放代理）；外部审计清零（API 限流、供应链门禁、模板防漂移测试、版本歪斜诊断）。
- [x] **多用户与配额限速**: `mirage_server.users[]` 多用户凭据与 per-user 密钥隔离；按用户独立限速 (`rate_limit_kbps`) 与按月流量配额 (`quota_gb`, `quota_reset_day`)，超额断连回落；`/api/users` 动态管理与凭据热重载吊销。
- [x] **出站与中转接入**: 轻量模式 (`lite-server` / `lite-client`)；Shadowsocks 上游 (SIP004/SIP022)；WireGuard 出站与上游中转；统一出站流接口 (`OutboundNode::connect`)；**服务端出站与路由引擎**（顶层 `outbounds` 与 `routing` 生效、多上游分流/落地双模式、`user` 规则条件、配置原子热重载、WG 密钥生成工具）。
- [x] **高维分流与 DNS**: 路由 inbound 维度、裸 IP SNI 嗅探与 SOCKS5 UDP 逐包路由；DNS 规则层 (`advanced_dns.rules` 分流/静态/拦截)；局域网 53 端口劫持与 IP 版本策略；进程名分流 (`process_name`)；灰域名自适应分类 (`auto_classify`)。
- [x] **性能调优与架构**: Cipher agility 自动协商硬件加速 AES-256-GCM（`tuning.cipher_agility`）；UDP 多路复用 (`tuning.udp_mux` 突破并发带机量瓶颈)；IPv6 隧道传输支持；隧道 relay 缓冲调优 (上行 64KB buf + greedy `try_read`)。
- [x] **运维工具与看板**: Web 看板 Mirage Console（双主题、中英双语、分角色视图、可视化规则编辑）；配置工具链 (`check` / `format` / `import` / `test` / `config`)；Geo 规则自动更新与热重载；CI 确定性回归哨兵；cosign keyless 供应链签名与多架构容器镜像。
- [x] **单隧道高 RTT 吞吐调研**: 实机确认高丢包高 RTT 链路受 TCP 固有机制限制，决定不在 TCP 侧追加多隧道单下载 striping 优化，转向 QUIC 链路。

### 🚧 进行中 / 部分完成

- [~] **订阅链接管理**: `mirage-rs subscribe <url>` 批量导入已支持，周期自动定时刷新待完成。
- [~] **LAN 设备监控与策略**: 设备分流规则 (`source_ip_cidr`)、多用户策略 (`routing.profiles` / `device_profiles`) 与用户态设备用量统计已完成；eBPF 精确统计与每主机独立 DNS 策略待完成。
- [~] **链式代理增强**: SS 双向转发、Mirage 嵌套与 WireGuard 干净设备入站已完成；自定义转发编排增强中。
- [~] **QUIC 传输链路 (实验特性)**: `--features quic` 骨架、erasure-aware CC、Salamander 混淆与证书 SPKI 固定 (`quic_pin`) 已实现，默认窗口优化为 8MB；FEC (P2) 与 pacing 层待完善。使用要点：两端同设 `transport: "quic"`，客户端必须配 `quic_pin`，暂不支持 UDP 中继，默认不隐蔽（可配 `quic_obfs`）；详见 [`docs/quic-transport-design.md`](docs/quic-transport-design.md)。
- [~] **ICMP 支持**: Fake-IP Echo 本地反射已实现（LAN 客户端 ping 被代理域名可通）；真隧道端到端 ICMP 评估后暂不实现。

### ⏳ 计划中 / 候选池

- [~] **QUIC 定速模式 (实验特性, 已实现待完善)**: 复用 `brutal_rate_mbps` 实现 QUIC 上下行定速与窗口补偿，补丁 quinn-proto 乱序上限至 8192。
- [ ] **QUIC 腿 ECH GREASE (暂缓)**: TCP 主协议已原生支持 ECH GREASE；QUIC 腿需等待底层 Rust 密码学库支持完善后再行评估。
- [ ] **orphan 验证器接回 CI**: 本地测试稳定，需重构为单进程模式以适应 GitHub Actions 共享 runner。

### 评估后决定不做（避免重复提）

- **v1/v2 协议版本开关 / 兼容旧协议**: v0.15 协议断代彻底解决了会话重放与新鲜度漏洞；老版本采用端口并行迁移，新代码不保留双协议栈技术债。
- **Tailscale 原生集成**: 官方 Rust 实现走 DERP 中继影响吞吐，建议通过系统 tailscaled 配合 Mirage 直连路由。
- **TLS session resumption 仿真**: 实测真实 Chrome 的 session_id 均为全新随机，与当前实现不可区分，立项前提不成立。
- **追平 sing-box 全部协议与规则**: 定位为轻量零配置网关，不做庞大通用代理框架。
- **io_uring 替代 relay 循环**: 实测瓶颈在 AEAD 加密 CPU 而非系统调用开销，切换无吞吐提升且增加维护负担。
- **Shadowsocks 上游 UDP 中继**: 存在出口 IP 不一致与丢包黑洞隐患，默认 block 为安全失败设计；UDP 需求建议直接使用 WireGuard 上游。

---

## 版本迭代概览 (Changelog)

详细更新记录请查阅 [`CHANGELOG.md`](CHANGELOG.md)，跨版本兼容矩阵与平滑迁移指引请参阅 [`docs/version-compatibility.md`](docs/version-compatibility.md)。

| 版本 | 发布日期 | 核心重大特性与变更 |
| :--- | :--- | :--- |
| **v0.16.2** | 2026-10-28 | **无协议变更 (可单端升级)**: 纯服务端配置不再重复加载 geosite / geoip；非 mux UDP 经 WG 出口时解析结果会话内缓存 (隧道 DNS 不通不再拖住上行)；QUIC 口令错误首个请求即告警。 |
| **v0.16.1** | 2026-10-27 | **无协议变更 (可单端升级)**: 客户端暖池建连失败指数退避 (1s→30s, 有请求等待时最快 2s 重试), 口令错误等持续失败时不再每秒数次握手打服务端, 失败日志限频。 |
| **v0.16.0** | 2026-10-27 | **无协议变更 (可单端升级)**: **服务端出站路由** —— 顶层 `outbounds` (direct / block / Shadowsocks / WireGuard, 可多个) 与 `routing` 在服务端生效，支持「默认直连 + 规则分流到上游」与「默认走落地 + 规则拉回直连」两种模式、按用户分流；出站与路由热重载；`wg-keygen` / `wg-pubkey`；`install.sh` 菜单 9 升级为「管理服务端出口与路由」。 |
| **v0.15.7** | 2026-10-27 | **无协议变更 (可单端升级)**: 上行异常截断对上游发 RST；TCP 中继双向共享空闲超时 (单向长传输不再 30 分钟被掐)；QUIC lean 异常收尾；`install.sh` 新增「修改服务端上游出口」菜单。 |
| **v0.15.6** | 2026-10-26 | **无协议变更 (可单端升级)**: 重放缓存按凭据分区 (单用户刷不满全体)；修复 SS 入站 / Mirage-over-X 首包挂死；下行异常截断对本地发 RST 不再伪装正常结束；依赖安全升级 (rustls-webpki / webpki-root-certs / ctutils / tokio)。 |
| **v0.15.5** | 2026-10-19 | **无协议变更 (可单端升级)**: 服务端全局并发上限 + 单来源未认证上限（网关 / CGNAT 不受影响）；DNS 缓存按 DO/CD/EDNS 大小分维、上游单飞、响应 Question 校验；QUIC 客户端被拒退避；握手模板防多样性塌缩；修复 TCP 规则漏匹配 Shadowsocks 出站。 |
| **v0.15.4** | 2026-10-17 | **无协议变更 (可单端升级)**: API 补齐 DNS rebinding 防护；`/api/users` 覆盖全部入站；按 IP 限速桶跨热重载保留；修复统计软链接与路径安全校验。 |
| **v0.15.3** | 2026-10-16 | **无协议变更 (可单端升级)**: 伪装站主动探测防护（按需建连、新增 `tuning.client_hello_guard`）；补充版本兼容矩阵与迁移向导；rustls 安全修复；网关 UDP 接收缓冲调优至 4MB。 |
| **v0.15.2** | 2026-10-04 | **无协议变更 (可单端升级)**: Release 首次包含实验性 **QUIC 传输** (`transport: "quic"`) 与定速模式；优化 quinn-proto 乱序上限至 8192 与 8MB 窗口；install.sh brutal 模块选项升级。 |
| **v0.15.1** | 2026-10-02 | **无协议变更 (可单端升级)**: 新增 `mirage-rs config` 交互式配置管理；服务端日志降级保护隐私；QUIC UDP 快速失败与远程 DNS 走 QUIC 流；配置校验区分同端口 TCP/UDP。 |
| **v0.15.0** | 2026-09-28 | **⚠️ 协议断代 (两端须同时升级)**: 双随机 master salt 派生与 token tag 绑定 random（消除重放与伪造）；PFS Elligator2 编码；ChaCha20 nonce 防复用；按用户限速与月度配额 (`rate_limit_kbps`/`quota_gb`)；QUIC 证书 SPKI 固定 (`quic_pin`)；出站防 SSRF (`allow_local_targets`)；凭据热重载实时吊销。 |
| **v0.14.1** | 2026-09-26 | **纯服务端审计修复**: 配置文件与备份原子写以 0600 权限创建；API DNS rebinding 防护；XDP DNS 缓存淘汰清除；域名统计表与连接池内存泄漏修复。 |
| **v0.14.0** | 2026-09-21 | **多用户凭据**: `mirage_server.users[]` 多用户独立口令与密钥隔离；用量统计与按人吊销；`/api/users` 管理接口对接 Mirage Console 用户管理页。 |
| **v0.13.3** | 2026-09-21 | **热路径压榨**: recv 借用式解密消除每帧内存分配；send 双拷贝优化；rustls 安全漏洞修复。 |
| **v0.13.0** | 2026-09-10 | **DNS 解析增强**: `fakeip.exclude` 域名排除；`advanced_dns.rules` 规则分流、静态解析与拦截；灰域名 `auto_classify` 自适应分类。 |
| **v0.12.0** | 2026-09-07 | **tcp-brutal 2.0 groups 适配**: 服务端按客户端 IP 分组共享总速率，消除多连接超发；v1 内核模块自动回落兼容。 |
| **v0.11.0** | 2026-09-04 | **TLS 指纹捕获与回放**: `mirage tls-capture` 与 API 捕获真实浏览器 ClientHello 存为模板，`client_hello_template` 精准复刻 JA3/JA4。 |
| **v0.10.0** | 2026-08-22 | **WebUI Mirage Console**: 现代化双主题仪表盘、i18n 中英双语、分角色视图、可视化规则编辑器与 Admin 局域网设备管理。 |
| **v0.9.4** | 2026-08-16 | **CI 回归哨兵**: 引入 UDP mux 容量不变量、AES/ChaCha 性能比值与 brutal 收敛轨迹等确定性守护测试。 |
| **v0.9.3** | 2026-08-14 | **前向保密 (PFS) 与供应链签名**: 一次性 X25519 ECDH；cosign keyless 产物签名与 ghcr 多架构容器镜像；代码结构重构与防漂移测试。 |
| **v0.9.2** | 2026-08-14 | **握手完整性修复**: 修复 camouflage 模板三型不齐导致的握手超时；补齐 API 认证限流与 cargo-deny 供应链门禁。 |
| **v0.9.1** | 2026-08-12 | **WireGuard 干净设备接入**: install.sh 支持原生 WireGuard 接入透明网关，终端零翻墙痕迹；抗审查泄漏护甲测试。 |
| **v0.9.0** | 2026-08-04 | **UDP 多路复用 (UDP mux)**: 透明 UDP 散列复用共享隧道突破并发瓶颈；补齐常量时间比对与 DNS-over-TCP 校验。 |
| **v0.8.1** | 2026-08-03 | **链式代理**: 统一出站流接口 `OutboundNode::connect`；Mirage 嵌套与 Shadowsocks 双向中转支持。 |
| **v0.8.0** | 2026-08-02 | **TLS 填充整形**: 握手后数据追加原生零填充抹除包长序列特征；外部审查防御加固与规则校验 API。 |
| **v0.7.0** | 2026-07-30 | **Cipher Agility 与 IPv6 传输**: 硬件加速 AES-256-GCM 密闭协商；服务端 IPv6 监听与客户端 IPv6 拨号支持。 |
| **v0.6.9** | 2026-07-29 | **灰域名自适应分流**: `auto_classify` 自动按解析 IP 归属分流与 TTL 学习；配置命名规范化。 |
| **v0.6.8** | 2026-07-28 | **配置导入导出闭环**: 支持交互式导出节点与规则 JSON 片段，支持 `subscribe` 导入本地文件合并。 |
| **v0.6.7** | 2026-07-28 | **负载均衡出站组**: 新增 `load_balance` 轮询组；订阅批量导入；集成 GeoIP 区域告警。 |
| **v0.6.6** | 2026-07-27 | **进程名分流**: 支持按发起程序名分流 (`process_name`)；新增 `dump_tls` 指纹分析工具。 |
| **v0.6.5** | 2026-07-27 | **DNS-over-TCP 兜底**: 服务端可选 `dns_tcp_resolver`，解决 VPS UDP 出口受阻导致的解析失败。 |
| **v0.6.4** | 2026-07-26 | **网络质量探测**: 节点测活集成 HTTP 穿隧道端到端探测与 RTT 评估。 |
| **v0.6.1** | 2026-07-26 | **DNS 增强**: 局域网 53 端口劫持；静态解析；IPv4/IPv6 双栈返回控制。 |
| **v0.6.0** | 2026-07-23 | **WireGuard 全面接入**: 客户端出站与服务端上游支持 WireGuard；修复 SOCKS5 UDP 绕过。 |
| **v0.5.0** | 早期 | 引入 Neon Pulse Dashboard 看板；重写 DNS 引擎支持 TTL 缓存。 |
| **v0.4.5** | 早期 | 抗 DNS 风暴机制完善；TCP Brutal 拥塞控制定型；eBPF 透明网关正式成型。 |

---

*"在数字迷雾中构筑坚不可摧的幻象。" —— Mirage-rs 团队*
