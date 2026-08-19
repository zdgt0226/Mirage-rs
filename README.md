# Mirage-rs

![Mirage-rs](https://img.shields.io/badge/Language-Rust-f74c00.svg) ![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg) ![Version](https://img.shields.io/badge/Version-v0.9.6-10b981.svg)

基于 **Rust** 与 **Tokio** 全新重写的高性能、抗审查代理引擎。继承 Python 版 POC (Shadow-TLS + Reality) 的隐藏特性, 底层彻底重构, 提供内核级 eBPF 加速与内置 Web 看板。

> **定位**: 面向**自建跨境线路的个人/小团队** —— 有一台墙外 VPS + 一台能当网关的 Linux 机器。
> 主打「零配置 eBPF 透明网关」+ 抗被动识别。

> ⚠️ **安全声明 (务必先读)**:
> - **未经专业安全审计**。加密分帧 (ChaCha20-Poly1305) 与握手认证由项目自研, 仅经过多轮 LLM
>   复核与真机验证, **没有**独立安全公司审计。请据此评估信任度, 不要用于生命安全级场景。
> - **前向保密 (PFS) 可选, 默认关**: 默认会话密钥仅由**共享口令**派生 (不做密钥协商) ——
>   **口令泄露则历史与未来流量都可被解密**。两端 config 设 `"pfs": true` 可开启**一次性
>   X25519 ECDH** (临时私钥用完即弃), 开启后即便口令泄露也解不了已录流量。**两端必须同开**
>   (改了会话密钥派生, 一端开一端没开会连不上)。无论是否开 PFS, 都请用高强度随机口令、
>   限制传播、定期更换。见 brain external-audit-2026-08 / handshake-forward-secrecy。
> - **认证是单一共享口令**, 无 per-user 维度。多人共用即共担泄露风险。
> - **负责任使用**: 本工具用于**保护自己合法流量的隐私与可达性**。是否可在你所在司法辖区使用、
>   以及如何使用, 由你自行判断与负责; 请遵守当地法律。

> **运行要求**: **Linux 内核 ≥ 5.10** —— eBPF 透明网关依赖 `sk_lookup`(5.9+) / `sk_assign`(5.7+) /
> XDP DNS, 旧内核 (如 Ubuntu 20.04 的 5.4、老 NAS/OpenWrt) 上这些程序**加载会失败**。
> 内核不够也不必放弃: **轻量 / SOCKS 模式不碰 eBPF**, 任意较新 Linux 都能跑 (只是没有透明网关)。
> 服务端**不需要** eBPF (入站是加密流, 自动跳过), 内核门槛只针对**客户端/网关侧**。

---

## 🌟 核心特性概览

* **极致传输与伪装**: TLS 1.3 ClientHello 字节级仿真（多浏览器 Profile 轮换）、TCP Brutal 拥塞控制、无锁化异步架构底座。
* **可选前向保密 (PFS)**: 两端 `pfs: true` 开启一次性 X25519 ECDH（公钥搭 fake-TLS random 字段交换，零指纹变化），口令泄露也解不了已录流量。默认关（向后兼容），认证仍靠口令、与加密解耦（对标 REALITY）。
* **eBPF 透明网关**: 基于 Linux `sk_lookup` / `tc_divert` 的无感知内核级透明代理，内置抗风暴 DNS 与 Fake-IP 加速；LAN 客户端 `ping` 被代理域名可通（fake-IP ICMP echo 本地反射）。（无 eBPF 的 VPS/容器服务端 Auto 自动跳过，TCP/UDP/PFS 全线可用。）
* **全场景出站与中转**: 支持 WireGuard 与 Shadowsocks (SIP004/SIP022) 上游/出站。
* **高维路由引擎**: 支持按域名、GeoIP/GeoSite、IP CIDR、进程名 (`process_name`)、源设备/网段 (`source_ip_cidr`) 分流。支持裸 IP SNI 嗅探与 SOCKS5 UDP 逐包路由。
* **内置 Web 看板**: Neon Pulse Dashboard，实时监控流速、eBPF 拦截率，并支持可视化热重载规则。
* **供应链完整性**: Release 产物 (SHA256SUMS) 与多架构容器镜像 (`ghcr.io`) 均经 **cosign keyless** 签名 (Sigstore OIDC + Rekor 透明日志，零密钥可公开审计)。

---

## 一键安装 (推荐)

**alpha.4+ 起提供交互式安装向导 `install.sh`**, 会自动 (需 root):
- 下载最新预编译二进制到 `/usr/local/bin/mirage-rs` (含 SHA256 双通道校验)
- 探测公网 IP + 端口占用检测 + Brutal 内核模块
- 生成服务端 / 客户端 config, 写 systemd unit —— 完整版 `mirage-rs-{server,client}.service`,
  轻量版 `mirage-rs-lite-{server,client}.service`(名字区分, 一眼看出装的是哪个模式)
- **选择部署形态**: 完整版 (分流/DNS/透明网关/看板) 或**轻量版** (只要能翻墙, 配置极简)
- 交互配置 GUI 端口 / SNI 伪装 / brutal 速率 / geo 分流策略
- **可选配置 Shadowsocks 上游出口** (把本机当中转站)
- 非回环监听时**强制设入站账号密码**, 避免装出一个开放代理
- 服务端配完可直接输出 `mirage://` 节点 URI (含二维码), 客户端安装时一步导入

```bash
# 一键运行 (1=服务端 / 2=客户端 / 3=同机 / 4=更新二进制 / 5=显示节点 / 6=卸载)
# 选完 1/2/3 后会再问一次「部署形态」: 完整版 or 轻量版
curl -fsSL https://raw.githubusercontent.com/zdgt0226/Mirage-rs/main/install.sh | sudo bash
# 或先 clone 再看内容:
git clone https://github.com/zdgt0226/Mirage-rs.git && cd Mirage-rs
sudo bash install.sh
```

装完立刻可用: `sudo systemctl status mirage-rs-{server,client}`
(轻量版是 `mirage-rs-lite-{server,client}`)。

### 容器镜像 (multi-arch amd64/arm64)

```bash
docker run --rm -v /etc/mirage-rs:/etc/mirage-rs \
  ghcr.io/zdgt0226/mirage-rs:latest server -c /etc/mirage-rs/config_server.json
```

### 验证产物签名 (cosign keyless, 无需任何公钥)

Release 里的 `SHA256SUMS` 由 CI 用 **cosign keyless** (Sigstore, 身份 = 本仓库 Release workflow 的 GitHub OIDC) 签名, 容器镜像同样签名 —— 无长期私钥、可公开审计 (Rekor 透明日志):

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
cargo build --release                 # 纯用户态版 (默认, 无需 clang)
cargo build --release --features ebpf # 含 eBPF 透明网关 (需 clang + llvm)
```

> ⚠️ **`--features ebpf` 必须装 clang/llvm** (`apt install clang llvm libbpf-dev`) —— 要编译内核
> BPF 程序。缺 clang 时构建会**明确报错提示装 clang**, 而非神秘失败 (eBPF 目标文件不入库, 不会
> 静默加载陈旧版本; 见 `build.rs`)。**默认构建 (无 `--features ebpf`) 不碰 BPF, 不需要 clang。**
> 大多数用户直接用上面的预编译二进制/容器即可, 无需自编译。

---

## 🛠️ 灵活的部署形态

### 轻量模式 (只要"能翻墙"就够了)

如果你不需要分流 / fake-IP / 透明网关 / 看板, 只想要「本机 SOCKS5 → 全部走隧道」,
用轻量模式 —— **同一个二进制、同一套协议与伪装**, 与完整版可互通。

**一键安装向导已支持**: 跑 `install.sh` 选完"部署服务端/客户端"后, 会再问一次
**部署形态**, 选「轻量版」即可 —— 它会问端口/密码/SNI, 生成平铺配置并注册 systemd 服务
(服务名为 `mirage-rs-lite-{server,client}`, 与完整版区分)。

> 两种形态的 unit 可以并存, 但它们**默认监听同一端口**。安装向导会自动停用并禁用另一形态的
> 同角色服务(配置文件保留), 避免两个服务抢一个端口导致"装完却时好时坏"。想切回去重新跑
> 一次安装、选另一个形态即可。
客户端还支持直接粘贴服务端导出的 `mirage://` 串, 免得手抄密码出错。

手动运行:

```bash
mirage-rs lite-server -c lite_server.json    # 墙外 VPS
mirage-rs lite-client -c lite_client.json    # 本机
```

配置是平铺的极简格式。**带完整注释的模板见 [`templates/lite_server.jsonc`](templates/lite_server.jsonc)
与 [`templates/lite_client.jsonc`](templates/lite_client.jsonc)**(列全了每个字段的含义与取值建议;
JSON 不支持注释, 使用时请去掉 `//` 注释再存为 `.json`)。

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

> 服务端端口选 443 伪装效果最好(与真实 HTTPS 同端口), 但它是特权端口(<1024), 非 root
> 启动会 bind 失败 —— 用 systemd/root, 或给二进制加 `CAP_NET_BIND_SERVICE`, 或直接换个
> `>1024` 的端口(如 8443/9443, 同样可用)。**两端的端口必须对上**: 客户端 `server_port`
> = 服务端 `port`。

**与完整版的差别**: 无分流(**全部转发**)、无 DNS/fake-IP、无透明代理、无 Web 看板、
无 geo 数据下载、无配置热重载、**SOCKS5 仅 TCP**(UDP ASSOCIATE 会按规范回 `0x07` 拒绝,
所以 QUIC/HTTP3 走不了代理 —— 浏览器会自动回落 TCP)。
加密、TLS 指纹伪装、握手认证、认证失败转发真站这些**一个都没少**。

> 注: 轻量模式是**运行时**精简, 不是单独编译的小二进制 —— 体积与完整版相同。

---

### 中转站模式 (服务端接 Shadowsocks 上游)

服务端可以**不直连目标**, 而是把流量再经 Shadowsocks 发往上游出口 —— 即把 Mirage 当中转站:

```
客户端 ──(Mirage 隧道)──▶ Mirage 服务端 ──(Shadowsocks)──▶ SS 服务器 ──▶ 目标
```

典型用途: Mirage 服务端放在离你近、线路好的位置(如香港)只做中转, 真正的出口落在另一台
SS 服务器上(如落地解锁用的机器)。给 `mirage_server` 入站(或轻量服务端配置)加:

```jsonc
"upstream": {
    "type": "shadowsocks",
    "server": "1.2.3.4",
    "server_port": 8388,
    "password": "ss-password",
    "method": "aes-256-gcm",    // SIP004: aes-128-gcm / aes-256-gcm / chacha20-ietf-poly1305
                                // SIP022: 2022-blake3-aes-128-gcm / 2022-blake3-aes-256-gcm
                                //         / 2022-blake3-chacha20-poly1305
    "udp": "block"              // block(默认) | direct, 见下方说明
}
```

不配 `upstream` = 直连目标(原行为)。加密方式写错会**直接报错拒绝启动**, 而不是悄悄降级
成直连 —— 配了中转却走直连意味着出口 IP 与预期完全不同, 必须让人立刻知道。

> ⚠️ **仅作用于 TCP**。SS 的 UDP 是另一套包格式, 尚未实现, 因此 `udp` **默认 `block`**
> (直接拒绝 UDP 中继)。这是刻意的: 若放行, UDP 会从**本机 IP** 直连出去而 TCP 从上游出去,
> 出口 IP 不一致 —— 对落地解锁场景这不是"不一致"而是**功能性错误**(流媒体走 QUIC 时会被判
> 成错误区域, 且不会像被封那样回落 TCP, 表现为解锁时灵时不灵)。**安全的失败方式是"不发",
> 而非"发到别处去"**。代价: QUIC 回落 TCP(页面照常), 游戏/WebRTC 不可用。
> 确需旧行为写 `"udp": "direct"`(启动会 WARN)。轻量客户端本就仅 TCP, 不受影响。
>
> 📌 同时支持 **SIP004 AEAD** 与 **SIP022 (Shadowsocks 2022)**;
> **不支持** legacy 流式加密(`aes-256-cfb` 等)—— 它们无完整性校验、已被社区废弃、易被主动探测识别。
>
> 📌 **SIP022 的 `password` 与 SIP004 语义完全不同**: 它不是任意密码, 而是 **base64 编码的密钥本身**
> (2022-blake3-aes-128-gcm 要 16 字节, aes-256 要 32 字节), 不做密码拉伸。用
> `openssl rand -base64 32` 生成。长度不对会被 `mirage-rs check` 直接拦下并说明应有长度 ——
> 这类错**不会**让服务端起不来, 而是每条连接都静默失败, 所以必须提前拦住。

---

### 干净设备接入 (WireGuard 入站)

让手机/平板用**系统原生 WireGuard** 接入家中网关, 经网关的 Mirage 抗审查出海 —— **设备上零翻墙
痕迹** (只是一条通用 VPN), 翻墙逻辑全在网关侧。

```
[手机 原生 WireGuard] ──家域内 WG(不跨 GFW)──▶ [家中网关: wg0 + eBPF 透明 + Mirage] ──▶ 海外
```

**为什么成立**: 设备↔家中网关是**局域网/家域内**的 WireGuard, 不跨 GFW 不会被封; 真正的抗审查
出海发生在**网关**上。设备侧只有一个普通 WG 配置, 查不到任何代理/翻墙软件痕迹, 降低"查水表"风险。

**一键配置**: 在已装好透明网关的机器上跑 `install.sh` 选 **`7) 家庭 WireGuard 服务端 (干净设备接入)`**:
- 装 `wireguard-tools` + 内核 WG, 生成 `wg0` 服务端 (`10.7.0.1/24`) + NAT + 开机自启 (`wg-quick@wg0`)。
- 为每台设备生成配置 (文本 + **二维码**), 存 `/etc/wireguard/peer-<名字>.conf`。设备装官方 WireGuard App
  扫码即用。再加设备重跑一次, 会**追加 peer 不覆盖**旧的。

**机制 (无需改代码)**: 透明拦截**按 fake-IP 目标, 不靠 SO_MARK** —— fake-IP 段是本机地址, `sk_lookup`
挂在 netns 上**不绑网卡**, 所以 wg0 收到的、目的是 fake-IP 的包会本地投递并自动命中透明代理, 和 LAN
流量一样, 零额外配置。国内/直连流量走标准 `ip_forward` + NAT。

> **命门: 设备的 DNS 必须指向网关 wg0 IP** (`10.7.0.1`) —— 一键脚本已在设备配置里写好。**别在设备上
> 改成公共 DNS** (8.8.8.8 等), 否则海外域名解不成 fake-IP 就走不了代理 (会直连或失败)。

> **已知限制**: 不经 DNS 的**裸 IP** 直连 (少数 App 硬编码 IP) 从 wg0 进来不会被透明拦截 (tc_divert 绑
> 物理网卡), 手机场景罕见且绝大多数流量走域名/fake-IP。真机已端到端验证 (WG peer → 网关 → Mirage →
> google/cloudflare `HTTP 200`; 国内 baidu 走直连; 被代理域名只解到 fake-IP 不泄真实 IP)。

---

## ⚙️ 服务端配置说明

### 服务端配置示例 (`/etc/mirage-rs/config_server.json`)
<details>
<summary>点击查看: 服务端配置示例 (config_server.json)</summary>

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

</details>

密码 + `camouflage_host` 必须跟客户端完全一致。`brutal_rate_mbps` 是服务端到客户端方向 (下载) 的 brutal 目标速率, 见下方 Brutal 章节。

> ⚠️ **看板安全**: `gui.listen` 默认 `127.0.0.1` (只本机, 安全)。若改 `0.0.0.0` 暴露到 LAN/公网,
> **务必设 `gui.token`** —— 看板能读日志/配置**并可视化改路由规则**, 无鉴权暴露 = 任何可达者
> 都能把你的流量重定向。设了之后 `/api/*` 需带 token (`Authorization: Bearer <token>` /
> `mirage_token` cookie / `?token=`, 常量时间校验防时序侧信道)。install.sh 选「全网开放」会自动
> 生成随机 token 并打印。不设仍可用 (向后兼容), 但非本机暴露时会 WARN。生产建议叠 Nginx TLS。

> **出向 UDP 被封的 VPS**: 系统 `getaddrinfo` (glibc) 默认用 **UDP:53** 查 DNS, 封了 UDP
> 就解析不了代理目标域名 (代理域名全挂)。加 `"tuning": {"dns_tcp_resolver": "1.1.1.1"}` 让
> **本进程所有域名解析改走 DNS-over-TCP** (地址无端口默认 53), 脱离系统解析器。不设 = 系统解析器。
> (零改代码的替代: VPS 上 `echo "options use-vc" >> /etc/resolv.conf` 强制 glibc 走 TCP。)

> **UDP 带机量 (透明网关)**: 透明 UDP 的 Mirage 流默认**一流一隧道**, 并发 UDP 流封顶在
> `pool_size`。做局域网网关且大量并发 UDP (QUIC/游戏) 时, 加 `"tuning": {"udp_mux": true}`
> 开 **UDP 多路复用** —— 多流按散列复用少量 (默认 `udp_mux_tunnels: 4`) 共享隧道, 并发脱钩
> `pool_size`。install.sh 安装透明网关时会询问是否开启 (默认开)。⚠️ **需服务端也升级** (老服务端
> 不认 mux, 那些 UDP 流回落 TCP)。代价: 同隧道内跨流队头阻塞 (靠加大 `udp_mux_tunnels` 分摊);
> 实时 UDP 建议走 WG 上游 (原生无 TCP HoL)。真机实测 (旁路网关 + 单核 VPS): 并发 UDP 流拐点
> **20 → 450 (22.5×)**, 且天花板受限于服务端 fd/CPU 而非 mux 本身 —— 高并发建议把服务端
> `LimitNOFILE` 调高 (install.sh 的 systemd unit 已设 1048576)。

> 注: 客户端与透明网关的详细配置示例见 `templates/` 目录下的注释版模板。

---

## 🧰 CLI 用法

节点/配置管理子命令 (都写回配置文件, 原子写 + `.bak` 备份):

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
```

> 组类型 (rule / default_outbound 可指向): `urltest` (选延迟最低) · `fallback` (第一个健康) ·
> `selector` (手动) · `load_balance` (round-robin 分摊)。`import`/`subscribe --group` 会自动建
> urltest 组并把 `default_outbound` 指向它。`test` 与 `--group` 建组会读 `geoip.dat` 显示节点区域,
> 混区域时告警 (负载均衡/自动选路出口国不一致会影响落地解锁)。

---

## 路线图 / TODO

> 图例: `[x]` 已完成并发布 · `[ ]` 未完成 · `[~]` 部分完成。完成一项即勾选一项。
> 这是**候选池而非排期** —— 走一步看一步, 哪个撞到痛点先修哪个。

### ✅ 已完成

- [x] 透明网关整链路真机跑通 (TCP + UDP + 隧道 + 回源)
- [x] TLS ClientHello 字节级仿真 (三 profile 轮换 + JA4 对照 harness + 后量子 key_share)
- [x] 轻量模式 (`lite-server` / `lite-client`)
- [x] 中转站: Shadowsocks 上游 (SIP004 + SIP022) & WireGuard 上游
- [x] WireGuard 出站 (客户端) + 上游 (服务端), TCP/UDP/隧道内 DNS, 真实 peer 五层验证
- [x] 路由 `inbound` 维度 + 裸 IP 按域名分流 + SOCKS5 UDP 逐数据报路由
- [x] geo 自动更新 (ETag/304 + 多镜像 + 落地前校验 + 重启不重下)
- [x] 配置工具链 (`check` / `format` / `import` + urltest 建组 / `test` 节点握手测活) + 启动时配置校验
- [x] 入站认证 (SOCKS5 / HTTP), 修默认开放代理
- [x] DNS: 可选劫持 (接管 LAN 53/UDP+TCP, 默认关) · 静态解析 (类 dnsmasq, 精确+子域) · IP 版本策略 (`ip_strategy` 控 v4/v6 返回) (v0.6.1)
- [x] **process_name 分流** —— 按应用分流 ("Telegram 走代理、微信直连"), 本机 loopback 入站经 `/proc` 反查进程名; 透明/LAN 转发无本机进程故不适用
- [x] **MSS clamp** —— 内联 `tc_divert` (`clamp_tcp_mss`), MTU 自动探测网卡下发 (`max_mss = mtu-40`, PPPoE 1492), 覆盖直连转发路径, 防小 MTU 链路 PMTU 黑洞 ("小请求通、大下载卡"); `verify_mss_clamp.sh` CI 验证
- [x] **cipher agility** (v0.7.0) —— 两端有 AES-NI 时协商 AES-256-GCM (比 ChaCha20 快 ~2.1x), 否则回落 ChaCha20; 协商全在加密信道内 (proto_ver 0x02 + CIPHER_NEGO/ACK), ClientHello 零触碰不改指纹; 服务端 `tuning.cipher_agility` 开关 (默认关=向后兼容)
- [x] **IPv6 隧道传输** (v0.7.0, 瘦身自"IPv6 全栈") —— 隧道传输走 v6: 服务端 v6 监听 + 客户端 v6 字面量自动加方括号 (`net_util::join_host_port`) + `node_uri` v6。透明数据面 v6 大 epic **评估后否** (fake-IP + 服务端远程解析已让客户端 v6 数据面不必要; 已知限制见 brain `ipv6-full-stack-design`)
- [x] **UDP 多路复用** (v0.9.0) —— 透明 UDP 的 Mirage 流按 flowkey 散列复用少量 (默认 K=4) 长命共享隧道, 拿掉"并发 UDP 流 ≤ `pool_size`"带机量硬伤 (真机拐点 20→450, 22.5×)。`tuning.udp_mux` 门控默认关 (两端同版)。容量不变量已有 CI 守卫 (v0.9.4)
- [x] **可选前向保密 PFS** (v0.9.3, 外部审计 #2) —— 一次性 X25519 ECDH, 公钥搭 fake-TLS random 字段交换 (零指纹变化 + 高位随机化抗指纹), `password‖ecdh` 混进会话 master; opt-in 两端同开, 失配 fail-closed; install.sh 一键开关
- [x] **供应链签名 + 多架构容器** (v0.9.3, 外部审计 #13) —— cosign **keyless** (Sigstore OIDC, 零密钥) 签 SHA256SUMS + ghcr 容器镜像 (amd64/arm64, 镜像亦签名); 验签命令见上方「验证产物签名」
- [x] **外部审计整批清零** (v0.9.2–v0.9.4) —— API 失败限流 (#3) · cargo-deny 供应链门禁 (#11) · start_proxy 巨石拆分 (#4) · config 模板防漂移测试 (#7) · 版本歪斜诊断 (#8) · 解析器 proptest (#12) · 未审计声明 (#1)。纯代码/零密钥项全清, 残余仅 #14 bench (边际) / #10 orphan CI (需 ≥6.1 自托管 runner)
- [x] **CI 回归哨兵** (v0.9.4) —— mux 容量不变量 · crypto AES/ChaCha 相对吞吐比值 (≥1.3×) · brutal 收敛轨迹; 相对/行为门抗共享 runner 计时噪声

### 🚧 部分完成

- [~] **订阅链接** —— `mirage-rs subscribe <url>` 批量导入 (格式=每行 `mirage://` 或整段 base64, server:port 去重, 可选 --group)。**周期自动刷新**待做

### ⏳ 未完成 (计划池)

- [~] **WebUI 重构 (分阶段)** —— ①**活跃连接登记表 + `/api/connections`** (Phase 1, 未发版): 用户态连接登记表 (域名·入站·选中出站·协议·进程·时长·上下行字节 + 最近关闭环), 修 `/api/overview` 此前硬编码的 `connections:0`; 全用户态 lite/网关通用 (区别于仅 eBPF 的 `bpf/tunnels`); TCP 全出站覆盖, 透明 UDP 登记见 Phase 1b。②**前端连接面板** (Phase 2, 未发版): Neon Dashboard 加「Active Connections」表 (TARGET·ROUTE 入站→出站·PROTO·PROCESS·AGE·↑↓) + 「Recent Closed」段, 1Hz 差量刷新。③**规则编辑器增强** (Phase 3, 未发版): 补 `domain_regex`/`process_name`/`inbound`/`port` 维度 (打通进程分流可视化) + Save 前 `dry_run` 预检 (结构非法拒绝、语义告警确认) + 规则上下移 (首命中顺序) + outbound 下拉建议 (`GET /api/rules` 附 outbound 标签); 附带修 `?dry_run=1` 后端 bool 解析 (axum 只认 `true`, 契约是 `=1`)。④**per-出站分流量 + 规则命中统计** (Phase 4, 未发版): `GET /api/stats` + 面板 —— 每出站累计上下行/连接数/活跃数 + 每条规则命中次数 (0 命中=死规则一眼可见) + 默认出口命中。⑤**透明 UDP 登记** (Phase 1b, 未发版): `transparent_udp` 每 flow 登记进连接表 (目标·入站·出站·udp), down 计 Direct/WG/非-mux Mirage 三条下行 (Mirage-mux/SOCKS-UDP 字节留后续)
- [~] **LAN 每主机监控 + 设备专用规则** (随 WebUI 优化做) —— ① **设备规则已生效**: `source_ip_cidr` 现对透明 TCP + SOCKS-UDP + 透明 UDP 全路径匹配 (给 proxy_tcp_target 填 `source_ip` = 发起方 IP, v4-mapped 归一; 见 brain `source-ip-routing`)。DNS 查询维度暂 None (每主机 DNS 策略未实现)。② **每主机用量** (待做): eBPF 按源 IP 计上下行字节 (tc 看得到含 splice 直连的全部流量, 用户态计数会漏) → 用户态读 map → API + Neon 面板 per-host 视图 + 可选设备别名
- [ ] **rule-set 远程规则集自动更新** —— 免手动放 geo 文件 (须先定安全模型: 规则决定流量去向, 更新失败必须保留旧规则)
- [x] **统一出站流接口** (v0.8.1) —— `OutboundNode::connect(target)->OutStream`, geo 等进程内消费者直连隧道
- [~] **链式代理 / WG·SS 双向** —— SS 双向 (入站+出站) · Mirage 套娃 · SS-over-Mirage 已做 (v0.8.1); **WG 入站**改用"干净设备"落地 (内核 WG 服务端 + 现有 eBPF 透明网关, install.sh 选项 7, 非 boringtun responder) —— 见上方「干净设备接入」。剩自定义转发编排增强
- [ ] **UDP mux → QUIC Datagram** —— TCP-mux 已解带机量 (v0.9.0); QUIC 版解跨流队头阻塞 + 实时质量, 大工程
- [~] **ICMP 处理** —— ①fake-IP echo **本地反射已做** (未发版): LAN 客户端 `ping` 被代理域名可通 —— `tc_divert` 就地把 fake-IP 段的 Echo Request 翻成 Echo Reply 弹回 (RTT 是本机假值, 对齐 Clash/sing-box fake-ip ping)。②真隧道 ICMP (端到端真 RTT) **评估后暂不做**: 捕获路径 (AF_PACKET / TUN / 无) 均需真机验证, TUN 违背 TUN-free eBPF 定位, 边际价值低 (应用走 TCP)。本机自身 ping fake-IP 不经 tc ingress, 暂不覆盖。
- [ ] orphan 验证器接回 CI —— **本地-only** (本机 ≥6.1 稳过, 但 GitHub runner 5.15 与 6.8 都红: 客户端连不上, 是 runner 对"跨进程 sk_assign"场景的兼容问题非产品; 覆盖已由 verify_tc_divert_tcp 兜)。接回需先把验证器改单进程 (仿 tcp.sh)
- [x] **隧道 relay 缓冲/合帧再调** —— 客户端**上行**已对称服务端 download 加 64KB heap buf + greedy `try_read` 收割 (修上下行不对称的上传碎片, 未发版)。**BufWriter/全局 read 灌大 (256KB) 评估后不做**: loopback bench 证明 relay 是 crypto CPU-bound 非 syscall-bound (见下 io_uring 条), 灌大不解瓶颈反增 warm 池空闲内存

### 评估后决定不做（避免重复提）

- **Tailscale 原生支持** —— 官方 Rust 实现当前全走 DERP 中继, 对代理是吞吐硬伤; 让用户自己跑 `tailscaled` + Mirage 直连 `100.64.0.0/10` 今天就能用
- **TLS session resumption 仿真** —— 抓包 + 统计实测证明: 真 Chrome 的 `legacy_session_id` 也每次全新随机, 我们与之不可区分, 立项前提不成立
- **追平 sing-box 全部协议/规则** —— 定位是零配置 eBPF 网关, 不是通用代理框架
- **io_uring 替代 relay read/write 循环** —— loopback bench (2026-08-19): 直连 splice 1418 MB/s vs 隧道单流 137 MB/s, 并发随核涨 4 核饱和 = relay 瓶颈是 **AEAD crypto CPU 非 syscall**。io_uring 优化 syscall 开销 → 优化错位零收益; 且 tokio-uring 独立 runtime 塞进全 tokio 库要整体迁移。唯一有效杠杆是更快 crypto (cipher agility AES-NI 已做)。单流 1.1 Gbps 已超真实跨境链路 —— 部署里网络才是瓶颈
- **SS 上游 UDP** —— ①要 UDP 同出口**直接用 WireGuard 上游** (已通), 功能已覆盖; ②多数 SS 服务器默认不开 UDP, **实现≠能用**; ③SS UDP 无握手, 上游不支持时"包石沉大海"无法探测只能等报障; ④当前默认 `block` 已是安全失败方式 (不静默从本机 IP 直发致出口 IP 不一致)。仅"落地机只会 SS 不能上 WG 且必须走 UDP"这一窄场景才翻案
---

## 📜 版本迭代概览 (Changelog)

Mirage-rs 遵循快速迭代模式，详细更新日志请查阅 [`CHANGELOG.md`](CHANGELOG.md)。

| 版本 | 发布日期 | 核心重大特性 |
| :--- | :--- | :--- |
| **v0.9.4** | 2026-08-16 | **CI 回归哨兵**: 给"没人看的相对性能特征"补确定性/相对哨兵 —— UDP mux 容量不变量 (N 流散布到全 K 槽 + `MAX_FLOWS` 下限, 防 22.5× 带机量静默回归) · crypto AES/ChaCha 吞吐**比值** ≥1.3× (CI 实测 4.22×, 比值抗计时噪声) · brutal 收敛轨迹 (拥塞收敛 BDP±20% + 恢复回 ≥90% 满速)。均相对/行为门, 不上共享 runner 假报警。camouflage 模板拉取失败回落降 WARN (无外网服务端不再满屏 ERROR)。 |
| **v0.9.3** | 2026-08-14 | **可选前向保密 (PFS)** + **供应链签名/容器**: 一次性 X25519 ECDH (公钥搭 fake-TLS random 字段交换, 零指纹变化 + 高位随机化抗指纹; `password‖ecdh` 混进 master; opt-in 两端同开, 失配 fail-closed) 补外部审计 #2 最大真安全缺口, install.sh 一键开关。cosign **keyless** 签 SHA256SUMS (bundle) + ghcr **多架构容器镜像** (buildx amd64/arm64, GITHUB_TOKEN, 镜像亦签名), 零密钥。审计尾单: start_proxy 巨石拆分 (753→400) · config 模板防漂移测试 (#7) · 版本歪斜诊断 (#8) · WG connect 同步失败 socket 泄漏修复。 |
| **v0.9.2** | 2026-08-14 | **握手模板完整性修复**: 服务端只缓存含齐 `0x16+0x14+0x17` 三型的 camouflage 模板 (残模板回落恒完整 fallback), 修完整服务端↔客户端 (含轻量模式) 偶发 `read_exact tail timed out` 握手卡死。**外部审计便宜纯赚**: API 认证失败 per-IP 限流 (#3) · cargo-deny 供应链门禁 (#11, 抓出 anyhow RUSTSEC) · README 安全声明 (#1)。RTT/brutal 监控去阻塞 (spawn_blocking) + 调速抽纯函数 (#5) · 解析器 proptest (#12)。 |
| **v0.9.1** | 2026-08-12 | **WireGuard 入站"干净设备"落地**: install.sh 菜单项 7 家庭 WireGuard 服务端 (内核 WG + eBPF 透明网关, 非 boringtun responder), 移动设备经家中网关代理零翻墙痕迹, 真机验证。§7 抗审查泄漏护甲测试 (T2/T4: fake-IP / 空 AAAA / block→NXDOMAIN) · clippy 安全子集清理。 |
| **v0.9.0** | 2026-08-04 | **UDP 多路复用 (UDP mux)**: 透明 UDP 的 Mirage 流由"一流一隧道"改为多流按 flowkey 散列复用少量 (默认 K=4) 长命共享隧道, 拿掉"并发 UDP 流 ≤ pool_size"带机量硬伤 (真机实测拐点 20→450, 22.5×)。协议加 `[0x01]` mux sentinel + 帧插 4B sid, 服务端 per-sid 连接式 egress socket (两流打同目标不串) + 单 AEAD writer cancel-safe; 客户端 K 条共享隧道持 Weak-pool 防热重载泄漏。`tuning.udp_mux` 门控默认关 (需两端同版), install.sh 装网关时询问。**外部审计 4 修**: WireGuard 隧道内 DNS 死代码接线 (config `dns` 此前被丢弃) · UDP mux 背压 (服务端 idle 对齐/饱和告警/客户端 sid 上限/首下行快拆) · DNS-over-TCP 响应校验 TXID+QR 防注入 · 常量时间比较统一 `subtle` (弃用 deprecated ring)。install.sh 修生成的服务端配置缺 direct 出站 (新版校验必需)。 |
| **v0.8.1** | 2026-08-03 | **链式代理 (Chain Proxy)**: 统一出站流接口 `OutboundNode::connect(target)` (地基) · **Mirage-over-X** 套娃 (`underlying`: Mirage 隧道经另一出站拨号, Mirage-over-WG/双跳) · **Shadowsocks 入站** (网关接受 SS 客户端 SIP004, 惰性 salt 抗主动探测) · **Shadowsocks 出站 + SS-over-Mirage** (类 shadow-tls+ss: SS 骑 Mirage 隧道) · **geo 经隧道下载免配 SOCKS 入站** (进程内临时 SOCKS)。均经 Sonnet 多轮复核。 |
| **v0.8.0** | 2026-08-02 | **TLS record padding** (协议层): 握手后前几条加密记录追加 TLS 1.3 原生零填充, 抹掉"包长序列"指纹 (抗 GFW ML 识别); 收端恒剥零 (兼容基座), 发端 `tuning.tls_padding` 门控 (默认关), 含抹除 server 首帧 TIME_SYNC 固定 10 字节。⚠️ 开启需两端同版。**外部审查加固**: DNS resolver `tcp://` 前缀解析修复 · outbound 循环组返 Result 不 panic · API token 常量时间比较改 `ring` + CSRF 重构进中间件 + `?token=` 限根路径 + `/api/rules` 写前结构化校验/dry-run · 抗审查威胁模型文档 + 泄漏守卫测试 · clippy 门禁。 |
| **v0.7.0** | 2026-07-30 | **Cipher agility**: 两端有硬件 AES 加速时协商 **AES-256-GCM** (大流量 ~2x, 否则 ChaCha20); 全在加密信道内协商 + `rekey`, **ClientHello 一字不改 (TLS 指纹零触碰)**, 服务端 `tuning.cipher_agility` 门控。**IPv6 隧道传输**: 服务端 v6 监听 + 客户端连 v6 服务端 (`[v6]:port` 括号处理); 透明数据面 v6 epic 评估后否 (fake-IP+服务端远程解析已让客户端 v6 数据面不必要)。 |
| **v0.6.9** | 2026-07-29 | **DNS 未分类域名自适应分流** (`auto_classify`): 灰域名按解析 IP 归属自动直连/代理 + TTL 学习, 可选 `verify_cn` 非阻塞交叉校验防污染。配置命名统一 snake_case (移除 `load-balance` 别名); 移除从未实现的 `advanced_dns.rules`; 4 路 Sonnet 全局审查加固。 |
| **v0.6.8** | 2026-07-28 | **配置片段 Export/Import 闭环**: 支持交互式导出节点与规则 JSON 片段，支持 `subscribe` 导入本地文件合并；全局代码护栏加固。 |
| **v0.6.7** | 2026-07-28 | **负载均衡组**: 新增 `load_balance` 出站组 (Round-Robin 分摊)；支持 URL 订阅批量导入；集成节点 GeoIP 区域判定与分组告警。 |
| **v0.6.6** | 2026-07-27 | **进程名分流**: 支持按发起程序名路由 (`process_name`)；新增 `dump_tls` 会话指纹量化分析工具。 |
| **v0.6.5** | 2026-07-27 | **DNS-over-TCP兜底**: 服务端可选 `dns_tcp_resolver`，彻底解决 VPS 屏蔽出口 UDP 导致的域名解析失败问题。 |
| **v0.6.4** | 2026-07-26 | **智能网络质量探测**: 节点测活集成 HTTP 穿隧道端到端探测，联动 TCP RTT 揭露劣质出口节点。 |
| **v0.6.1** | 2026-07-26 | **DNS 三件套重构**: 支持局域网 53 端口劫持；新增静态解析；新增 IPv4/IPv6 双栈返回控制。 |
| **v0.6.0** | 2026-07-23 | **WireGuard 全面接入**: 客户端出站与服务端上游支持 WireGuard；修复 SOCKS5 UDP 绕过路由问题。 |
| **v0.5.0** | 早期 | 引入 Neon Pulse Dashboard 看板；重写 DNS 引擎支持 TTL 缓存。 |
| **v0.4.5** | 早期 | 抗 DNS 风暴机制完善；TCP Brutal CC 优化定型；eBPF 透明网关正式成型。 |

---
*"在数字迷雾中构筑坚不可摧的幻象。" —— Mirage-rs 团队*
