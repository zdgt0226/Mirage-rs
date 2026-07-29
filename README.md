# Mirage-rs

![Mirage-rs](https://img.shields.io/badge/Language-Rust-f74c00.svg) ![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg) ![Version](https://img.shields.io/badge/Version-v0.6.9-10b981.svg)

基于 **Rust** 与 **Tokio** 全新重写的高性能、抗审查代理引擎。继承 Python 版 POC (Shadow-TLS + Reality) 的隐藏特性, 底层彻底重构, 提供内核级 eBPF 加速与内置 Web 看板。

> **定位**: 面向**自建跨境线路的个人/小团队** —— 有一台墙外 VPS + 一台能当网关的 Linux 机器。
> 主打「零配置 eBPF 透明网关」+ 抗被动识别。

> **运行要求**: **Linux 内核 ≥ 5.10** —— eBPF 透明网关依赖 `sk_lookup`(5.9+) / `sk_assign`(5.7+) /
> XDP DNS, 旧内核 (如 Ubuntu 20.04 的 5.4、老 NAS/OpenWrt) 上这些程序**加载会失败**。
> 内核不够也不必放弃: **轻量 / SOCKS 模式不碰 eBPF**, 任意较新 Linux 都能跑 (只是没有透明网关)。
> 服务端**不需要** eBPF (入站是加密流, 自动跳过), 内核门槛只针对**客户端/网关侧**。

---

## 🌟 核心特性概览

* **极致传输与伪装**: TLS 1.3 ClientHello 字节级仿真（多浏览器 Profile 轮换）、TCP Brutal 拥塞控制、无锁化异步架构底座。
* **eBPF 透明网关**: 基于 Linux `sk_lookup` / `tc_divert` 的无感知内核级透明代理，内置抗风暴 DNS 与 Fake-IP 加速。
* **全场景出站与中转**: 支持 WireGuard 与 Shadowsocks (SIP004/SIP022) 上游/出站。
* **高维路由引擎**: 支持按域名、GeoIP/GeoSite、IP CIDR、进程名 (`process_name`) 分流。支持裸 IP SNI 嗅探与 SOCKS5 UDP 逐包路由。
* **内置 Web 看板**: Neon Pulse Dashboard，实时监控流速、eBPF 拦截率，并支持可视化热重载规则。

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
  "outbounds": [],
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

### 🚧 部分完成

- [~] **订阅链接** —— `mirage-rs subscribe <url>` 批量导入 (格式=每行 `mirage://` 或整段 base64, server:port 去重, 可选 --group)。**周期自动刷新**待做
- [~] **SS 上游 UDP** —— 未实现; 需要 UDP 同出口可**直接用 WireGuard 上游** (已通)

### ⏳ 未完成 (计划池)

- [ ] **IPv6 全栈** —— 当前 WireGuard 与透明代理数据面均 **IPv4-only** (DNS 层已可控 v4/v6 返回, 但数据面未通)。这是最大的结构性缺口, IPv6 优先/仅 IPv6 网络 (尤其国内移动网) 下会漏流量或不可用
- [ ] **LAN 每主机监控 + 设备专用规则** (随 WebUI 优化做) —— ① 设备规则: 路由已有 `source_ip_cidr`/`source_mac`, 只需给 TCP 透明路径填 `source_ip` (现为 None, ~2 行, UDP 已填) 即对 TCP 生效。② 每主机用量: eBPF 按源 IP 计上下行字节 (tc 看得到含 splice 直连的全部流量, 用户态计数会漏) → 用户态读 map → API + Neon 面板 per-host 视图 + 可选设备别名
- [ ] **rule-set 远程规则集自动更新** —— 免手动放 geo 文件 (须先定安全模型: 规则决定流量去向, 更新失败必须保留旧规则)
- [ ] **统一出站流接口** (重构) —— 抽 `OutboundNode::connect(target)`, 让 geo 等进程内消费者直连隧道, 不再绕 SOCKS 自连
- [ ] **链式代理 / WG·SS 双向** —— WireGuard、Shadowsocks 既能作出站也能作**入站**, 支持"入站 X → 出站 Y"自定义转发编排。当前二者仅出站/上游, 缺入站侧; 依赖"统一出站流接口"先落地, 大工程分阶段
- [ ] **ICMP 处理** —— ping/traceroute 被代理域名当前不通 (待真机确认失败形态)
- [ ] orphan 验证器接回 CI —— **本地-only** (本机 ≥6.1 稳过, 但 GitHub runner 5.15 与 6.8 都红: 客户端连不上, 是 runner 对"跨进程 sk_assign"场景的兼容问题非产品; 覆盖已由 verify_tc_divert_tcp 兜)。接回需先把验证器改单进程 (仿 tcp.sh)
- [ ] **加密吞吐 (首选, 已 profile)** —— 隧道硬编码 ChaCha20-Poly1305, 不吃 AES-NI。实测本机 AES-256-GCM 比 ChaCha20 快 **2.1x** (release), 回环隧道 154 MB/s 加密占大头。方向: **cipher agility** (有 AES-NI 用 AES-GCM, 否则 ChaCha20, 即 TLS 做法; 需两端协商 cipher, 注意向后兼容)
- [ ] **隧道 relay 缓冲/合帧再调** —— 当前 BufWriter 64KB, 高 BDP 链路可能有余量
- [ ] **io_uring 替代 relay 的 read/write 循环** —— 大工程, 高并发小包收益明显
- [ ] **MSS clamp / 网络层** —— 见 landscape 参考 P1
- **Tailscale 原生支持** —— 官方 Rust 实现当前全走 DERP 中继, 对代理是吞吐硬伤; 让用户自己跑 `tailscaled` + Mirage 直连 `100.64.0.0/10` 今天就能用
- **TLS session resumption 仿真** —— 抓包 + 统计实测证明: 真 Chrome 的 `legacy_session_id` 也每次全新随机, 我们与之不可区分, 立项前提不成立
- **追平 sing-box 全部协议/规则** —— 定位是零配置 eBPF 网关, 不是通用代理框架
---

**评估后决定不做** (避免重复提)

## 📜 版本迭代概览 (Changelog)

Mirage-rs 遵循快速迭代模式，详细更新日志请查阅 [`CHANGELOG.md`](CHANGELOG.md)。

| 版本 | 发布日期 | 核心重大特性 |
| :--- | :--- | :--- |
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
