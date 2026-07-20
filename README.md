# Mirage-rs

![Mirage-rs](https://img.shields.io/badge/Language-Rust-f74c00.svg) ![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg) ![Version](https://img.shields.io/badge/Version-v0.4.5-10b981.svg)

基于 **Rust** 与 **Tokio** 全新重写的高性能、抗审查代理引擎。继承 Python 版 POC (Shadow-TLS + Reality) 的隐藏特性, 底层彻底重构, 内核级 eBPF 加速 + 内置 Neon Dashboard。

## 核心特性

- **无锁化异步架构**: 全异步数据搬运, 千兆网络 + 上万连接场景下内存低占用, CPU 接近理论极限
- **eBPF sk_lookup / tc_divert / XDP**: 内核级透明代理 (拦截 LAN 裸-IP 转发流量) + fake-IP DNS + 直连 splice(2) 零拷贝 (Linux ≥ 5.10)
- **TCP Brutal 拥塞控制**: 单条 TCP 死磕设定速率, 跨洲专线 / 高丢包链路吊打 BBR (设计哲学见下方专章)
- **零延迟认证与伪装**: 首包完成身份验证 + TLS 1.3 握手回放, 时序特征 100% 复刻真实站点
- **抗风暴 DNS (v0.4.5)**: fake-IP 稳定 TTL + 空答复 SOA 负缓存 + 国内上游多路并行/重传, 根治开网页时的 DNS 查询风暴与偶发 ~11s 卡顿
- **日志自动滚动压缩 (v0.4.5)**: 文件日志超 10MB 自动滚动 + gzip 归档, 长跑网关不再撑爆磁盘
- **Neon Pulse Dashboard**: 内置网页大屏, Canvas 时序图展示 eBPF 命中率 / 吞吐量 / 连接动态

---

## 一键安装 (推荐)

**alpha.4+ 起提供交互式安装向导 `install.sh`**, 会自动 (需 root):
- 下载最新预编译二进制到 `/usr/local/bin/mirage-rs` (含 SHA256 双通道校验)
- 探测公网 IP + 端口占用检测 + Brutal 内核模块
- 生成服务端 / 客户端 config, 写 systemd unit `mirage-rs-{server,client}.service`
- 交互配置 GUI 端口 / SNI 伪装 / brutal 速率 / geo 分流策略
- 服务端配完可直接输出 `mirage://` 节点 URI (含二维码), 客户端安装时一步导入

```bash
# 一键运行 (选 1=服务端 / 2=客户端 / 3=同机 / 4=卸载)
curl -fsSL https://raw.githubusercontent.com/zdgt0226/Mirage-rs/main/install.sh | sudo bash
# 或先 clone 再看内容:
git clone https://github.com/zdgt0226/Mirage-rs.git && cd Mirage-rs
sudo bash install.sh
```

装完立刻可用: `sudo systemctl status mirage-rs-{server,client}`.

## 手动部署 (熟悉用户)

前往 [Releases](https://github.com/zdgt0226/Mirage-rs/releases) 拉最新二进制:
- **`mirage-rs-amd64-musl`** — 推荐, 静态链接, 全 Linux 通吃
- `mirage-rs-amd64` — gnu 动态链接, glibc ≥ 2.35 (Ubuntu 22.04+ / Debian 12+ / RHEL 9+)
- `mirage-rs-arm64-musl` — ARM (树莓派 / 甲骨文云 / Ampere)

每个 binary 都有配套 `.sha256`, 校验:
```bash
sha256sum -c mirage-rs-amd64-musl.sha256
```

启动:
```bash
./mirage-rs-amd64-musl client -c /etc/mirage-rs/config_client.json
./mirage-rs-amd64-musl server -c /etc/mirage-rs/config_server.json
```

配置校验与格式化 (不启动服务):
```bash
# 校验: 未知字段 (拼写错误) / 引用了不存在的 outbound / 明显无效值。
# 有问题即非零退出, 适合当重启前的闸门:
mirage-rs check -c /etc/mirage-rs/config_client.json && systemctl restart mirage-rs-client

# 格式化输出到 stdout (不改动原文件, 保留原键序与全部字段):
mirage-rs format -c config.json > config.pretty.json

# 导入 mirage:// 节点为新的 mirage 出站 (会写回配置, 自动备份为 config.json.bak):
mirage-rs import -c config.json "mirage://密码@host:443?sni=www.apple.com"
```

`import` 会交互式询问出站 tag 并**保证不与现有出站 tag 冲突**(撞名就重问, 绝不覆盖既有节点)。
导入只添加出站、**不动路由** —— 要让流量走它, 需自行把 `routing.default_outbound` 或某条
`rule` 的 `outbound` 改成新 tag, 再 `check` 一遍后重启。

> 服务**启动时**也会跑同一套校验, 但那里只打 WARN 不阻止启动 (配置多一个字段就让网关起不来
> 代价太大)。`check` 反过来求"拦得住", 所以有问题就非零退出 —— 两者的严格度差异是刻意的。

⚠️ **内核必须 ≥ 5.10**, 详见下方 [系统兼容性](#系统兼容性)。

### 轻量模式 (只要"能翻墙"就够了)

如果你不需要分流 / fake-IP / 透明网关 / 看板, 只想要「本机 SOCKS5 → 全部走隧道」,
用轻量模式 —— **同一个二进制、同一套协议与伪装**, 与完整版可互通:

```bash
mirage-rs lite-server -c lite_server.json    # 墙外 VPS
mirage-rs lite-client -c lite_client.json    # 本机
```

配置是平铺的极简格式:

```jsonc
// lite_client.json —— server/server_port/password 必填, 其余可省
{
  "listen": "127.0.0.1", "port": 1080,      // 默认值, 可省
  "server": "1.2.3.4", "server_port": 443,
  "password": "你的密码",
  "sni": "www.apple.com",                    // 须与服务端一致
  // 监听 0.0.0.0 时强烈建议设置, 否则是开放代理:
  "auth": { "username": "u", "password": "p" }
}

// lite_server.json —— password 必填
{ "listen": "0.0.0.0", "port": 443, "password": "你的密码", "sni": "www.apple.com" }
```

**与完整版的差别**: 无分流(**全部转发**)、无 DNS/fake-IP、无透明代理、无 Web 看板、
无 geo 数据下载、无配置热重载、**SOCKS5 仅 TCP**(UDP ASSOCIATE 会按规范回 `0x07` 拒绝,
所以 QUIC/HTTP3 走不了代理 —— 浏览器会自动回落 TCP)。
加密、TLS 指纹伪装、握手认证、认证失败转发真站这些**一个都没少**。

> 注: 轻量模式是**运行时**精简, 不是单独编译的小二进制 —— 体积与完整版相同。

---

## 🖥️ 科幻大屏：Neon Pulse Dashboard

我们为 Mirage-rs 打造了一个前端 Web UI。
只要在 config 里 `gui.enabled: true`, `gui.listen: "127.0.0.1:9090"` (install.sh 默认开启):

1. 打开浏览器, 访问: `http://127.0.0.1:9090`
2. 您将看到一个炫酷的 **THE NEON PULSE** 面板。
3. **功能一览**：
   - **历史流速全景图**：上下行速率、eBPF 硬件加速拦截量的 2 分钟滚动折线图，F5 刷新数据不会丢失。
   - **节点秒级切换**：支持 URLTest（自动测速最快节点）、Selector（手动点选切换）。每个节点都会显示 BPF 与 HTTP 真实握手延迟。
   - **活体规则系统**：点击 "+ Add Rule" 可视化添加分流规则（GeoIP、域名后缀等），点击 "Save & Apply" **无感热重载生效**，不会断开正在看视频或下载的 TCP 连接。
   - **沉浸式终端日志**：不用再盯着黑白命令行，实时路由分发动作直接在面板彩色刷新。

> **⚠️ 核心安全警告 (v0.5.0-alpha.1+)**：面板默认 `127.0.0.1` 只监听本机是安全的。若要暴露到 LAN/公网（`gui.listen: "0.0.0.0:..."`），**务必设 `gui.token`**——设了之后所有 `/api/*` 请求都要带它（`Authorization: Bearer <token>` / `mirage_token` cookie / `?token=`），否则任何可达者都能读日志/配置、改路由规则。`install.sh` 选「全网开放」时会**自动生成随机 token 并打印**。浏览器首次访问 `http://host:9090/?token=XXX` 即种 HttpOnly cookie，之后免带。不设 token 仍可用（向后兼容），但非本机暴露时会有 WARN 提醒。生产环境仍建议叠加 Nginx TLS。

---

## 配置文件

`install.sh` 生成的 config 已经是可用状态, 手动配置需要注意 alpha.14+ 引入的新字段。

### 客户端配置示例 (`/etc/mirage-rs/config_client.json`)

```json
{
  "schema_version": 1,
  "log_level": "info",
  "log_file": "/var/log/mirage-rs/client.log",
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "0.0.0.0",
      "port": 1080
    }
  ],
  "outbounds": [
    {
      "type": "mirage",
      "tag": "proxy",
      "server": "vps.example.com",
      "server_port": 443,
      "password": "your-strong-password",
      "camouflage_host": "www.cloudflare.com",
      "pool_size": 50
    },
    { "tag": "direct", "type": "direct" },
    { "tag": "block", "type": "block" }
  ],
  "gui": {
    "enabled": true,
    "listen": "127.0.0.1:9090"
  },
  "routing": {
    "default_outbound": "proxy",
    "rules": [
      { "outbound": "direct", "ip_cidr": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] },
      { "outbound": "direct", "geosite": ["cn", "apple-cn", "google-cn"] },
      { "outbound": "direct", "geoip": ["cn"] }
    ]
  },
  "tuning": {
    "ebpf_mode": "off",
    "geodata_dir": "/etc/mirage-rs/geosite",
    "geo_update_days": 7,
    "geo_sources": [
      {
        "name": "geosite",
        "kind": "geosite",
        "url":  "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
        "via":  "proxy"
      },
      {
        "name": "geoip",
        "kind": "geoip",
        "url":  "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
        "via":  "proxy"
      }
    ]
  }
}
```

#### 关键字段说明

- **`log_file`** (alpha.14+): 可选日志文件路径, 同时输出 stdout (journalctl) + 该文件. 不设保持老 stdout-only 行为
  - **自动滚动压缩 (v0.4.5)**: 单文件超 **10MB** 自动滚动, 旧文件后台 gzip 压缩为 `server.log.1.gz` … `.10.gz` (保留最近 **10** 份, 约 10:1 压缩 → 磁盘 ~10MB 封顶)。压缩在后台线程跑, 不阻塞日志写入; 无需任何配置, 设了 `log_file` 即生效。滚动大小/份数目前硬编码 (`src/monitor.rs::LOG_ROTATE_BYTES / LOG_KEEP_ARCHIVES`)
- **`inbounds[]`**: 标准结构化 (数组), `type: mixed` 同时支持 SOCKS5 + HTTP
- **`outbounds[]`**: `type: mirage` 是代理节点 (旧名 `pyreality` 已弃用)
  - `pool_size`: WarmPool 上限 (默认 16). alpha.11+ 有自动 floor=10 保证突发无 wait build
  - `brutal_rate_mbps` (可选): 客户端出站 brutal 速率. 默认不开 (0 或不写字段)
- **`gui.enabled`** + **`gui.listen`**: alpha.4+ 结构化 (老的 `gui_listen` 单字段弃用)
- **`gui.token`** (v0.5.0-alpha.1+): 可选 API 鉴权 token。设了则所有 `/api/*` 要求携带 (Bearer header / `mirage_token` cookie / `?token=`)。不设=不鉴权 (localhost 默认安全)；`gui.listen` 改 `0.0.0.0` 暴露时**强烈建议**设，install.sh 会自动生成。常量时间校验防时序侧信道
  - ⚠️ **`api.secret` 是废弃 stub，不提供任何鉴权**（历史遗留，解析后从不被使用）。老配置里若有它，**它什么都没做** —— API 鉴权只认 `gui.token`。启动时会 WARN 提醒，未来版本移除。同理 `advanced_dns.rules` 也尚未实现、当前被忽略（DNS 分流由 `routing.rules` 决定）
- **`routing.rules[]`**: `ip_cidr` / `geosite` / `geoip` / `domain_suffix` / `domain_regex` 等
- **`tuning.ebpf_mode`**: `"auto"` / `"force"` / `"off"`. alpha.7 起 install.sh 客户端默认 `"off"` (BPF SockMap 直连转发有已知问题, 见 CHANGELOG alpha.7)
- **`tuning.geo_sources[]`**: 多源 geo 数据下载 (v0.4.3+ 替代旧的 `geosite_url` / `geoip_url`)
  - `via`: `"direct"` 或 `"proxy"`. **`"proxy"` 走客户端 mirage 出口拉 GitHub** — 大陆用户强烈推荐, `install.sh` 默认就是它
  - alpha.14+ 自动 fallback: via=proxy 失败会自动重试 direct
  - alpha.15+ 30s timeout + 空 body 拒收覆盖旧 .dat
  - alpha.17+ 支持热更新: 改 config 加/删 geo_sources 秒生效不必 restart
- **`tuning.geo_update_days`**: 更新间隔天数, 默认 7. alpha.18 起硬 clamp min=1 防 tight loop 打死 CPU

### 服务端配置示例 (`/etc/mirage-rs/config_server.json`)

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

密码 + `camouflage_host` 必须跟客户端完全一致。`brutal_rate_mbps` 是服务端到客户端方向 (下载) 的 brutal 目标速率, 见下方 Brutal 章节。

### 节点 URI 导出/导入 (alpha.4+)

服务端 `install.sh` 配完自动输出:
```
mirage://<url-encoded-pwd>@<host>:<port>?sni=<sni>&brutal=<mbps>
```
保存到 `/etc/mirage-rs/node-export.txt` (chmod 600). 客户端 `install.sh` 选"粘贴节点导入", 直接一步填充 host / port / password / SNI. 装了 `qrencode` 还能出 UTF8 二维码方便手机拍照。

---

## 🌐 透明网关 DNS 与 fake-IP (v0.4.5 重点)

透明网关模式 (`install.sh` 部署模式选 2) 会起一个 DNS 服务 (`type: dns` 入站, 默认 `:53`), LAN 设备把 DNS 指向它。它按域名的分流去向分两条路处理:

### 代理域名 → fake-IP (本地即时应答, 不出网)

被代理规则命中的域名, DNS 直接返回一个 **fake-IP** (默认 `198.18.0.0/15` 段的地址), 客户端拿它建连, 网关的 `tc_divert` 按 fake-IP 段拦截并按域名走隧道。fake-IP 映射稳定 (一个域名固定一个 fake-IP)。

**持久化 (v0.5.0-alpha.4+)**: `advanced_dns.fakeip.persist_path`(install.sh 网关模式默认 `/var/lib/mirage-rs/fakeip.cache`)。设了则启动加载 + 周期(60s)/退出落盘。**意义**: 网关重启后,客户端还揣着的旧 fake-IP(≤300s TTL)仍能反查到域名,避免重启后那段时间代理连接反查失败而断。映射无时间 TTL(稳定,由 round-robin 有界),换 fakeip 网段时旧缓存自动失效。不设 = 纯内存(向后兼容)。

**v0.4.5 抗 DNS 风暴的三处协议/行为调整** (根治开网页时几百倍 DNS 放大 + 偶发 ~11s 卡顿):

| 调整 | 之前 | v0.4.5 | 原因 |
|---|---|---|---|
| fake-IP A 记录 **TTL** | 1s | **300s** | 1s 让客户端几乎每个请求都重查, grass.io/遥测把查询量放大数百倍 → DNS 偶发丢包 → Windows 重传累积 11s。映射本就稳定, 300s 无损 |
| AAAA / type65(HTTPS) **空答复** | 纯 NODATA (无 SOA) | 带一条合成 **SOA** (TTL/MINIMUM=300) | 无 SOA 时 (RFC 2308) 客户端**不做负缓存**, `getaddrinfo` 每次并发重查 AAAA/type65 → 残留查询风暴。带 SOA 后客户端缓存 NODATA 5 分钟 |
| type65 处理 | 逐个走隧道真解析 | 直接空答复 (免隧道) | 现代浏览器对每域名都发 type65, 逐个走隧道会瞬间打空 WarmPool |

> ⚠️ **XDP DNS 加速 (`advanced_dns.xdp_interface`) 默认不开、也不建议开**: 该路径对带 EDNS0 (现代客户端近乎必带) 的查询处理不完整, 开了反而可能让缓存域名解析失败。fake-IP 由用户态 DNS 服务处理已足够快且稳。

### 国内/直连域名 → 真实上游解析 (多上游并行 + 重传, v0.4.5)

被"直连"规则命中的域名 (国内站点等) 走真实上游 DNS (配置里 `tag: direct` / `cn` 的 resolver)。

**v0.4.5 前**: 单上游、单发、**不重传** —— 上游 (114/223 等公共 DNS 高峰期偶发丢包/限速) 丢一个 UDP 包就整体失败, 网关不回包 → 客户端靠自身重传累积 ~11s 才成功 (国外域名走 fake-IP 不碰上游, 故只有国内域名暴露)。

**v0.4.5**: `udp_query` 重写为**多上游并行 + 重传**:
- 每轮向**所有** `direct`/`cn` 上游各发一份查询, 等 800ms, 无匹配响应则重传, 最多 3 轮 (总上限 2.4s ≪ 客户端 11s)
- 任一上游先回且 tx_id/QR 匹配即用 —— 上游健康时仍是**几十毫秒返回, 不增加延迟**, 只有真丢包才触发重传/换上游
- 配置里配**多个** `tag: direct` resolver 即启用多上游; 一个都没配时默认双公共 DNS 兜底 (`114.114.114.114` + `223.5.5.5`)

**配置示例** (`install.sh` 透明网关模式会问"主用/备用直连 DNS" 自动生成):

```json
"advanced_dns": {
    "resolvers": [
        { "tag": "direct", "address": "223.5.5.5:53" },
        { "tag": "direct", "address": "114.114.114.114:53" },
        { "tag": "remote", "address": "8.8.8.8", "via": "proxy" }
    ],
    "fakeip": { "enabled": true, "inet4_range": "198.18.0.0/15" }
}
```

> 尊重配置: 你配了 `direct` resolver 就**只用你配的那些** (不掺公共 DNS, 避免内网/split-horizon 域名被公共 DNS 解析错); 只有一个 `direct` 都没配时才回落到双公共兜底。`remote` (境外) DNS 走隧道查, 抗污染。

### DNS 响应缓存 (v0.5.0-alpha.3+, honoring TTL)

`advanced_dns.cache: { "enabled": true, "max_entries": 10000 }`（install.sh 网关模式默认开启）：按上游返回的**最小 TTL** 缓存直连 + 隧道-DNS 的响应，过期再查。

- **直连域名**不再每查都打 114/223 上游；
- **最实在的收益**：非 fake-IP 模式 / 罕见 qtype (MX/TXT/SRV) 的**隧道-DNS 不再每次消耗一条 WarmPool 隧道**——缓存命中直接免隧道。
- 只缓存有答案的正响应（NODATA/NXDOMAIN 不缓存，客户端 SOA 负缓存已兜 AAAA）；命中时 patch tx_id + question 段兼容 0x20；TTL clamp `[1, 3600]`s。
- fake-IP 路径本地即时应答，无需缓存。

> **为什么不用 DoH/DoT**：墙内 DoT(853) 端口即封、DoH(443) 靠 SNI 阻断 + 封公共解析器 IP + 投毒，对公共解析器长期不可靠。Mirage 的抗审查 DNS 靠的是**远端解析**（被墙域名走 fake-IP，真解析推到墙外服务端）+ 本缓存 + TTL，而非加密到公共解析器。

---

## ⚡ 高级玩家指南：拥抱 Linux 极客内核

### 开启 TCP Brutal 模块（仅在服务端执行）
要想体验让拥塞控制算法跑出上限的快感，您可以在服务端（墙外 VPS）安装 `tcp_brutal` 内核模块：

**方法一：官方一键安装（推荐）**
```bash
curl -fsSL https://tcp.hy2.sh/ | bash
```

**方法二：手动编译安装**
```bash
git clone https://github.com/apernet/tcp-brutal
cd tcp-brutal && make && sudo make install
sudo modprobe tcp_brutal
```
*提示：Mirage-rs 会自动检测内核是否有该模块，如果没有，会自动回退到默认的 BBR 或 Cubic，绝不崩溃。*

### brutal_rate_mbps 的设计哲学 (v0.4.4-alpha.10+ 新解, 请务必看)

**Brutal CC 死磕设定速率, 不响应丢包**, 适合"高 RTT + 低丢包"的**跨洲专线 / 移动 4G/5G 无线**链路 — 这种链路上 BBR/Cubic 见丢包就退让, brutal 反而能吃满。

**关键设计** (alpha.8+ 修正):
- 服务端在 **listener socket 预设** `TCP_CONGESTION = brutal`, accept 出来的子 socket 从 SYN-ACK 起就跑 brutal (kernel pacing 状态干净)
- accepted socket 只补 `TCP_BRUTAL_PARAMS` (rate + cwnd_gain=15)
- 无 autofallback (alpha.9+): brutal 顶着丢包硬跑到底, 跟 Python POC 行为一致

**速率取值**:

| 场景 | 单连接 rate 建议 | 说明 |
|---|---|---|
| 100M 出口 (家宽) | 30~50 Mbps | 链路带宽的 30-50% |
| 1G 出口 (VPS) | 300~500 Mbps | 链路带宽的 30-50% |
| 极限吃满 (跨洲专线) | 链路带宽的 1.5-2 倍 | Hysteria2 派设值哲学, 让 brutal 有余量填满信道 |
| 关闭 brutal | `0` 或不设 | 系统默认 BBR, 适合低 RTT 高丢包的 CDN 链路 |

**为什么单连接可以设这么高**? WarmPool 里同一时刻真正在传数据的通常只有 1-3 条 tunnel (浏览器每 host 6-8 并发), 空闲 tunnel 不占用带宽. 所以"单条 × pool_size 总和"这个公式**不成立**, brutal 的单条 rate 可以直接对齐链路带宽。

**如果发现慢**:
1. 用 `ss -tipn 'sport = :你的端口'` 看 `retrans` 比例
2. `retrans < 5%` → 链路适合 brutal, rate 可以往上加
3. `retrans > 15%` → 链路不适合 brutal (低 RTT 高丢包 CDN 常见), 把 rate 设 0 关掉走 BBR 反而更快
4. 观察 `pacing_rate` 是否达到设定, `delivery_rate` 是否接近 `pacing_rate`

alpha.5-11 的排错长征见 [CHANGELOG](CHANGELOG.md), 大约 8 个 alpha 版本才把这套调准。

### eBPF 性能巨兽开关（仅限 Linux 客户端/网关）
我们在 `v0.2.x` 为核心路由链路植入了内核态网卡劫持。
**启用条件**：
1. 内核 ≥ 5.10 (sk_lookup 透明代理 + sockmap 加速 + XDP DNS 全部需要)。
2. 使用 `sudo` 权限运行客户端 `sudo ./mirage client -c config...`
3. 享受魔法：启动日志将提示 `[eBPF] XDP program successfully loaded and attached to primary interface`，并且您的 Neon 仪表盘上会出现耀眼的 **eBPF ENGINE: ONLINE**！它能直接在网卡接收端剥离解析包，无视系统网络栈延迟。

---

## 🐧 系统兼容性

Mirage-rs 是 **eBPF 原生**代理, 性能与隐蔽性深度依赖现代 Linux 内核能力。我们和 [dae](https://github.com/daeuniverse/dae) 一样选择**不为老内核做架构妥协** — 没有 TPROXY 后备模式, 没有 TUN 后备模式。

### 内核版本要求

| 内核版本 | 状态 | 说明 |
|---|---|---|
| **≥ 5.10** (LTS) | ✅ 全功能 | sk_lookup 透明代理 + sockmap splice + XDP DNS 全部可用 |
| 5.9 | ⚠️ 边界版本 | sk_lookup 首版, 推荐升级至 5.10 LTS |
| < 5.9 | ❌ 不支持 | 透明代理路径无法启动 |

### 主流发行版查表

| 发行版 | 默认内核 | 状态 |
|---|---|---|
| Debian 12 (Bookworm) | 6.1 | ✅ |
| Debian 11 (Bullseye) | 5.10 | ✅ |
| Debian 10 / 9 | 4.19 / 4.9 | ❌ |
| Ubuntu 24.04 / 22.04 LTS | 6.8 / 5.15 | ✅ |
| Ubuntu 20.04 LTS | 5.4 (HWE 内核可达 5.15) | ⚠️ 启用 HWE 后可用 |
| Ubuntu 18.04 及更早 | < 5.4 | ❌ |
| RHEL / Rocky / Alma 9 | 5.14 | ✅ |
| RHEL / CentOS 8 | 4.18 (ELRepo 可装 kernel-ml) | ⚠️ 装 kernel-ml 后可用 |
| RHEL / CentOS 7 | 3.10 | ❌ |
| Alpine 3.18+ | 6.x | ⚠️ 客户端需手动开启 BPF 内核配置 (见下方); 服务端无需 |
| Arch Linux / Manjaro | 滚动最新 | ✅ |

如果你需要 SOCKS5 / HTTP 普通入站, 老内核也能跑 (不启用 eBPF 模块即可), 但 v0.3 的透明代理核心特性会自动跳过。

### Alpine Linux 内核要求 ⚠️ (仅客户端)

**服务端不受影响** — 自 v0.4.1-alpha.3 起, `mirage server` 默认完全跳过 eBPF 加载 (服务端走"协议解密 → 直连"路径, sockmap splice/sockops/XDP/sk_lookup 全部子系统在服务端都无价值). Alpine 服务端可以直接用 stock `linux-lts` / `linux-virt` 内核.

**客户端需要手动开启 BPF 内核配置**: Alpine 默认的 `linux-lts` / `linux-virt` 内核**关闭了 BPF cgroup 子系统** (`CONFIG_CGROUP_BPF=n`), 导致 SockOps 加载时 `bpf_link_create failed`。Mirage-rs 客户端会启动但 RTT 监控 + Brutal CC 动态速率全部失效。

完整启用步骤参考 [dae 的 Alpine 教程](https://github.com/daeuniverse/dae/blob/main/docs/en/tutorials/run-on-alpine.md), 关键的内核配置:

```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
CONFIG_CGROUP_BPF=y          # ← Alpine 默认 =n, 必须开
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_BTF=y      # ← BTF 调试信息, CO-RE 用
CONFIG_BPF_STREAM_PARSER=y   # ← sockmap splice 需要
CONFIG_NET_INGRESS=y
CONFIG_NET_EGRESS=y
CONFIG_NET_CLS_BPF=m
CONFIG_NET_CLS_ACT=y
CONFIG_BPF_EVENTS=y
CONFIG_KPROBES=y
CONFIG_KPROBE_EVENTS=y
```

验证当前内核是否支持:

```sh
zcat /proc/config.gz | grep -E 'CGROUP_BPF|BPF_SYSCALL|DEBUG_INFO_BTF|BPF_STREAM_PARSER'
```

如果上面输出有 `=n` 或没有, 你需要从 alpine-aports 源码重编内核, 或换用 `daeuniverse/dae` 仓库提供的预编译 Alpine 内核包。

---

## 卸载

`install.sh` 主菜单第 4 项 "卸载 (Uninstall)":
- 停止 + 禁用 `mirage-rs-server` / `mirage-rs-client` systemd 服务 (同时清老名字 `mirage-server` / `mirage-client` 兼容 alpha.8 之前的部署)
- 删除 unit 文件 + 二进制 `/usr/local/bin/mirage-rs`
- 交互询问是否删 `/var/log/mirage-rs` (默认 y) / `/etc/mirage-rs` config (默认 n, 重装可复用) / `/var/lib/mirage-rs` / `/etc/sysctl.d/99-mirage.conf`

```bash
sudo bash install.sh
# 选 4 → 全自动清理
```

## 版本演进

alpha.4 → **v0.4.5 (final)** 的重要里程碑:

| 版本 | 关键改动 |
|---|---|
| alpha.4-9 | Brutal 排错长征 (cwnd_gain / listener 时序 / autofallback / cwnd_gain 15) |
| alpha.7 | eBPF SockMap 直连转发弃用 → 改 splice(2)+pipe 零拷贝 |
| alpha.10-11 | WarmPool 反馈算法修正 (cwnd_gain=15 对齐 POC, floor 提到 10) |
| alpha.12-18 | 初始 target 修正 / TIME_SYNC 降噪 / log_file / geo 完整性校验+via proxy fallback / 热更新架构 UpdaterHandle / update_days clamp |
| alpha.19-26 | **透明网关成型**: tc_divert 纯 eBPF 抓 LAN 裸-IP 分流 (netns 实测) + 透明 UDP + cgroup/connect4 本机流量 + 异常链路修复 (握手缓存毒化/僵尸泄漏/pool 饿死) |
| alpha.27-31 | 真机部署踩坑修复: 透明 listener `Backlog::MAXCONN` EINVAL 根治, fake-IP TCP/UDP 真机首次跑通 |
| alpha.32-34 | **抗 DNS 风暴**: fake-IP TTL 1s→300s + 空答复 SOA 负缓存 (根治网页 ~11s 卡顿) + **全量代码审计** (逐行审 ~11K Rust + 852 eBPF C, 修 5 处: 越界 panic / varint 溢出 / XDP-EDNS0 畸形 / 重放窗口 / fd 复用) |
| **alpha.35** | DNS 上游解析加**重传 + 多上游并行兜底** (根治国内域名偶发 11s) |
| **v0.4.5 (final)** | 日志按大小滚动 + gzip 压缩归档收尾 |

> **协议调整摘要 (v0.4 → v0.4.5)**: ①时间同步内嵌协议 (服务端 handshake 后经加密 channel 下发 `[0x01][ver][8B unix sec]` 帧, 客户端写全局 offset, 0 外部依赖/0 指纹); ②DNS 空答复带合成 SOA (RFC 2308 负缓存); ③fake-IP 稳定 TTL 300s。密码派生 info 常量 `pyrealiy-session` 为历史冻结值, **切勿修改** (两端必须一致)。

完整清单见 [CHANGELOG.md](CHANGELOG.md)。

**后续开发从 `v0.5.0` 版本号开始。**

---

*"在数字迷雾中构筑坚不可摧的幻象。" —— Mirage-rs 团队*
