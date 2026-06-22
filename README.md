# Mirage-rs

![Mirage-rs](https://img.shields.io/badge/Language-Rust-f74c00.svg) ![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-blue.svg) ![Version](https://img.shields.io/badge/Version-v0.2.3-10b981.svg)

基于 **Rust** 与 **Tokio** 全新重写的高性能、抗审查代理引擎。在继承了 Python 版 `Mirage` (Shadow-TLS + Reality) 的极致隐藏特性的基础上，`Mirage-rs` 进行了彻底的底层重构，引入了真正的内核级流量加速与赛博朋克风格的监控面板。

## 🌟 核心特性 (v0.2.x 新纪元)

- **无锁化异步架构 (Lock-free)**：全异步数据搬运，摆脱历史包袱。即便在千兆网络、过万连接的高压环境下，内存占用依旧极低，CPU 利用率接近理论极限。
- **eBPF / XDP 内核级加速**（独占）：在网卡驱动层（XDP）直接挂载 eBPF 字节码，毫秒级捕获 DNS 数据包与特定的碎包流量。相比经过内核网络栈 (TCP/IP) 处理，**PPS 处理能力提升百倍**。
- **动态自适应 Brutal 拥塞控制**（独占）：打破了传统 TCP Brutal 需要“猜”死板速率的困境！引入动态 BDP（带宽延迟乘积）与 RTT 探测计算，在网络通畅时保持极限压榨，在丢包抖动时平滑退避，实现“暴力”与“优雅”的完美结合。
- **零延迟认证与伪装**：继承系列优良传统，首包完成身份验证并即刻开启 TLS 1.3 握手回放，实现 0 RTT 和与伪装站点绝对一致的响应时序特征。
- **科幻级 Neon Pulse 可视化大屏**（独占）：引擎内置极具未来感的网页 Dashboard，以时间序列 Canvas 曲线为您描绘每一秒的 eBPF 命中率、下行吞吐量与连接动态。

---

## 🛠️ 安装与部署 (对小白绝对友好！)

得益于 Rust 的特性，您**不需要安装任何依赖环境（不需要 Python，不需要 pip）**！我们通过强大的 CI/CD 流水线，为您准备好了能在任何系统上“点开即用”的静态二进制包。

### 1. 下载预编译版本 (推荐)
前往项目的 [Releases 页面](#)，下载对应您系统架构的压缩包：
*   **推荐所有 Linux 用户**：`mirage-rs-amd64-musl` (静态链接, 不依赖宿主 glibc, 在所有现代 Linux 上"开箱即用")
*   **gnu 动态链接版**：`mirage-rs-amd64` (要求 glibc ≥ 2.35, 即 Ubuntu 22.04+ / Debian 12+ / RHEL 9+)
*   **ARM 架构** (树莓派 / 甲骨文 ARM 等)：`mirage-rs-arm64-musl`

⚠️ **不论选哪个二进制, 你的内核版本必须 ≥ 5.10**。详见下方 [系统兼容性](#-系统兼容性) 矩阵。

解压后，得到一个名为 `mirage` 的单文件可执行程序。

### 2. 启动服务

**作为客户端运行（本地机器/路由器）：**
```bash
./mirage client -c config_client.json
```

**作为服务端运行（墙外 VPS）：**
```bash
./mirage server -c config_server.json
```

*(想要在后台挂机运行？可以使用 `tmux` 或者配置 `systemd` 守护进程)*

---

## 🖥️ 科幻大屏：Neon Pulse Dashboard

我们为 Mirage-rs 打造了一个令人惊叹的前端 Web UI。
只要在 `config_client.json` 中配置了 `gui_listen`（默认开启）：

1. 打开浏览器，访问：`http://127.0.0.1:9090`
2. 您将看到一个炫酷的 **THE NEON PULSE** 面板。
3. **功能一览**：
   - **历史流速全景图**：上下行速率、eBPF 硬件加速拦截量的 2 分钟滚动折线图，F5 刷新数据不会丢失。
   - **节点秒级切换**：支持 URLTest（自动测速最快节点）、Selector（手动点选切换）。每个节点都会显示 BPF 与 HTTP 真实握手延迟。
   - **活体规则系统**：点击 "+ Add Rule" 可视化添加分流规则（GeoIP、域名后缀等），点击 "Save & Apply" **无感热重载生效**，不会断开正在看视频或下载的 TCP 连接。
   - **沉浸式终端日志**：不用再盯着黑白命令行，实时路由分发动作直接在面板彩色刷新。

> **⚠️ 核心安全警告**：面板目前依靠内部接口进行局部防护，如果您要把它暴露到公网（比如通过 VPS 访问），**请一定在外面套一层 Nginx 并加上密码认证**，否则任何人都能随意修改您的路由规则。

---

## ⚙️ 配置文件全解

`mirage` 使用标准的 JSON 进行配置。

### 客户端配置示例 (`config_client.json`)

```json
{
  "fakeip": {
    "inet4_range": "198.18.0.0/15"
  },
  "inbounds": [
    {
      "type": "mixed", 
      "listen": "127.0.0.1:1080"
    }
  ],
  "outbounds": [
    {
      "tag": "my-tokyo-node",
      "type": "mirage",
      "server": "198.51.100.1",
      "server_port": 443,
      "password": "your-strong-password",
      "camouflage_host": "www.apple.com",
      "pool_size": 20,
      "brutal_rate_mbps": 8
    },
    {
      "tag": "auto",
      "type": "urltest",
      "outbounds": ["my-tokyo-node"],
      "interval": 60,
      "tolerance": 50
    },
    {
      "tag": "manual-pick",
      "type": "selector",
      "outbounds": ["my-tokyo-node", "auto"],
      "default": "auto"
    },
    { "tag": "direct", "type": "direct" },
    { "tag": "block", "type": "block" }
  ],
  "route": {
    "default": "auto",
    "rules": [
      {
        "rule_set": ["loyalsoldier:category-ads-all"],
        "outbound": "block"
      },
      {
        "geoip": ["cn"],
        "outbound": "direct"
      },
      {
        "domain_suffix": ["google.com", "youtube.com"],
        "outbound": "auto"
      }
    ]
  },
  "gui_listen": "127.0.0.1:9090",
  "dns": {
    "listen": "127.0.0.1:5353",
    "cn": "119.29.29.29",
    "remote": "8.8.8.8:53"
  }
}
```

#### 关键字段释疑（哪怕是小白也要看这里）：
*   `fakeip`: **DNS 伪装响应**。开启后，代理引擎会拦截所有 DNS 请求并立即返回 `198.18.x.x` 网段的保留 IP，彻底根除 DNS 泄漏问题与 DNS 解析延迟。在遇到网络请求时，系统会自动将伪装 IP 还原成真实域名并进行路由分发。
*   `inbounds`: **数据入口**。`mixed` 类型代表它同时支持 SOCKS5 和 HTTP 代理。您只需在操作系统的网络代理设置里填入 `127.0.0.1:1080` 即可。
*   `outbounds`: **数据出口**。
    *   `type: mirage` 就是您的境外 VPS 节点配置（旧版名称 `pyreality` 同样兼容，但强烈推荐改用 `mirage` 保持规范）。
    *   `brutal_rate_mbps`: **单条 TCP 连接的目标速率** (不是总带宽). 推荐 8-10, 上限 10. 多连接并发时各自独立打满设定值, 设高会拖累总速度. 详见下方 "Brutal 设计哲学" 章节.
    *   `type: urltest`: 自动测速组。把您的多个 VPS 节点 tag 塞进数组，它会自动帮你选延迟最低的用。**高阶细节**：我们的 urltest 并非无脑发送 HTTP 探针，而是**优先提取底层的 socket RTT（TCP 真实握手延迟）**进行决策，全程零开销！只有在连接池彻底闲置时，才会使用 HTTP probe 作为后备唤醒手段。
    *   `type: selector`: 手动点选组。与 Neon Dashboard 面板无缝联动，您可以在网页上自由指定流量出口，不爽自动选路时可以直接接管。
*   `route`: **交通警察**。如果访问的 IP 在 `cn` 库中，走 `direct` 直连；如果访问谷歌，走 `auto` 出国；广告全走 `block` 丢弃。

### 服务端配置示例 (`config_server.json`)

```json
{
  "listen_host": "0.0.0.0",
  "listen_port": 443,
  "password": "your-strong-password",
  "camouflage_host": "www.apple.com",
  "camouflage_port": 443
}
```
*(就这么简短！保持密码和客户端一致，找一个干净的伪装站点即可。)*

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

### brutal_rate_mbps 的设计哲学 (看了再设值)

**Brutal CC 是 ★ 单条 TCP ★ 跑满目标速率的拥塞控制**, 跟 BBR / Cubic 随网络情况自适应不同 — 它不主动让步, 设置多少就发多少, 直接对抗高延迟/丢包链路的概率性退让.

但 Mirage 的 WarmPool 会同时持有多条 brutal 连接, 它们互相不知道彼此存在, **各自独立打满设定值**. 因此设值哲学跟"链路总带宽"无关:

| 单连接 rate | 50 条并发总需求 | 1G 链路效果 | 100M 链路效果 |
|---|---|---|---|
| **8 Mbps (推荐)** | 400 Mbps | 充足缓冲 | 高并发场景接近上限, 日常单流稳定 |
| 10 Mbps (上限) | 500 Mbps | 仍有余量 | 多并发可能进入拥塞边缘 |
| 50 Mbps (危险) | 2.5 Gbps | 严重过载 | 完全拥塞崩溃 |
| 100 Mbps (错误) | 5 Gbps | 灾难 | 灾难 |

**推荐**: 不分 100M / 1G 链路, 一律配 **8-10 Mbps**。**上限红线 10 Mbps**。

原理: 单流场景 (一个大文件下载, 一段视频) 单条 brutal 连接 8 Mbps 已经稳得很; 多流场景 (一堆并发请求) brutal 不会主动让步, 必须靠 ★ 单连接低 rate ★ 留出多连接共用空间, 而不是靠"我有 1G 链路就把每条设到 100 Mbps"那种直觉算法.

> 不建议超过 10 Mbps. 超过会拖累整体速度而不是提升, 因为多连接并发总需求超出链路 → 持续丢包 → Brutal 不响应丢包继续发 → 路径上的队列填满 → 全部连接都被拖累.

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
| Alpine 3.18+ | 6.x | ⚠️ 需手动开启 BPF 内核配置, 见下方 |
| Arch Linux / Manjaro | 滚动最新 | ✅ |

如果你需要 SOCKS5 / HTTP 普通入站, 老内核也能跑 (不启用 eBPF 模块即可), 但 v0.3 的透明代理核心特性会自动跳过。

### Alpine Linux 内核要求 ⚠️

Alpine 默认的 `linux-lts` / `linux-virt` 内核**关闭了 BPF cgroup 子系统** (`CONFIG_CGROUP_BPF=n`), 导致 SockOps 加载时 `bpf_link_create failed`。Mirage-rs 启动会跑起来, 但 RTT 监控 + Brutal CC 动态速率全部失效。

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

*"在数字迷雾中构筑坚不可摧的幻象。" —— Mirage-rs 团队*
