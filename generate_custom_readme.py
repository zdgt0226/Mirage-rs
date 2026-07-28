import re

with open("README.md", "r", encoding="utf-8") as f:
    orig = f.read()

def extract_section(regex_pattern, text):
    match = re.search(regex_pattern, text, re.DOTALL)
    return match.group(1).strip() if match else ""

# Extracting Sections
install_sh_sec = extract_section(r"(## 一键安装 \(推荐\).*?)(?=\n## 手动部署|\n## 🖥️)", orig)
relay_mode_sec = extract_section(r"(### 中转站模式 \(服务端接 Shadowsocks 上游\).*?)(?=\n### WireGuard|\n### 轻量模式)", orig)
lite_mode_sec = extract_section(r"(### 轻量模式 \(只要\"能翻墙\"就够了\).*?)(?=\n---|\n##)", orig)
server_cfg_sec = extract_section(r"(### 服务端配置示例[^\n]*\n.*?```json.*?```.*?)(?=\n### 透明网关|\n### 节点 URI)", orig)
todo_sec = extract_section(r"(## 路线图 / TODO.*?)(?=\n## 版本演进|\n---)", orig)

# Sanitize server cfg to use details
server_cfg_sec = re.sub(
    r'(### 服务端配置示例[^\n]*\n)(.*?)```json\n(.*?)\n```(.*)',
    r'\1<details>\n<summary>点击查看: 服务端配置示例 (config_server.json)</summary>\n\n```json\n\3\n```\n</details>\n\4',
    server_cfg_sec,
    flags=re.DOTALL
)

simplified_readme = f"""# Mirage-rs

![Mirage-rs](https://img.shields.io/badge/Language-Rust-f74c00.svg) ![Platform](https://img.shields.io/badge/Platform-Linux-blue.svg) ![Version](https://img.shields.io/badge/Version-v0.6.8-10b981.svg)

基于 **Rust** 与 **Tokio** 全新重写的高性能、抗审查代理引擎。继承 Python 版 POC (Shadow-TLS + Reality) 的隐藏特性, 底层彻底重构, 提供内核级 eBPF 加速与内置 Web 看板。

> **定位**: 面向**自建跨境线路的个人/小团队** —— 有一台墙外 VPS + 一台能当网关的 Linux 机器。
> 主打「零配置 eBPF 透明网关」+ 抗被动识别。

---

## 🌟 核心特性概览

* **极致传输与伪装**: TLS 1.3 ClientHello 字节级仿真（多浏览器 Profile 轮换）、TCP Brutal 拥塞控制、无锁化异步架构底座。
* **eBPF 透明网关**: 基于 Linux `sk_lookup` / `tc_divert` 的无感知内核级透明代理，内置抗风暴 DNS 与 Fake-IP 加速。
* **全场景出站与中转**: 支持 WireGuard 与 Shadowsocks (SIP004/SIP022) 上游/出站。
* **高维路由引擎**: 支持按域名、GeoIP/GeoSite、IP CIDR、进程名 (`process_name`) 分流。支持裸 IP SNI 嗅探与 SOCKS5 UDP 逐包路由。
* **内置 Web 看板**: Neon Pulse Dashboard，实时监控流速、eBPF 拦截率，并支持可视化热重载规则。

---

{install_sh_sec}

---

## 🛠️ 灵活的部署形态

{lite_mode_sec}

---

{relay_mode_sec}

---

## ⚙️ 服务端配置说明

{server_cfg_sec}

> 注: 客户端与透明网关的详细配置示例见 `templates/` 目录下的注释版模板。

---

{todo_sec}

---

## 📜 版本迭代概览 (Changelog)

Mirage-rs 遵循快速迭代模式，详细更新日志请查阅 [`CHANGELOG.md`](CHANGELOG.md)。

| 版本 | 发布日期 | 核心重大特性 |
| :--- | :--- | :--- |
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
"""

with open("README.md", "w", encoding="utf-8") as f:
    f.write(simplified_readme)

print("Custom rewrite done.")
