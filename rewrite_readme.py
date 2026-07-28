import re

with open("README.md", "r", encoding="utf-8") as f:
    content = f.read()

# 1. Wrap large JSON config blocks in <details>
def wrap_json_in_details(match):
    summary_text = "点击查看详细配置示例"
    return f"<details>\n<summary>{summary_text}</summary>\n\n" + match.group(0) + "\n</details>"

# The sections that have huge JSONs:
# ### 客户端配置示例
# ### 服务端配置示例
# ### 透明网关完整配置模板 (v0.6.1)
# We will just target the ```json ... ``` or ```jsonc ... ``` blocks after these headers.

# Let's replace specifically those blocks by finding them.
content = re.sub(
    r'(### 客户端配置示例[^\n]*\n.*?)```json\n(.*?)\n```',
    r'\1<details>\n<summary>点击查看: 客户端配置示例 (config_client.json)</summary>\n\n```json\n\2\n```\n</details>',
    content,
    flags=re.DOTALL
)

content = re.sub(
    r'(### 服务端配置示例[^\n]*\n.*?)```json\n(.*?)\n```',
    r'\1<details>\n<summary>点击查看: 服务端配置示例 (config_server.json)</summary>\n\n```json\n\2\n```\n</details>',
    content,
    flags=re.DOTALL
)

content = re.sub(
    r'(### 透明网关完整配置模板[^\n]*\n.*?)```jsonc\n(.*?)\n```',
    r'\1<details>\n<summary>点击查看: 透明网关完整配置模板 (gateway.jsonc)</summary>\n\n```jsonc\n\2\n```\n</details>',
    content,
    flags=re.DOTALL
)


# 2. Rewrite the "版本演进" section to have the major version table.
# Find where "## 版本演进" starts
idx = content.find("## 版本演进")
if idx != -1:
    content = content[:idx] + """## 📜 版本迭代概览 (Changelog)

Mirage-rs 遵循快速迭代模式，详细更新日志请查阅 [`CHANGELOG.md`](CHANGELOG.md)。

| 版本 | 发布日期 | 核心重大特性 |
| :--- | :--- | :--- |
| **v0.6.8** | 2026-07-28 | **配置片段 Export/Import 闭环**: 支持交互式导出节点与规则 JSON 片段，支持 `subscribe` 导入本地文件合并；全局代码护栏加固。 |
| **v0.6.7** | 2026-07-28 | **负载均衡组**: 新增 `load_balance` 出站组 (Round-Robin 分摊)；支持 URL 订阅批量导入；集成节点 GeoIP 区域判定与分组告警。 |
| **v0.6.6** | 2026-07-27 | **进程名分流**: 支持按发起程序名路由 (`process_name`)；新增 `dump_tls` 会话指纹量化分析工具。 |
| **v0.6.5** | 2026-07-27 | **DNS-over-TCP兜底**: 服务端可选 `dns_tcp_resolver`，彻底解决 VPS 屏蔽出口 UDP 导致的域名解析失败问题。 |
| **v0.6.4** | 2026-07-26 | **智能网络质量探测**: 节点测活集成 HTTP 穿隧道端到端探测，联动 TCP RTT 自动揭露“离得近但出口线路烂”的劣质节点。 |
| **v0.6.1** | 2026-07-26 | **DNS 三件套重构**: 支持局域网 53 端口流量劫持接管；新增 `advanced_dns.static` 内网静态解析；新增 `ip_strategy` IPv4/IPv6 双栈返回控制。 |
| **v0.6.0** | 2026-07-23 | **WireGuard 全面接入**: 客户端出站与服务端上游支持 WireGuard (纯用户态协议栈)；修复 SOCKS5 UDP 绕过路由问题；改进 Geo 更新器。 |
| **v0.5.0** | 早期 | 引入 Neon Pulse Dashboard 可视化看板；重写 DNS 引擎支持 TTL 缓存与抗风暴机制。 |
| **v0.4.5** | 早期 | 抗 DNS 风暴机制完善（多上游并发与重传）；TCP Brutal CC 优化定型；eBPF 透明网关正式成型。 |

---
*"在数字迷雾中构筑坚不可摧的幻象。" —— Mirage-rs 团队*
"""

with open("README.md", "w", encoding="utf-8") as f:
    f.write(content)

print("Rewrite done.")
