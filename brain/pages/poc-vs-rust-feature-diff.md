---
id: poc-vs-rust-feature-diff
title: "Python POC vs Mirage-rs 功能差异与取舍"
category: reference
status: active
tags: [poc, comparison, architecture, ebpf, tradeoff]
created: "2026-07-28T09:56:25"
updated: "2026-07-28T09:57:38"
---

## compiled_truth

POC 源: `/opt/claude/mirage/` (~15k 行 Python; `pyrealiy-*` 是同源旧名副本)。见 [[rust-rewrite-from-python-poc]]。

## 定位/架构迁移
| 维度 | POC (Python) | Mirage-rs (Rust) |
|---|---|---|
| 运行时 | Python 3.11 + uvloop | Rust + Tokio 无锁 |
| 源码 | ~15k Python | ~23k Rust + 781 eBPF C |
| 透明代理 | **iptables TPROXY** (IP_TRANSPARENT + 防火墙规则) | **eBPF sk_lookup/tc_divert/sk_assign** (无 iptables) |
| 零拷贝 | 无 (用户态拷贝) | **splice(2)+pipe** |
| 内核地板 | 低 (老内核有 iptables) | **≥5.10** (sk_lookup 5.9/sk_assign 5.7) |

## 继承的核心 (两边对等, 非差异)
零延迟认证 (Poly1305 嵌 legacy_session_id) · 零延迟伪装 (缓存真站 TLS 握手回放, [[camouflage-forward-on-auth-fail]]) · 多浏览器 JA3 轮换 · ChaCha20-Poly1305+HKDF c2s/s2c 独立密钥 · **防重放** (nonce+60s 时间桶, 两边都有) · TCP Brutal · 每节点连接池+被动延迟采集 · 域名+IP 分流 (suffix/keyword/regex/CIDR/GeoSite/GeoIP, or/and, [[routing-rules]])。

## Mirage-rs 新增 (POC 没有)
- **eBPF 透明网关** (sk_lookup 拦裸-IP 转发, 免 iptables; XDP DNS), 见 [[ebpf-scope-narrowed]]
- **fake-IP DNS** (POC 只 config 桩**未实现**; Rust 完整 198.18/15+远程解析+持久化, [[fakeip-remote-resolution]])
- **DNS 劫持+静态解析+ip_strategy** (POC 只有转发器)
- **Shadowsocks 出入站** (SS2022 双向+上游中转; POC 无)
- **splice 零拷贝直连** ([[splice-over-sockmap]]; Python 做不了)
- **load_balance 组** (POC 只 urltest/fallback/selector; Rust 多 round-robin, [[load-balance-outbound]])
- **process_name 分流** (/proc 反查, [[process-name-routing]])
- **subscribe/export CLI** (订阅导入+配置片段导出闭环, [[subscription-import]] [[config-export-fragment]]; POC 只 WS API)
- **GeoIP 节点区域判定** ([[node-region-geoip]])
- **Neon Dashboard + lite 模式**

WireGuard 出站两边都有 (POC egress.py / Rust boringtun+smoltcp)。

## Mirage-rs 砍掉/替换的 POC 功能 (取舍)
| POC 有 | Rust 处理 | 理由 |
|---|---|---|
| **Clash API 兼容** (clash_endpoints.py) | 刻意不做, 走自有 API+面板 | [[no-clash-api]]; selector 改自有 API/配置 |
| 完整 WS/admin API (admin.py 711 行) | 自有轻量 API+面板 | 减面, 不做管理平台 |
| bloom 域名预过滤 | aho-corasick/前缀树 | 无需 Python hash() 那套优化 |
| DoT-over-tunnel (dns/tls_over_tunnel.py) | 隧道内远程解析 (fake-IP 路线) | [[no-doh-dot]]: DoH/DoT 不当抗审查手段 |

## 横向取舍
| 轴 | POC 优 | Rust 优 |
|---|---|---|
| 部署门槛 | ✓ 老内核可跑, 无编译 | 需 ≥5.10 + eBPF ([[ipv6-v4only-tradeoff]] 同族约束) |
| 性能 | | ✓ 无 GIL, splice, eBPF, 无用户态拷贝 |
| 透明网关体验 | | ✓ 零 iptables, 内核直拦 (软路由零配置) |
| 生态兼容 | ✓ Clash API 接现成 GUI | 自有面板 |
| 协议完整度 | 对等 | ✓ 多 SS/fake-IP/LB/进程分流 |
| 内存占用 | 高 (Python 运行时) | ✓ 低 (适合 256MB ARM 软路由) |

**结论**: Rust 版 = POC 抗审查协议内核 **100% 继承** + 数据面**彻底换 eBPF/splice** (换性能与零配置透明网关, 代价内核地板抬到 5.10) + 补齐 fake-IP/SS/负载均衡/进程分流工程能力 + **主动砍 Clash 生态绑定**。POC 唯一净胜项 = **老内核部署门槛**。


## timeline

- time: 2026-07-28T09:56:25
  kind: decision
  summary: "Created this page: Python POC vs Mirage-rs 功能差异与取舍"
  source: created via brain create-page
  affects: [poc-vs-rust-feature-diff]

- time: 2026-07-28T09:57:38
  kind: decision
  summary: "POC(Python+uvloop+iptables-TProxy) vs Mirage-rs(Rust+eBPF+splice): 协议内核100%继承, 数据面换eBPF, 补fake-IP/SS/LB/进程分流, 砍Clash生态"
  source: "/opt/claude/mirage (POC), /opt/claude/Mirage-rs"
  affects: [poc-vs-rust-feature-diff]
