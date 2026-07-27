---
id: ipv6-full-stack-design
title: "IPv6 全栈透明代理设计 (镜像 v4 三层模型)"
category: decision
status: active
tags: [ipv6, transparent, ebpf, fakeip, tc_divert, roadmap]
created: "2026-07-28T02:32:06"
updated: "2026-07-28T02:34:59"
---

## compiled_truth

**目标**: 补齐 IPv6 透明代理, 闭合当前唯一真缺口 —— "应用用 **v6 字面量**直连本应被代理的目标 (不经 DNS)"。现状见 [[ipv6-v4only-tradeoff]] (v4-only 是取舍非漏洞, 靠 AAAA 抑制兜底)。

## 架构 = 把现有 v4 三层模型镜像到 v6

| 流类型 | v4 现状 | v6 设计 |
|---|---|---|
| 域名代理流 | 被代理域名 A → fake-ip, tc_divert 拦 | AAAA → **fake-v6**, tc_divert v6 拦 (**保留域名路由信息**) |
| IP 直连快路径 | `direct_cidr` LPM 4B → `TC_ACT_OK` 原生直连 | `direct_cidr6` LPM 16B → 原生直连 |
| v6 字面量代理 | v4 字面量已覆盖 | 非 direct 非 fake 的真 v6 dst → sk_assign, listener 读 `IPV6_ORIGDSTADDR` → 隧道 ATYP=4 **(闭缺口)** |

DNS 改动是关键: 被代理域名 AAAA 从"NODATA 抑制"改为"返 fake-v6", 让 v6-preferring 应用也把流量交给数据面。直连域名仍返真 AAAA 走原生 v6 直连。

## 决策 (2026-07-28, 用户定)

- **fake-v6 段 = `2001:2::/48`** (RFC 5180 benchmarking, 语义对应 v4 的 198.18/15)。ULA 方案被否。风险: 少数网络可能对该段特殊处理; /48 容量足 (2^80)。同 v4 fake_ip_net 可配。
- **透明 listener = 双栈单 socket (AF_INET6, IPV6_V6ONLY=0, v4-mapped)**。⚠️**风险 (需 P2 实测)**: `IP_TRANSPARENT` 是 v4 sockopt, 双栈上要靠 `IPV6_TRANSPARENT` + v4-mapped TPROXY 投递 + v4/v6 origdst 混在一个 recvmsg 里取, Linux 语义有坑。**若 P2 落地发现坏 → 回退两个独立 v4/v6 listener** (备选方案已评估, 干净但多一个 socket)。
- **协议层已就绪**: 隧道 TCP 目标是字符串 (v6 字面量当 `[host]:port` 传, control.rs:110 长度前缀), UDP 帧 ATYP=4 已支持 (udp_relay.rs:5)。只需客户端正确括号编码 v6 字面量。
- **借鉴** landscape `union u_ld_ip`: eBPF 侧用 `union {v4; v6[16]} + family`, 省两套 map/分支重复 (详见 docs/landscape-analysis.md)。

## 卡点清单 (~16, 已定位到行)

**eBPF-C:**
- `tc_divert.c:121` — 加 `ETH_P_IPV6` 分支解析 ipv6hdr (现直接 `TC_ACT_OK` 放行)
- `tc_divert.c:86,155` — 第二张 16B LPM map `direct_cidr6`, prefixlen=128 + daddr[16]
- `tc_divert.c:177+` — sk_lookup 用 `bpf_sock_tuple.ipv6` 分支
- `tc_divert.c:38` — MSS clamp v6 偏移 (v6 头固定 40B, 无 ihl; 注意扩展头)
- `transparent.c` — sk_lookup v6 listener 注册
- `cgroup_connect.c:79` — `connect6` hook (现只改 user_ip4)

**Rust:**
- `transparent.rs:42` — AF_INET6 listener + IPV6_TRANSPARENT + v6 ORIGDSTADDR
- `transparent_udp.rs` — v6 origdst / dual FlowKey / frame_udp_ipv6 (SocketAddrV4 遍布, 大改)
- `transparent_net.rs` — fake-v6 net + 路由安装 (现 Ipv4Addr)
- `ebpf/tc_divert.rs:97` — `sync_direct_cidrs6(&[Ipv6Net])`
- `config_watcher.rs:23` — `direct_v6_cidrs`
- `router/mod.rs:251` — v6 CIDR 规则匹配 (现 `all_v4_cidrs`)
- `dns/fake_ip.rs` — fake-v6 分配器 (现 Ipv4Addr-only)
- `dns/server.rs:197` — 被代理域名 AAAA 改返 fake-v6 (弃现 NODATA 抑制, 见 `ip_strategy_suppresses`)

## 分期 (multi-PR epic)

| 期 | 内容 | 依赖 |
|---|---|---|
| P1 | DNS: fake-v6 分配器 + AAAA 返 fake-v6 (纯用户态, 无 eBPF) | 无 |
| P2 | tc_divert v6 分支 + `direct_cidr6` + v6 TCP transparent listener (双栈单 socket) | P1 |
| P3 | v6 UDP transparent (transparent_udp v6 大改) | P2 |
| P4 | cgroup connect6 + MSS clamp v6 + 路由 v6 CIDR 规则 | P2 |
| P5 | 真机双栈验证 (SYN/UDP/v6 字面量/Happy Eyeballs 不卡) | P1-P4 |

本轮=只出设计, 未排 PR。关联 [[ipv6-v4only-tradeoff]] [[fakeip-remote-resolution]] [[splice-over-sockmap]] [[syn-only-sk-assign]]。


## timeline

- time: 2026-07-28T02:32:06
  kind: decision
  summary: "Created this page: IPv6 全栈透明代理设计 (镜像 v4 三层模型)"
  source: created via brain create-page
  affects: [ipv6-full-stack-design]

- time: 2026-07-28T02:32:48
  kind: decision
  summary: "IPv6 全栈设计: fake-v6=2001:2::/48 + direct_cidr6 + v6字面量passthrough, 镜像v4三层; 双栈单socket; 分P1-P5"
  source: "ebpf-src/tc_divert.c, src/proxy/transparent*.rs, src/dns/{fake_ip,server}.rs"
  affects: [ipv6-full-stack-design]

- time: 2026-07-28T02:34:59
  kind: decision
  summary: "IPv6 全栈设计: fake-v6=2001:2::/48 + direct_cidr6 + v6字面量passthrough, 镜像v4三层; 双栈单socket; 分P1-P5"
  source: "ebpf-src/tc_divert.c, src/proxy/transparent*.rs, src/dns/{fake_ip,server}.rs"
  affects: [ipv6-full-stack-design]
