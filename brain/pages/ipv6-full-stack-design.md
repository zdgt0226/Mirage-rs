---
id: ipv6-full-stack-design
title: "IPv6 全栈透明代理设计 (镜像 v4 三层模型)"
category: decision
status: active
tags: [ipv6, transparent, ebpf, fakeip, tc_divert, roadmap]
created: "2026-07-28T02:32:06"
updated: "2026-07-30T02:43:30"
---

## compiled_truth

**决定 (2026-07-30 瘦身)**: 原"整条透明数据面 v6"大 epic (fake-v6/tc_divert v6/sk_lookup v6/v6 listener/direct_cidr6) **评估后否**。核心洞见: **fake-IP + 服务端远程解析**架构下, **客户端的 v6 数据面本就不必要**。

## 为什么客户端不需要 v6 数据面
- 被代理(海外)域名: AAAA 抑制 → 客户端拿 v4 fake-IP → 隧道 → **服务端**解析真址并连 (v4/v6 都行)。见 [[fakeip-remote-resolution]]。
- 连**海外 v6-only 站点也已经能用**: 客户端只发 A → fake-IP; 服务端远程解析发现只有 AAAA → 服务端侧连 v6。客户端全程 v4 fake-IP。
- AAAA 抑制**现已实现**: process_query 的 Mirage 分支对 AAAA(28)/HTTPS(65) 回 NODATA 空答复。

## 唯一要补: 隧道传输走 IPv6 (小)
让 v6-only/v6-优先客户端网络 (国内移动) 能**够到服务端**:
- 服务端 bind v6 (`listen: "[::]:443"`): ✅ `TcpListener::bind(&str)` 已支持
- 客户端连服务端 (server 域名解析到 v6): ✅ `TcpStream::connect("host:port")` getaddrinfo 自动 v6
- 客户端连服务端 (server **v6 字面量**): ⚠️ pool.rs:522 `format!("{}:{}")` 对裸 v6 缺方括号 → 需小修 `[::1]:443`
- 服务端→海外目标 v6: ✅ `connect_smart` 按域名解析+failover 两族都连
- **实际新代码 ≈ 客户端 v6 字面量加方括号 + 文档**, 服务端 v6 监听/域名→v6/服务端连 v6 全已就绪。

## 接受的残留 (诚实)
1. **v6 字面量直连被代理目标** (app 不经 DNS 直拨海外 v6) → 透明层不拦 (tc_divert 放行 v6) → 直连泄漏/失败。罕见, 即 [[ipv6-v4only-tradeoff]] 那个"唯一真缺口", 接受。
2. **纯 v6-only 无 v4 的 LAN 终端**访问海外: AAAA 抑制返 NODATA, 无 v4 用不了 fake-IP。但国内移动多是双栈+CGNAT v4, 纯 v6-only 罕见。文档注明。
3. 国内 v6 直连 = 网关做 v6 路由 (内核转发, 非代码; tc_divert 放行 v6 → 内核原生路由), 基本已通。

## 结论
IPv6 从 P1-P5 五期 epic → **1 个小 PR (隧道传输 v6)**。roadmap 里 IPv6 的前置权重大幅下降, 不再是挡 LAN 监控/链式代理的大地基。旧 epic 的 tc_divert v6 等设计**归档否决**。


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

- time: 2026-07-30T00:37:25
  kind: decision
  summary: "IPv6 瘦身: 不做透明数据面v6 epic; 只需隧道传输走v6(小)+DNS抑制海外AAAA(已实现)。fake-IP+服务端远程解析已让客户端v6数据面不必要"
  source: "src/proxy/pool.rs, src/dns/server.rs"
  affects: [ipv6-full-stack-design]

- time: 2026-07-30T02:43:30
  kind: note
  summary: "IPv6 数据面已知限制 (v0.7.0 隧道传输落地后复核): (1) 服务端直连 UDP 出站 socket 硬绑 v4 —— mirage_server/udp_relay.rs:78 与 transparent_udp.rs:555 均 UdpSocket::bind(0.0.0.0:0), send_to v6 目标会 Network unreachable; 当前不可达 (客户端压制海外 AAAA + 透明 UDP 面 v6 直接 drop), 属 deferred scope 非回归. 做 v6 数据面时按目标 AF 动态选 0.0.0.0:0 / [::]:0. (2) 透明 UDP 硬拦 v6: transparent_udp.rs:551/617 if real.is_ipv6() return, 有意, 数据面 v6 边界. (3) net_util::join_host_port 不处理 scope ID (fe80::1%eth0): Ipv6Addr::parse 拒 %scope; 远端节点永不会 link-local, 且 stable Rust 加括号也 parse 不了 scope, 零影响不修."
  source: "外部审查(Gemini)复核 + 源码确认"
  affects: [src/proxy/mirage_server/udp_relay.rs, src/proxy/transparent_udp.rs, src/net_util.rs]
