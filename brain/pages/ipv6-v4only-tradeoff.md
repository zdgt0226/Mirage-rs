---
id: ipv6-v4only-tradeoff
title: "透明路径 IPv4-only 是取舍而非漏洞 (靠 AAAA 抑制)"
category: decision
status: active
created: "2026-07-20T11:43:27"
updated: "2026-07-20T12:19:58"
---

## compiled_truth

**现状**:透明路径整条 **IPv4-only**。`tc_divert.c:121` 对 `h_proto != ETH_P_IP` 直接 `TC_ACT_OK` 放行;
`direct_cidr` LPM key 仅 4 字节;`transparent_udp.rs` 对 IPv6 目标 warn + drop;无 AF_INET6 listener。

**这不是泄漏漏洞**:DNS 层已兜底 —— 对被代理域名的 AAAA 查询返回 NODATA + 合成 SOA(**秒回**)。
客户端并发查 A+AAAA 时:A 拿 fake-IP、AAAA 秒回空 → 强制走 v4 fake-IP → 被 `tc_divert` 拦。
**既不漏也不卡**("Happy Eyeballs 卡 3-5s"的说法前提是 AAAA 超时,而这里是秒回)。
直连域名返回真 AAAA 走原生 v6 直连,本就该直连,不算泄漏。

**真实缺口很窄**:仅"应用使用 **IPv6 字面量**直连本应被代理的目标"(不经 DNS)才泄漏。罕见。

**补齐的代价**:是**整条路**的工程,不是只改 `tc_divert` —— fake-v6 段 / AAAA 改返 fake-v6 /
tc_divert v6 + LPM 16B / listener AF_INET6 / `IPV6_ORIGDSTADDR` / `direct_cidr`+geoip v6 / sk_lookup v6。
(隧道 UDP 帧 `ATYP=4` 已支持 v6。)Landscape 的 `union u_ld_ip` 统一地址抽象值得借鉴。

**结论**:现状不漏故**优先级中**;随 v6 普及会从"取舍"变"硬伤"。


## timeline

- time: 2026-07-20T11:43:27
  kind: decision
  summary: "Created this page: 透明路径 IPv4-only 是取舍而非漏洞 (靠 AAAA 抑制)"
  source: "ebpf-src/tc_divert.c:121, src/dns/server.rs"
  affects: [ipv6-v4only-tradeoff]

- time: 2026-07-20T12:19:58
  kind: decision
  summary: "澄清 v4-only 是设计取舍而非泄漏漏洞"
  source: "ebpf-src/tc_divert.c:121, src/dns/server.rs"
  affects: [ipv6-v4only-tradeoff]
