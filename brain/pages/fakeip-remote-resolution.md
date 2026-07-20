---
id: fakeip-remote-resolution
title: "fake-IP + 服务端远程解析: 不信任本地 DNS"
category: decision
status: active
created: "2026-07-20T11:43:26"
updated: "2026-07-20T12:19:18"
---

## compiled_truth

**决定**:被代理域名的 DNS 查询返回**保留段 fake-IP**(198.18.0.0/15),真实域名随隧道送到**墙外服务端远程解析**。
客户端与网关**从不**接触被代理域名的真实 IP。

**明确拒绝的备选**:Landscape 式"DNS 解析出真实 IP → 灌 eBPF map → 按 IP 分流"。
对纯路由器合理,对抗审查**是错的**:它要求先在本地解析出真实 IP,而墙内 DNS 可能被污染。

**配套的坑与定论**:
- **fake-IP 响应 TTL 绝不能设短**。曾硬编码 1s → Windows 几乎每请求重查 → DNS 查询风暴 → 偶发 ~11s 卡顿。
  提到 300s 根治。映射本就稳定,短 TTL = 自造风暴。
- **AAAA / type65(HTTPS/SVCB) 返回带合成 SOA 的空答复**。无 SOA 时(RFC 2308)客户端不做负缓存,
  会每次并发重查;type65 若逐个走隧道真解析会瞬间打空 WarmPool(浏览器对每域名都发)。
- XDP DNS 加速(`advanced_dns.xdp_interface`)**默认关且不建议开** —— 对带 EDNS0 的查询处理不完整。

**影响面**:这是整个抗审查设计的地基,牵动 [[no-doh-dot]] 与透明路径的 [[ipv6-v4only-tradeoff]]。


## timeline

- time: 2026-07-20T11:43:26
  kind: decision
  summary: "Created this page: fake-IP + 服务端远程解析: 不信任本地 DNS"
  source: "src/dns/fake_ip.rs, docs/landscape-analysis.md, README"
  affects: [fakeip-remote-resolution]

- time: 2026-07-20T12:19:18
  kind: decision
  summary: "沉淀抗审查 DNS 的核心前提"
  source: "src/dns/, docs/landscape-analysis.md, README"
  affects: [fakeip-remote-resolution]
