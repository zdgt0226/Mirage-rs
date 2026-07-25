---
id: dns-ip-strategy
title: "DNS IP 版本策略 (ip_strategy): 抑制某族, 非真优先; static+direct"
category: decision
status: active
tags: [dns, ipv6, static, strategy]
created: "2026-07-26T01:59:42"
updated: "2026-07-26T01:59:42"
---

## compiled_truth

## 决定

`advanced_dns.ip_strategy` 控制 DNS 应答 IP 版本, 5 档 (默认 `dual`):
`dual` / `ipv4_only` / `ipv6_only` / `prefer_ipv4` / `prefer_ipv6`。

## 关键认知 (语义陷阱)

纯 DNS 服务器按记录类型 (A/AAAA) **分别**应答, 客户端各发一个查询、自己用 Happy Eyeballs
挑。服务端**无法在单查询里"优先"** —— 唯一能做的是**抑制某一族** (回 NODATA 逼客户端用
另一族)。所以"优先"只能靠"有首选族时抑制另一族"近似。

## 作用范围 (用户选"全局 static+direct", 排除 proxied)

- **硬模式** (`ipv4_only`/`ipv6_only`): static + direct 都抑制另一族。
- **软模式** (`prefer_*`): **仅 static 完全生效** (static 已知全部地址族 → 有首选族才抑制
  另一族)。direct/上游无法廉价探测另一族是否存在 → 降级为 `dual` (不抑制)。
- **proxied (Mirage/fake-IP) 不动**: 按设计恒 v4-fakeIP + AAAA 抑制。故 `ipv6_only` 下走代理
  的域名仍是 v4 fake-IP —— 与 v4-only 代理数据面绑定的已知限制。

## 与 IPv6 数据面修复解耦 (用户问过)

本功能纯在 DNS 应答层, **不依赖**代理数据面的 IPv6 支持: static/direct 返回真实地址,
客户端**原生**连接 (有 v6 网络就走 v6, 不经代理)。唯一交集是 proxied 无法被逼成 v6
(没有 v6 fake-IP), 已作为限制记录。故先做本功能、IPv6 数据面 (transparent/fake-IP v6)
仍归 roadmap 独立推进。

## 实现

- config: `IpStrategy` enum (Copy, Default=Dual, serde snake_case) + `AdvancedDnsConfig.ip_strategy`。
- server: 纯函数 `ip_strategy_suppresses(strategy, qtype, has_v4, has_v6) -> bool` (direct 传
  has_*=false 使 prefer 降 Dual; static 传真实值)。`static_answer` 加 strategy 参数;
  process_query 在 drop(st) 前取出 ip_strategy, Direct 分支硬抑制前置。三处逻辑纯函数化 + 单测
  (抑制矩阵 / static prefer+only)。

关联 [[dns-static-resolution]] (prefer 完全生效处)、[[dns-hijack-lan]] (共用 process_query)、
[[fakeip-remote-resolution]] (proxied v4-fakeIP 的由来)。


## timeline

- time: 2026-07-26T01:59:42
  kind: decision
  summary: "Created this page: DNS IP 版本策略 (ip_strategy): 抑制某族, 非真优先; static+direct"
  source: "feat/dns-hijack 分支"
  affects: [dns-ip-strategy]

- time: 2026-07-26T01:59:42
  kind: decision
  summary: "advanced_dns.ip_strategy 5 档控制 v4/v6 应答: 纯 DNS 只能抑制某族(NODATA), prefer 仅 static 生效, direct 只硬抑制, proxied 不动; 与 v4-only 数据面解耦"
  source: brain update-truth
  affects: [dns-ip-strategy]
