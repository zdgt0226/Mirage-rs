---
id: tailscale-support-deferred
title: "暂不做 Tailscale 原生支持 (WireGuard 已覆盖多数需求)"
category: decision
status: active
tags: [wireguard, tailscale, scope]
created: "2026-07-22T12:51:44"
updated: "2026-07-22T12:52:46"
---

## compiled_truth

**决定**: 暂不为 Mirage 实现 Tailscale 原生支持。WireGuard 出站/上游 (见 [[ss-upstream-relay]] 的同类中转形态) 已覆盖绝大多数需求。

## 为什么"支持了 WG 所以 Tailscale 不难"是错的

WireGuard 只是 Tailscale 的**数据面**。已有的 WG 实现在 Tailscale 里可复用比例很低,缺的全是控制面:

- 与 coordination server 的自定义控制协议 (节点注册、netmap 分发、密钥轮换)
- 认证 (OAuth/SSO、auth key)
- **DERP 中继** —— 直连失败时走 (CGNAT 后是常态), 是另一套 HTTP/WebSocket 协议
- **disco / NAT 打洞** —— 端点发现、STUN、路径选择、端点漂移

还有架构层面的硬冲突: 本项目的 `WgTunnel` 是**单 peer + 静态 endpoint**; Tailscale 是**多 peer 且 endpoint 由 magicsock 动态漂移**。这不是加字段能解决的, 是基本假设不成立。

## 关键判断依据 (不是"难", 而是"做了更差")

官方 [tailscale-rs](https://github.com/tailscale/tailscale-rs) (crate `tailscale`, v0.4.0, 2026-07 仍活跃) 自述: **当前所有通信走 DERP 中继, NAT 打洞尚未实现**, 并明确说这给吞吐设了上限。

对**代理**而言这是硬伤: DERP 是为控制面与兜底设计的中继, 不是为吞吐; 而 Tailscale 的价值恰在打洞后的直连。现在接进来会得到一个"能连但慢"的出站, 且用户会归因于 Mirage。

## 替代方案 (今天就能用, 零代码)

用户自行运行 `tailscaled`, Mirage 用 `direct` 出站连 `100.64.0.0/10` 地址 —— 内核已把该网段路由进 tailscale 接口。要按规则分流就加一条匹配该网段的路由规则, 现有功能全支持。

## 重新评估的触发条件

`tailscale-rs` 实现 NAT 打洞 (不再全量依赖 DERP) 之后。那时原生支持才有真价值 —— 省掉用户装 tailscaled 这一步。


## timeline

- time: 2026-07-22T12:51:44
  kind: decision
  summary: "Created this page: 暂不做 Tailscale 原生支持 (WireGuard 已覆盖多数需求)"
  source: "2026-07-22 讨论"
  affects: [tailscale-support-deferred]

- time: 2026-07-22T12:52:46
  kind: decision
  summary: "评估后决定暂不做: 复用率低 + 官方 Rust 实现当前全走 DERP 中继, 体验不如让用户直接跑 tailscaled"
  source: "2026-07-22 讨论"
  affects: [tailscale-support-deferred]
