---
id: chain-proxy-roadmap
title: "链式代理 roadmap: WG/SS 双向 (入站+出站) + 自定义转发"
category: decision
status: draft
tags: [roadmap, chain-proxy, wireguard, shadowsocks, architecture]
created: "2026-07-27T01:30:56"
updated: "2026-07-27T01:31:30"
---

## compiled_truth

## 用户诉求 (2026-07-27)

后续要**链式代理**: WireGuard 和 Shadowsocks 作为对接协议, **既能作入站也能作出站**,
实现自定义转发 (如 SS 入 → WG 出, 或 Mirage 入 → SS 出 的任意编排)。

## 当前状态 (差距)

- **Shadowsocks**: 仅**出站/上游** (`UpstreamConfig::Shadowsocks`, 服务端把流量再经 SS 发上游,
  仅 TCP)。**无 SS 入站** (不能接受 SS 客户端)。
- **WireGuard**: 出站 (`OutboundConfig::Wireguard`) + 上游 (`UpstreamConfig::Wireguard`)。
  **无 WG 入站** (不能作 WG 服务端/responder 接受 peer)。
- 入站只有 Socks/Mixed/Dns/Transparent/MirageServer。

## 方向 (分阶段, 大工程 —— 不塞进小改)

1. **抽象出站流接口** (roadmap 已有): `OutboundNode::connect(target) -> Stream`, 让所有出站
   (Mirage/WG/SS/Direct) 统一; 是链式转发的地基。
2. **SS 入站**: 实现 SS 服务端协议 (SIP004/022 解密 + 目标解析), 作 inbound。
3. **WG 入站**: 实现 WG responder (boringtun 服务端侧 + smoltcp), 接受 peer, 取隧道内 TCP/UDP。
4. **自定义转发链**: 路由/出站编排让"入站 X → 出站 Y"任意组合 (类 sing-box inbound→outbound)。

## 决定

**认可方向, 但不在当前小改里做** (一次吞太大违背简单优先)。先记为 roadmap, 后续独立分阶段推进。
设计新东西时保持与此兼容 (如 dns_tcp_resolver、出站接口抽象都不挡路)。根 roadmap 见 brain/roadmap.md。

关联 [[server-dns-over-tcp]]。


## timeline

- time: 2026-07-27T01:30:56
  kind: decision
  summary: "Created this page: 链式代理 roadmap: WG/SS 双向 (入站+出站) + 自定义转发"
  source: "用户 2026-07-27 提出"
  affects: [chain-proxy-roadmap]

- time: 2026-07-27T01:30:56
  kind: decision
  summary: "未来方向(未实现): WG/SS 既能作入站也能作出站, 支持自定义转发链; 当前二者仅出站/上游, 缺入站侧实现; 大工程, 分阶段"
  source: brain update-truth
  affects: [chain-proxy-roadmap]

- time: 2026-07-27T01:31:30
  kind: decision
  summary: "未来方向(未实现): WG/SS 既能作入站也能作出站, 支持自定义转发链; 当前二者仅出站/上游, 缺入站侧实现; 大工程, 分阶段"
  source: brain update-truth
  affects: [chain-proxy-roadmap]
