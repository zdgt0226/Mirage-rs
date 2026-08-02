---
id: chain-proxy-roadmap
title: "链式代理 roadmap: WG/SS 双向 (入站+出站) + 自定义转发"
category: decision
status: draft
tags: [roadmap, chain-proxy, wireguard, shadowsocks, architecture]
created: "2026-07-27T01:30:56"
updated: "2026-08-02T19:48:12"
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

- time: 2026-08-02T19:48:12
  kind: decision
  summary: "链式代理(5) 设计吸收 (Gemini 方案对比, 2026-08-02)。前置 [[unified-outbound-stream]] Phase A 已给 OutboundNode::connect(target)->OutStream (building block)。链式代理的核心增量 = **underlying_dialer 注入** (Gemini 方案精华, 即 sing-box detour / 俄罗斯套娃): 让协议的 dial 可选地穿另一个 dialer 返回的流拨号, 而非物理网卡 —— 例 SS 出站注入 WG 出站作 underlying_dialer, SS.dial 时先 WG.dial(ss_server) 拿到隧道流, 再在其上做 SIP022 握手返回 Box<dyn Stream>。零耦合套装。另吸收 Address 枚举 (Domain/SocketAddr) 替 &str+split_host_port。**三个坑别照抄 Gemini**: (1) AnyStream 别加 Sync bound (MirageStream 持 BoxFuture 非 Sync, 流只需 Send); (2) 别上 #[async_trait] (加依赖+每调用装箱; Rust 1.75 原生 async trait 已稳, 或保持枚举); (3) 别整体把 OutboundNode 枚举擦成 Arc<dyn OutboundDialer> (大重写高风险) —— 优先增量: 枚举变体加 underlying_dialer 字段即可套娃, 热路径流类型保留 OutStream 枚举 (无 vtable) 而非 Box<dyn AnyStream>。handler.rs 用 connect+copy_bidirectional 去重 (Gemini Phase1 / 我们 unified-outbound Phase C) 是可选清理, 动热路径风险高, 与链式代理解耦分开做。"
  source: "Gemini 链式代理方案 vs 我们 Phase A 对比 + Rust async trait/Sync 现实"
  affects: [chain-proxy-roadmap, unified-outbound-stream, src/proxy/outbound.rs]
