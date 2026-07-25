---
id: dns-hijack-lan
title: "DNS 劫持 (可选): 复用 tc_divert sk_assign, 纯用户态"
category: decision
status: active
tags: [dns, transparent, tc_divert, fakeip]
created: "2026-07-25T22:37:45"
updated: "2026-07-25T22:37:45"
---

## compiled_truth

## 决定

透明网关新增**可选** DNS 劫持 (默认关): LAN 设备无需把 DNS 指向网关, 流经的 53 端口
查询即被本机 DNS 服务接管、返回 fake-IP。开关在 install.sh 安装时询问, 或配置 transparent
入站 `"dns_hijack": true`。

## 为什么走这条路 (路线 A: sk_assign 复用, 非 DNAT 改包)

关键洞察: **零新内核机制**。tc_divert 的 `bpf_sk_assign` 本就抓 LAN 全部转发流量 (含
53 端口), 透明 listener/UDP socket + 回包源伪造 (回 orig_dst:53) 也都已就位并经 netns
verifier 验证。DNS 劫持只是在用户态给 orig_dst 端口 53 加一个分支, **不改包、无 conntrack、
不加 iptables/nftables**。相比 DNAT 改包方案 (双校验和 + conntrack), 干净得多。

## 边界 (用户明确框定)

- **只劫持转发流量, 不碰本机自身 DNS** (本机 DNS 走正常配置)。
- **不处理 DoT/DoH** —— 加密流量无从识别端口/内容。
- 只 53/UDP + 53/TCP。

## 实现落点

- UDP: `transparent_udp.rs::setup_flow` 对 orig_dst 端口 53 直接 `resolve_query` 本地
  应答, 不建 flow (一问一答, 每查询独立源端口=独立 flow key)。
- TCP: `transparent.rs` accept 后 `handle_tcp_dns`, 按 `[2B 大端长度][报文]` 逐条
  读→解析→回写 (RFC 7766 单连接多查询)。长度分帧有单元测试。
- forwarder: `DnsForwarder::for_hijack` 构造"只处理查询、不 serve"实例, 与 dns 入站
  共用 fake_ip_mapper; `process_query` 不碰 self.socket 故可复用。
- 关闭时 (默认) 53 流量照常按路由走, 行为不变。

关联 [[fakeip-remote-resolution]] (劫持返回的正是 fake-IP)、[[mss-clamp-merged-into-tc-divert]]。


## timeline

- time: 2026-07-25T22:37:45
  kind: decision
  summary: "Created this page: DNS 劫持 (可选): 复用 tc_divert sk_assign, 纯用户态"
  source: "feat/dns-hijack 分支"
  affects: [dns-hijack-lan]

- time: 2026-07-25T22:37:45
  kind: decision
  summary: "透明网关可选 DNS 劫持: 零新机制, 复用 tc_divert sk_assign + 透明回包, 默认关"
  source: brain update-truth
  affects: [dns-hijack-lan]
