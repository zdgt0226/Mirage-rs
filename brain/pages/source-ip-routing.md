---
id: source-ip-routing
title: "source_ip 路由语义: 发起方 IP (含本机 cgroup 出向), DNS 路径暂 None"
category: decision
status: active
tags: [routing, source-ip, transparent, dns]
created: "2026-08-16T15:57:49"
updated: "2026-08-16T15:58:08"
---

## compiled_truth

## 语义

RoutingRequest.source_ip = **发起方 IP**, 供 `source_ip_cidr` (按设备/网段分流) 匹配。

- **TCP** (proxy_tcp_target): `local.peer_addr()` 归一 (v4-mapped→v4)。透明网关=LAN 客户端真实 IP
  (TPROXY 保留源址); SOCKS/mixed=发起方。**含本机出向**: cgroup/connect4 重定向本机 fake-IP 连接
  时 peer=127.0.0.1 → source_ip=127.0.0.1 也参与匹配。
- **SOCKS-UDP** (udp_relay): 同样填 + 归一。
- **透明 UDP** (transparent_udp): SocketAddrV4 恒 v4, 无需归一。
- **DNS** (dns/server.rs process_query): **故意 None** —— 按源分流 DNS 查询 (每主机 DNS 策略) 未
  实现。要做把 run_loop 的 from 传进来即可 (成本低), 但填了 = source_ip_cidr 开始作用于 DNS 解析
  路由 = 行为新增, 需产品决策。

## 关键取舍 / 陷阱

- source_ip=发起方 IP **非仅 LAN 设备**: "非某网段一律走 X" 会把本机流量 (127.0.0.1) 算进去
  (语义自洽, 但与"只圈 LAN"直觉有差)。要精确圈 LAN 就在 cidr 排除 127.0.0.0/8。
- v4-mapped v6 必须归一成 v4 (双栈 socket), 否则 v4 CIDR `contains` 不中 (见 handler::normalize_peer_ip)。

## 历史

- 修前 source_ip 恒 None → source_ip_cidr 对 TCP 死规则 (只 UDP 生效)。#47 修 TCP + SOCKS-UDP 归一。
- 外部审计后续观察补: cgroup 本机出向语义 (本页) + DNS 路径仍 None (记录为未实现非疏漏)。

关联: [[routing-rules]] [[process-name-routing]]


## timeline

- time: 2026-08-16T15:57:49
  kind: decision
  summary: "Created this page: source_ip 路由语义: 发起方 IP (含本机 cgroup 出向), DNS 路径暂 None"
  source: commit docs/source-ip-semantics
  affects: [source-ip-routing]

- time: 2026-08-16T15:58:08
  kind: decision
  summary: "source_ip=发起方IP(TCP/UDP填, 含本机cgroup出向127.0.0.1); DNS路径故意None(每主机DNS未实现)"
  source: brain update-truth
  affects: [source-ip-routing]
