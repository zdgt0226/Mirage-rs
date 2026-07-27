---
id: process-name-routing
title: "process_name 分流: 本机 loopback 经 /proc 反查进程名, 非 eBPF"
category: decision
status: active
tags: [routing, process-name, proc, loopback]
created: "2026-07-27T11:18:40"
updated: "2026-07-27T11:18:40"
---

## compiled_truth

## 决定

路由规则加 `process_name` 维度 (comm 精确匹配), 实现"Telegram 走代理、微信直连"。

## 关键: 只对本机连接有意义 (非选择, 是物理约束)

process_name 只能查**本机发起**的连接。透明网关/LAN 转发的连接进程在**别的机器**上, 无从取。
故仅对**本机 loopback socks/mixed 入站**判定; 其它入站该维度恒 None, 带 process_name 的规则
不命中 (同 [[routing-rules]] 的 inbound "信息缺失不猜")。

## 实现 (纯用户态, 不用 eBPF)

README 说"已有 cgroup/connect4 eBPF 基础", 但核实 cgroup_connect.c **没抓 comm**。且 eBPF
connect4 只覆盖网关本机出向 (niche)。故走用户态 /proc (Clash/sing-box 的本地进程匹配同款):
- `proxy::proc_lookup::process_name_for_peer(peer)`: peer(app 的 local 端) 非 loopback→None;
  否则 /proc/net/tcp{,6} 按 local_address hex 找 socket inode → 扫 /proc/*/fd 找持有 PID →
  /proc/PID/comm。v4/v6 loopback 都支持 (proc_hex_local 处理字节序)。
- router: Rule.process_name + RoutingRequest.process_name + matches_extra + uses_process_name()。
- handler proxy_tcp_target: **仅当 router.uses_process_name() 且 peer loopback** 才查 (零开销
  opt-in), /proc 扫描走 spawn_blocking 不占 tokio worker。
- 未来若要网关本机进程分流, 可另加 eBPF connect4 抓 comm (本次不做)。

## 验证

proc_lookup 单测: v4/v6 hex 格式 + 非 loopback None + **真实 /proc 自反查** (起真 TCP 连接查到
本测试进程名)。router 单测: 按进程名分流 / 信息缺失不命中 / uses_process_name 门控。config check
接受 process_name 规则。

关联 [[routing-rules]] (同一 matches_extra + 信息缺失不猜)、[[chain-proxy-roadmap]]。


## timeline

- time: 2026-07-27T11:18:40
  kind: decision
  summary: "Created this page: process_name 分流: 本机 loopback 经 /proc 反查进程名, 非 eBPF"
  source: feat/process-name-routing
  affects: [process-name-routing]

- time: 2026-07-27T11:18:40
  kind: decision
  summary: "process_name 路由维度(comm 精确匹配): 仅本机 loopback socks/mixed 入站经 /proc 反查; 透明/LAN 转发无本机进程不适用; 纯用户态非 eBPF; opt-in 门控避免每连接扫 /proc"
  source: brain update-truth
  affects: [process-name-routing]
