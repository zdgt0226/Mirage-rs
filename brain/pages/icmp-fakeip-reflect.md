---
id: icmp-fakeip-reflect
title: "fake-IP ICMP echo 本地反射"
category: decision
status: active
tags: [icmp, tc-divert, fake-ip, ebpf]
created: "2026-08-17T13:26:22"
updated: "2026-08-17T20:45:31"
---

## compiled_truth

路线图 #6 ICMP 处理第一步。用户选"先本地后隧道"。

## 问题
LAN 客户端 `ping <代理域名>`: DNS 回 fake-IP (默认 198.18.0.0/16), 无真实主机, echo request
经 tc_divert ingress 漏给内核转发 → 无路由丢弃 → ping 超时。用户误判"不通"。

## 方案 (本步)
tc_divert.c 加 ICMP 分支: **仅 fake-IP 段** 的 Echo Request(type8,code0) 就地反射成 Echo Reply:
- 交换 MAC (h_dest↔h_source)
- 交换 IP src↔dst (IP 校验和是各 16bit 字反码和, 换位不改总和 → 保持有效)
- type 8→0; ICMP 校验和 += 0x0800 带环绕进位 (type/code 字 0x0800→0x0000, 反码和减 0x0800,
  校验和=~和 故加; 已用 Rust 独立复算比对 truth 确认相等)
- TTL 不动 (客户端直连一跳, 保 IP 校验和有效)
- bpf_redirect(skb->ifindex, 0) 回同网卡 egress 弹给 client

配置: DivertCfg 加 fakeip_net/fakeip_mask (网络序), lib.rs 从 fake_ip_mapper 灌; fake-IP 未启用
则 mask=0, 反射整体关闭。**只反射 fake-IP 段** (非全体非直连), 避免对真实 IP 谎报 RTT。

## 边界 / 已知
- RTT 是本机假值 (~0ms), 仅解决"看起来不通"。端到端真 RTT 需 ICMP 隧道 (roadmap 后续独立项)。
- **本机自身 ping fake-IP 不覆盖**: tc_divert 挂 LAN 网卡 ingress, 只抓转发流量; 本机 raw-socket
  ping 走本地出向, 不经此 hook。要覆盖需 egress hook 或 cgroup, 后续再说。
- 仅 --features ebpf 网关模式生效。
- **待真机验证**: redirect/netns 路径本地难复现; 校验和已复算, 但 bpf_redirect 回弹 + tc ingress
  语义需真机确认 (brain roadmap 早标"失败形态待真机确认")。

对齐 Clash/sing-box fake-ip ping 体验。真隧道 ICMP 见 [[roadmap]]。


## timeline

- time: 2026-08-17T13:26:22
  kind: decision
  summary: "Created this page: fake-IP ICMP echo 本地反射"
  source: "commit pending (feat/icmp-reflect)"
  affects: [icmp-fakeip-reflect]

- time: 2026-08-17T13:26:45
  kind: decision
  summary: "先本地反射: tc_divert 对 fake-IP echo 就地回 reply, ping 代理域名可通; 真隧道 RTT 后续"
  source: brain update-truth
  affects: [icmp-fakeip-reflect]

- time: 2026-08-17T20:45:31
  kind: decision
  summary: "真隧道 ICMP (第二步) 暂不做: 捕获路径三条 (AF_PACKET/TUN/无) 均待真机且边际价值低, 保留第一步本地反射"
  source: "对话 2026-08-17"
  affects: [roadmap]
