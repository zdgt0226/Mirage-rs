---
id: lan-host-monitor-device-rules
title: "LAN 每主机监控 + 设备专用规则 (计划池, 随 WebUI 优化做)"
category: decision
status: active
tags: [roadmap, lan, monitoring, ebpf, routing, webui]
created: "2026-07-29T11:24:20"
updated: "2026-07-29T11:24:20"
---

## compiled_truth

**计划池** (2026-07-29 定, 随 WebUI 优化再开发)。作网关后: ① 监控 LAN 各主机用量 ② 对特定设备下专用规则。

## A. 设备专用规则 (机制已有, 补 1 处)
- 路由引擎**已支持** `source_ip_cidr` + `source_mac` 条件 (见 [[routing-rules]])。写 `{"source_ip_cidr":["192.168.1.50/32"],"outbound":"kids"}` = 该设备专用规则。
- **UDP 透明已填** source_ip (transparent_udp.rs:489)。
- **缺口 (P1, 小)**: TCP 透明 handler.rs:175 `source_ip: None // Can extract from local if needed` —— 补 `source_ip = local.peer_addr().ip()` (TPROXY 下 peer = LAN 设备; transparent.rs:138 accept 也有 peer_addr) → 设备规则对 TCP 生效。~2 行 + 测试。
- source_mac: 用户态 TCP 看不到 L2 MAC (需 ARP 反查 src_ip→MAC 或 eBPF)。多数场景按 IP 分设备够 (DHCP 静态绑定), MAC 列可选后续。

## B. 每主机用量监控 (新建)
- **eBPF 按源 IP 计字节**: tc_divert 加 HASH map (key=设备 IPv4, val={up/down 字节, 包数, last_seen})。tc 看得到**所有**转发流量含 **splice 直连的零拷贝流量** —— 用户态计数只见隧道(AEAD)那半, 会漏 splice 直连, 故必须 eBPF (见 [[splice-over-sockmap]])。
- 上行 tc ingress 直接计 (LAN→网关); 下行按回程包 dst=设备 IP 归属 (ingress+egress 或按 dst)。
- 用户态周期读 map → 聚合 → API 端点 + Neon 面板 per-host 视图 (上下行速率/总量/连接数)。设备名: 可选 ip→别名配置 / DHCP-ARP hostname 反查。
- 可测性: eBPF 部分弱 (CI verifier 已知限制, 见 [[orphan-verifier-ci-blocked]]); Rust 读取/聚合/API 可测。

## 分期
P1 TCP 填 source_ip (设备规则 TCP 生效, 纯 Rust 可测) → P2 eBPF per-src 字节 map + 用户态读 + API → P3 面板 per-host 视图 + 设备别名。


## timeline

- time: 2026-07-29T11:24:20
  kind: decision
  summary: "Created this page: LAN 每主机监控 + 设备专用规则 (计划池, 随 WebUI 优化做)"
  source: created via brain create-page
  affects: [lan-host-monitor-device-rules]

- time: 2026-07-29T11:24:20
  kind: decision
  summary: "设备规则靠source_ip(TCP需补填, UDP已填); 每主机用量靠eBPF按源IP计字节(含splice直连); 随WebUI优化做"
  source: brain update-truth
  affects: [lan-host-monitor-device-rules]
