---
id: roadmap-dependencies
title: "路线图依赖关系与开发序"
category: reference
status: active
tags: [roadmap, planning, dependencies]
created: "2026-07-29T11:45:40"
updated: "2026-07-31T02:52:25"
---

## compiled_truth

计划池各项的依赖关系与建议开发序 (2026-07-29 整理)。源: README 路线图 + 各 roadmap 页。

## 依赖 (前置 → 被阻塞)
- **统一出站流接口(4)** [[unified-outbound-stream]] ──硬依赖──▶ **链式代理/WG·SS 双向入站(5)** [[chain-proxy-roadmap]]; ──软依赖──▶ rule-set 远程更新(3) (经代理拉取更干净)。
- **IPv6 全栈(1)** [[ipv6-full-stack-design]] ──软先行──▶ LAN 监控 eBPF(2·P2) [[lan-host-monitor-device-rules]] / 链式代理(5) 的 v6 / ICMP(6) 的 v6。可 v4-first 起步但迟早返工。
- rule-set 更新(3) ──自前置──▶ 先定"更新失败保留旧规则"安全模型。
- orphan CI 接回(7) [[orphan-verifier-ci-blocked]] ──自前置──▶ 先把验证器改单进程 (仿 tcp.sh)。

## 分类
- **地基 (解锁多项)**: 统一出站流接口(4) — 最清晰硬前置; IPv6(1) — 广义地基, 早做省返工。
- **被阻塞**: 链式代理(5) 等 (4)。
- **共享面 (一起做省事, 非硬依赖)**: IPv6·P2 (tc_divert v6) + LAN 监控·P2 (per-src 字节计数) + MSS clamp — **都改 tc_divert**, 批量做。LAN 监控·P3 (面板) 随 WebUI 优化捆绑。
- **独立 (随时/早收益)**: cipher agility(8) [[perf-roadmap-v070]] · LAN 监控·P1 (TCP 填 source_ip, ~2 行) · 订阅周期刷新 · relay 缓冲(9) · io_uring(10) · ICMP(6·v4)。
- **已做/待关闭**: MSS clamp — [[mss-clamp-merged-into-tc-divert]] 显示已并入 tc_divert, 路线图这条基本完成, 核对后勾掉。
- **已决定不做**: Tailscale 原生 / TLS resumption [[session-id-not-a-fingerprint]] / 追平 sing-box。

## 建议开发序
1. **cipher agility(8)** — 独立、v0.7.0 首选、2.1x 收益、易测。不阻塞任何东西, 先摘。
2. **统一出站流接口(4)** — 地基, 解锁链式代理 + 净化 geo/rule-set 拉取。做完再碰 (5)(3)。
3. **IPv6 全栈(1)** — 大 epic 早做; 之后 tc_divert 的 v6 改动**顺带**把 LAN 监控·P2 一起做 (共享面)。
4. 之后: 链式代理(5) / rule-set(3, 先安全模型) / LAN 监控完整 (随 WebUI) / io_uring(10)。
5. 插空: LAN 监控·P1 (2 行) / 订阅刷新 / ICMP / 关闭 MSS clamp。

**一句话**: 地基 = 统一出站流(4) + IPv6(1); cipher agility(8) 独立高收益可先做; tc_divert 三项 (IPv6·P2 / LAN 计数 / MSS) 批量做省重复。


## timeline

- time: 2026-07-29T11:45:40
  kind: decision
  summary: "Created this page: 路线图依赖关系与开发序"
  source: created via brain create-page
  affects: [roadmap-dependencies]

- time: 2026-07-29T11:45:40
  kind: decision
  summary: "计划池依赖图: 地基=统一出站流(4)+IPv6(1); cipher agility(8)独立先做; tc_divert三项批量; 建议开发序"
  source: brain update-truth
  affects: [roadmap-dependencies]

- time: 2026-07-30T00:57:43
  kind: decision
  summary: "IPv6(1)瘦身: 透明数据面v6 epic 否决, 降为'隧道传输走v6'小PR; 不再是挡LAN监控/链式代理的大地基。唯一地基剩统一出站流(4)"
  affects: [ipv6-full-stack-design]

- time: 2026-07-31T02:52:25
  kind: decision
  summary: "新立项: 隧道 UDP 流复用共享隧道 (带机量)。根因见 [[udp-capacity-findings]] —— 客户端一流一隧道, 并发 UDP 上限=pool_size(默认16)。中等工程, 独立项(不阻塞别的, 也不被阻塞), 优先级排在硬地基'统一出站流(4)'之后; QUIC 回落 TCP 故非致命, 可缓解(调大 pool_size)。direct UDP 网关实测健康不在范围。"
  source: "udp-capacity-findings 实测结论 + README 计划池新增条目"
  affects: [roadmap-dependencies, udp-capacity-findings, src/proxy/transparent_udp.rs]
