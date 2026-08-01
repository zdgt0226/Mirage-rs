---
id: roadmap-dependencies
title: "路线图依赖关系与开发序"
category: reference
status: active
tags: [roadmap, planning, dependencies]
created: "2026-07-29T11:45:40"
updated: "2026-08-02T01:25:22"
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

- time: 2026-08-01T23:32:46
  kind: decision
  summary: "外部审查'未来发展建议'7 条处置 + 平台决策 (2026-07-31)。#2 平台分层决策: Android/Windows 客户端将开独立项目重构 (不进本仓库), BSD 后续可能本仓库支持 → 本仓库现在不做 cfg-gating 分层 epic, CI '非 Linux 构建'门禁不适用; 核心模块 (SOCKS/Mixed/Mirage/WG) 保持合理可移植利于将来 BSD/独立项目复用。已做(commit 5b4cac1): #4 docs/threat-model.md 抗审查验收基准(T1抗主动探测/T2抗DNS污染/T3不泄真实IP/T4fail-closed/T5无时序侧信道); #1 clippy 进 CI(未 -D warnings); #3 check 报直连 DNS 上游解不出 IP。新 roadmap 项: clippy-cleanup(清 ~66 warning 后翻 cargo clippy -D warnings, 内含 1 条 MutexGuard-held-across-await 值得单独查是否真 bug)。待做高价值: #7 泄漏/场景集成测试(被代理域名永不走本地DNS/SS-UDP默认不裸奔/fake-IP丢失fail-closed/WG-DNS符合预期 → 对照 threat-model §7 施工, 抗审查最关键); #6 控制面产品化(/api/rules 加结构化校验+dry-run+reload结果回传, 原子写已有). 已在队列: #5 UDP mux(见 [[udp-capacity-findings]])."
  source: "外部审查 7 建议 + 用户平台决策 + docs/threat-model.md"
  affects: [roadmap-dependencies, docs/threat-model.md]

- time: 2026-08-02T01:25:22
  kind: decision
  summary: "landscape/dae + 抗GFW 建议筛选 (2026-08-02, 带立场)。方向合并: **#5 UDP mux 应落地为 QUIC Datagram** 而非在 TCP 上 mux —— QUIC 流独立无 HoL、Datagram 承载 UDP 无重传、被识别为正常 HTTP/3, 一举解跨流队头阻塞([[udp-capacity-findings]] 记的 mux HoL 约束) + 抗审查; 把 #5 与路线图 QUIC/H3 传输合并成一件事. 高价值待做: (A) TLS 握手后 Padding/包长序列混淆(Phase1) —— GFW 上 ML 认包长序列, 我们有字节级 ClientHello 仿真但无握手后 padding, 契合 camouflage+T1, 优先级高中等工程; (B) tproxy_outbound 编排 —— tproxy 重定向特定流到本机容器代理(Hysteria2/TUIC/VLESS), 契合'不做通用框架'定位(同 Tailscale 自己跑思路), 让 Mirage 当流量编排枢纽. 判**不做**: (1) DNS 驱动 XDP 零用户态直连(landscape #2) —— 与 brain [[splice-over-sockmap]] 决策冲突, splice 直连实测已很省 CPU(旁路由 620万包 TX dropped=0 未到瓶颈)1GbE 绰绰有余, XDP 双网卡 redirect+DNS→map+CO-RE 巨大复杂度只 10GbE+ 才值, niche payoff 不明; (2) 重放防御的 'TCP Reset 掐断'(Phase2) —— 真 TLS 站不那样 reset 是独特指纹违背 T1, 我们 camouflage-forward 更优(且 token 时间桶重放防御已有). 缓/依赖: NAT 类型控制(fullcone, 家庭网关游戏刚需但依赖 UDP 数据面成熟, 排 UDP 之后); 端口跳变 TOTP(抗单端口封锁但复杂+多端口本身或成信号, 靠后). 并入现有项: per-MAC 独立 DNS 缓存/上游防串味 → [[lan-host-monitor-device-rules]](source_mac 匹配已实现, 只差 DNS 隔离). 事实纠正: source_mac 路由匹配已有(router/mod.rs:65); token 重放防御已有(hello_auth 时间桶)."
  source: "landscape/dae + 抗GFW 7 建议逐条 + splice-over-sockmap/threat-model T1 决策 + 源码核实 source_mac/replay 已有"
  affects: [roadmap-dependencies, udp-capacity-findings, splice-over-sockmap, lan-host-monitor-device-rules]
