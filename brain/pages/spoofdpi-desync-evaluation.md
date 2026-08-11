---
id: spoofdpi-desync-evaluation
title: "SpoofDPI/DPI-desync 评估: 不替隧道, 可吸收成 direct-desync 可选路由档(T3 opt-in)"
category: decision
status: active
tags: [protocol, anti-censorship, dpi, desync, routing, spoofdpi]
created: "2026-08-11T23:15:17"
updated: "2026-08-11T23:16:21"
---

## compiled_truth

用户 2026-08-05 clone /opt/claude/spoofdpi (Go) 求分析能否用于 Mirage。

**SpoofDPI = DPI 绕过工具 (GoodbyeDPI/GreenTunnel/zapret 一系)。** 不建隧道不加密, 直连真站, 只对首包 ClientHello 做 desync 让 DPI 匹配不上 SNI。核心 internal/desync/tls.go:
1. **ClientHello 切片** (split): 首包打散, DPI 重组不出 SNI → 匹配不上黑名单。
2. **假包 + 低 TTL** (sendFakePackets + GetOptimalTTL): 发伪造 ClientHello, TTL 调到刚越过 GFW 盒子但到不了真站 (中途 TTL 耗尽) → GFW 状态机看假包、真站看真包, 脱同步 (desync)。lazy segment 用 TTL=1 首跳即死。
3. TTL 学习 (sniffer 数跳数, LRU 缓存) + 自带 DoH 解析 (internal/dns/https.go)。

## 与 Mirage 根本区别
SpoofDPI: 直连真站+首包骗 DPI, 无需 VPS, **暴露真实 IP**, 只破 **SNI-based DPI 封锁**, 猫鼠游戏 GFW 会 patch。
Mirage: 全加密隧道到自己 VPS, 藏内容+真实目标+出口 IP, 破 SNI+IP封+DNS污染+内容审查+抗主动探测, 隧道稳。
两条路, 只在"GFW 按 SNI 封"窄点重叠。

## 三角度判断
1. **隧道内 fake-ClientHello 加 desync → 不值。** Mirage 已字节级 CH 仿真+认证失败转发真站; 再切片破坏 on-wire 仿真模式, 边际负收益。
2. **替代隧道 → 不行。** 弱保证(暴露真IP/只破SNI/猫鼠), 违背定位。
3. **作 direct-desync 第三路由档 → 有价值。** 某些海外站只被 SNI 封、IP 可达(不在 IP 黑名单): 现在要么走隧道耗 VPS 带宽+延迟, 要么不通。加 direct-desync 档=直连+首包切片+假包TTL, 原地捅穿 SNI 封不占 VPS。契合 eBPF 透明网关(每连接首包操作, 用户态 relay 拦首个 record; raw socket TTL 网关已有 CAP_NET_ADMIN)。类 dae "pierce" / zapret tier。

## 关键权衡 (记牢)
- **暴露真实 IP = T3 泄漏**: desync-direct 真 IP 访问真站。**只对非敏感海外站, per-rule 显式 opt-in, 绝不默认**; 敏感目标仍走隧道。见 docs/threat-model.md T3。
- **best-effort**: GFW 会 patch, 当"廉价先试, 不行回落隧道"档, 非替代。
- **平台绑定**: TTL/假包/raw socket Linux 特定 (SpoofDPI 也分 handle_linux.go)。

## 结论
1. 不替换、不进隧道内。
2. 可吸收成可选路由 action `direct-desync`(直连省 VPS 捅 SNI 封), per-rule opt-in, T3 权衡显式化, 当隧道廉价补充。
3. 借鉴具体: split + 最优 TTL 假包 + 跳数学习 + DoH。
4. 工作量: 中(新 outbound/action + relay 首包 desync + TTL raw-socket 管道)。

**How to apply**: 若做, 加为 outbound 类型或 direct 的 per-rule flag, 首包 desync 在 handler/relay 首个 write 前插; 默认关, check 阶段警示 T3 真IP暴露; 与 [[routing-rules]] 的 direct/proxy/block 并列成第四档。痛点驱动: 只在"隧道 SNI-only 站耗 VPS 带宽"成真痛点时做。


## timeline

- time: 2026-08-11T23:15:17
  kind: decision
  summary: "Created this page: SpoofDPI/DPI-desync 评估: 不替隧道, 可吸收成 direct-desync 可选路由档(T3 opt-in)"
  source: "用户 2026-08-05 clone /opt/claude/spoofdpi 求分析"
  affects: [spoofdpi-desync-evaluation]

- time: 2026-08-11T23:16:21
  kind: decision
  summary: "SpoofDPI(GoodbyeDPI 系 DPI-desync)不替 Mirage 隧道(弱保证/暴露真IP/只破SNI); 可吸收成可选 direct-desync 路由档(直连省VPS捅SNI封, per-rule opt-in, T3权衡显式), 借鉴 split+最优TTL假包+跳数学习+DoH"
  source: "2026-08-05 读 /opt/claude/spoofdpi internal/desync"
  affects: [spoofdpi-desync-evaluation]
