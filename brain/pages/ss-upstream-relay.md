---
id: ss-upstream-relay
title: "SS 上游中转: 仅 TCP, UDP 默认阻断, 为何不先实现 SS UDP"
category: decision
status: active
created: "2026-07-21T09:27:41"
updated: "2026-07-21T09:29:04"
---

## compiled_truth

Mirage 服务端可配 `upstream` 把流量再经 Shadowsocks 发往上游, 即作中转站:
`客户端 ─Mirage隧道→ Mirage服务端 ─SS→ SS服务器 → 目标`。典型用途: Mirage 服务端放在离用户近、
线路好的位置只做中转, 真正出口落在另一台 SS 服务器上(如落地解锁机)。

**支持**: SIP004(aes-128/256-gcm, chacha20-ietf-poly1305)+ SIP022(2022-blake3-aes-128/256-gcm,
2022-blake3-chacha20-poly1305)。**仅 TCP**。加解密层与 `shadowsocks-crypto` 对照验证一致;
但**帧结构未对真实 SS 服务器验过**(定长/变长头出自规范解读)。见 [[external-audit-verification]] 的验证方法论。

**关键取舍 —— UDP 默认 block, 不先实现 SS UDP**:
- 配了上游而放行 UDP, 会让 UDP 从**本机 IP** 直连出去而 TCP 从上游出去, **出口 IP 不一致**。
  对落地解锁这是**功能性错误**(QUIC 走直连会被判错区域, 且不像被封那样回落 TCP → 解锁时灵时不灵)。
  安全的失败方式是"不发", 不是"发到别处去" → `upstream.udp` 默认 `block`(可显式设 `direct` 保留旧行为)。
- 为何不直接实现 SS UDP: ①多数 SS 服务器**默认不开 UDP**; ②SS UDP **无握手**, 上游不支持时表现为
  "包石沉大海", 无法探测、只能等用户报障 —— **实现了不等于能用**。故列为需求驱动项。

**易踩的坑(已加校验拦截)**:
- SIP022 的 `password` 不是任意密码, 而是 **base64 编码的密钥本身**(长度固定)。写错**不会**让服务端
  起不来, 而是**每条连接静默失败**(服务看着健康却代理不了) —— 比起不来更难查。`check` 与启动路径
  两处都校验(config.rs::semantic_issues + build_ss_upstream), 启动侧直接拒绝启动。
- 加密方式写错直接拒启, 不静默降级直连(配了中转却走直连 = 出口 IP 与预期不符, 必须立刻知道)。


## timeline

- time: 2026-07-21T09:27:41
  kind: decision
  summary: "Created this page: SS 上游中转: 仅 TCP, UDP 默认阻断, 为何不先实现 SS UDP"
  source: "src/proxy/shadowsocks.rs, config UdpPolicy"
  affects: [ss-upstream-relay]

- time: 2026-07-21T09:29:04
  kind: decision
  summary: "沉淀 SS 中转的边界与 UDP 取舍"
  source: src/proxy/shadowsocks.rs
  affects: [ss-upstream-relay]
