---
id: cipher-agility
title: "Cipher agility: 协商 AES-256-GCM (config 门控, 指纹零触碰)"
category: decision
status: active
tags: [crypto, aead, performance, negotiation, aes]
created: "2026-07-29T23:57:58"
updated: "2026-07-29T23:57:58"
---

## compiled_truth

**决定** (v0.7.0 首选性能项, 见 [[perf-roadmap-v070]]): 隧道 AEAD 从硬编码 ChaCha20-Poly1305 改可协商 —— 两端都有硬件 AES 加速时切 **AES-256-GCM** (实测 2.1x), 否则 ChaCha20 (无加速方 AES 更慢, 见 [[ring-for-aead]])。

## 关键设计约束 (踩过的坑)
握手首消息是 server→client TIME_SYNC, **老客户端严格只认 proto_ver==0x01**; 客户端先发协商哨兵会被**老服务端**当 target_len 掐连接; 唯一加密前客户端消息 ClientHello 是**指纹伪装**核心。三方都不能贸然先动。GREASE 信号方案被否 (profile 不同槽位/认证路径要解析 ClientHello/误报破老客户端/指纹相关性)。

## 落定方案: config 门控 + 加密信道内协商
- **服务端 `tuning.cipher_agility: bool` (默认 false)**。开关就是"混版安全闸": 开=声明所有客户端都已升 v0.7.0+。
- 开了 → 服务端 TIME_SYNC 发 `proto_ver=0x02`; 客户端见 0x02 → 加密 ChaCha20 信道内发 `CIPHER_NEGO([0xFF,0xFF,client_aes])`, 服务端回 `CIPHER_ACK([0x03,final])`, 两端 `rekey` 到 final。`negotiate = 两端都 AES ? AES : ChaCha`。
- **ClientHello 一字不改 → TLS 指纹零触碰** (14 指纹测试仍绿)。全局开关经 `set_server_cipher_agility` 设 (lib.rs 启动读 config), 避免穿 3 层签名。

## rekey 安全
`expand_key(master, info, cipher)` 把 cipher 折进 HKDF info 做**域分隔** → AES key ≠ ChaCha key; rekey = 重派生 + **nonce 归零** (新 (key,algo) 组合归零安全)。ChaCha20 后缀为空 → bootstrap 密钥**字节兼容老协议** (新客户端 bootstrap 与老服务端算同一 key)。

## 向后兼容矩阵
- agility=false (默认): 行为不变, 全兼容。
- 老客户端 (发真 target 非 NEGO) ↔ 新服务端(开): 服务端首帧非哨兵 → 不协商, ChaCha20。
- 新客户端 ↔ 老服务端 (proto_ver=0x01): 不协商, ChaCha20。
- ⚠️ 残留: 新服务端(开) → 老客户端收 0x02 丢时间同步 (故只在客户端全升级后开)。

## AES-NI 检测
x86 `aes && pclmulqdq` / aarch64 `aes`, 其它架构 ChaCha20。保守。

## 证据 (old-coder Tier 3)
crypto 单测 (wire/检测/域分隔/rekey nonce 归零/跨cipher fail-closed/兼容key字节一致) + 协商纯函数单测 + 集成测试场景 7-10 + 手工变异 (去nonce归零/域分隔失效/negotiate AND→OR 均被杀)。ClientHello 未改。


## timeline

- time: 2026-07-29T23:57:58
  kind: decision
  summary: "Created this page: Cipher agility: 协商 AES-256-GCM (config 门控, 指纹零触碰)"
  source: created via brain create-page
  affects: [cipher-agility]

- time: 2026-07-29T23:57:58
  kind: decision
  summary: "隧道AEAD可协商: 两端AES-NI→AES-256-GCM(2x); config门控+加密信道内协商+rekey, ClientHello不动(指纹零触碰)"
  source: brain update-truth
  affects: [cipher-agility]
