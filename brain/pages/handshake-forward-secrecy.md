---
id: handshake-forward-secrecy
title: "前向保密 PFS: 一次性 X25519 ECDH 搭 random 字段, opt-in 两端同开"
category: decision
status: active
tags: [security, forward-secrecy, handshake, x25519, pfs]
created: "2026-08-14T12:39:45"
updated: "2026-08-14T12:48:12"
---

## compiled_truth

## 决策

补外部审计 #2 (最大真安全缺口): 原会话密钥纯从口令派生, 口令泄露=历史+未来流量全可解。加
**opt-in 前向保密 (PFS)**, config `pfs: true` 两端同开。

## 机制 (零指纹变化)

- 两端各生成一次性 X25519 对 (`crypto::pfs`, ring 0.17 agreement)。
- **公钥直接当 fake-TLS 的 random 字段交换**: ClientHello.random = 客户端临时公钥,
  ServerHello.random = 服务端临时公钥。任意 32B 都是合法 X25519 公钥且看起来均匀随机, 而这俩
  字段本就每连接随机、明文交换 → **无需额外解析、无需 key_share 手术、指纹与非 PFS 无异**。
- 偏移对齐: 客户端公钥写进 ClientHello.random, 服务端从 ClientHello body[6..38] 读 (= client_random,
  本就是 HKDF salt)。服务端公钥经 `get_server_hello_pfs` 覆写模板 flight[11..43] (所有返回路径:
  patch + fallback 都覆盖), 客户端 `read_server_handshake` 从记录 body[6..38] 读 (11-5=6, 帧头 5B)。
- 两端算 `ecdh = X25519(自私钥, 对端公钥)` 相等; 混进 master: `derive_master_pfs` IKM = password‖ecdh,
  salt = client_random, **新 HKDF label `pyrealiy-session-pfs`** (与非 PFS 域分隔)。私钥用完即弃。
- 认证仍靠口令 token, 与加密解耦 (对标 REALITY: 认证/加密分离)。

## 门控 = config `pfs` opt-in, 两端同开

- 默认关; pfs=false 时逐字等价旧版 (向后兼容), 不动现有部署。
- 改了会话密钥派生 → **两端必须同开**, 失配 fail-closed (AEAD 解密失败, 不静默出乱数据)。不做
  自协商 (服→客无干净 ack 信道, 且 random 字段须保持随机样)。同 cipher_agility 的"同版耦合"哲学。
- config `pfs` 加到: mirage 出站 / mirage_server 入站 / lite 两端。install.sh 一键开关留后续小 PR。

## 未做 / 边界

- 无临时密钥认证签名: MITM 拿不到口令就伪造不了合法 token (认证挡在 ecdh 前), 故不需额外签名。
- 小阶点: 一次性密钥 + KDF, ring 处理, 威胁模型下不可利用。

关联: [[external-audit-2026-08]] [[tls-fingerprint-mimicry]] [[handshake-template-completeness]]


## timeline

- time: 2026-08-14T12:39:45
  kind: decision
  summary: "Created this page: 前向保密 PFS: 一次性 X25519 ECDH 搭 random 字段, opt-in 两端同开"
  source: commit feat/pfs-x25519-ecdh
  affects: [handshake-forward-secrecy]

- time: 2026-08-14T12:40:11
  kind: decision
  summary: "PFS=一次性X25519 ECDH, 公钥搭ClientHello/ServerHello.random交换, ecdh混进master; opt-in两端同开"
  source: brain update-truth
  affects: [handshake-forward-secrecy]

- time: 2026-08-14T12:48:12
  kind: evidence
  summary: "抗指纹补丁: X25519 u坐标最高位恒0 (正常TLS random随机), 发出前随机化公钥最高位, 收端RFC7748 mask不影响ECDH。Sonnet复核误判该字段均匀, 实测偏差已修"
  source: commit feat/pfs-x25519-ecdh
  affects: [handshake-forward-secrecy]
