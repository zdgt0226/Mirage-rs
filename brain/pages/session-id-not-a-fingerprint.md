---
id: session-id-not-a-fingerprint
title: "session_id 不是指纹: 实测证明我们与真 Chrome 不可区分, TLS resumption 不做"
category: decision
status: active
tags: [tls, fingerprint, resumption, evidence]
created: "2026-07-23T16:23:02"
updated: "2026-07-23T16:24:08"
---

## compiled_truth

**结论**: `legacy_session_id` **不是**暴露 Mirage 的指纹。TLS resumption 仿真**不做** ——
它要解决的问题经实测证明不存在。更正了 [[tls-fingerprint-mimicry]] 里一条错误假设。

## 起因

roadmap 曾把"零 TLS 会话复用"列为真实统计指纹 (P2 候选), 计划做 resumption 仿真。开
`feat/tls-resumption` 分支后, 先量化真实基线, 结果推翻了立项前提。

## 三重证据 (工具: `dump_tls --session-ids` / `--session-cmp`)

1. **复用模式**: 真 Chrome 抓包 (多域名) → **0% 复用, 每次全新 32 字节**。TLS 1.3 里
   `legacy_session_id` 是兼容字段, Chrome 每次填全新随机值; 真 resumption 走
   `pre_shared_key` + ticket, 与 session_id 无关。
2. **长度分布**: 恒 32 字节, 与 Chrome 一致。
3. **字节熵 + 逐位置均值**: 我们的 token 生成器 vs 纯随机 → 熵 7.97/7.97, 三维度不可区分。
   **阳性对照**: 纯随机 vs 后16字节固定的样本 → 熵 4.95、位置偏差 51 (🔴), 证明工具真能
   抓破绽、不是永远报绿。

## 为什么本该如此 (理论)

我们的 token = `随机8 + 加密掩码时间戳8 + poly1305 tag16`, 三段皆加密输出, 对不知道密码的
观测者即均匀随机流 —— 与 Chrome 的 CSPRNG session_id **数学上必然不可区分**。实测只是把
"必然"变成"实测确认"。

## 严谨论证指纹差异的方法 (可复用)

**不要凭对协议的印象猜"这是指纹"** —— 本条和 [[fingerprint-hot-update]] 那次是同一个错误
(把未验证的假设当已知缺陷)。正确做法:
1. 先抓**真实基线** (真 Chrome 到同类目标)。
2. 多个**正交维度**比对, 不止一个 (复用/长度/熵/逐位置结构)。
3. 必带**阳性对照**: 喂一个已知有破绽的样本, 确认工具会报红 —— 否则"全绿"可能只是工具瞎。
4. 样本量下限 (熵检验 ≥20), 少了拒绝下结论。

## 附带发现: 真正的连接层差异 (记入 roadmap, 待论证)

session_id 是死路, 但抓包过程暴露了更可能的指纹, 都在**连接层**而非字节层:
- **连接复用**: 真 Chrome 一条 TLS 用很久 (keep-alive / H2 多路复用), 刷新不再握手; 我们
  每条被代理连接一次完整握手 → 单位时间握手数偏高。
- **QUIC/HTTP3 缺失**: Chrome 大量流量走 QUIC, 我们零 QUIC。一个 IP 短时间大量 TCP+TLS
  完整握手且完全无 QUIC, 宏观模式扎眼。
  ⚠️ **但方向相反的力**: QUIC 在国内受 QoS 影响且**分地区**, 做了 QUIC 可能反而被限速/更慢。
  故"缺 QUIC 是指纹"与"QUIC 在国内不一定能用"要一起权衡 —— 列为**待论证方向**, 非直接立项。


## timeline

- time: 2026-07-23T16:23:02
  kind: decision
  summary: "Created this page: session_id 不是指纹: 实测证明我们与真 Chrome 不可区分, TLS resumption 不做"
  source: "2026-07-23 抓包实测"
  affects: [session-id-not-a-fingerprint]

- time: 2026-07-23T16:24:08
  kind: decision
  summary: "实测三重证据推翻'零 session 复用是指纹', TLS resumption 不做; 记严谨论证方法"
  source: "2026-07-23 抓包实测"
  affects: [session-id-not-a-fingerprint]
