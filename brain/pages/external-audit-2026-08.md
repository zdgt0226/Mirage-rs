---
id: external-audit-2026-08
title: "外部审计评估 (2026-08): PFS 是最大真缺口, clippy 已做, 便宜纯赚三件先做"
category: decision
status: active
tags: [security, audit, forward-secrecy, supply-chain, api]
created: "2026-08-13T09:15:07"
updated: "2026-08-13T09:15:39"
---

## compiled_truth

外部审计报告(2026-08)逐条核实与处置。总评: 质量高(具体、有代码指向、多数属实)。

## 已核实为真 (该修)
- **#2 无前向保密 (最要命)**: `crypto/aead.rs::derive_master(password, salt)` —— 会话密钥纯从口令派生, **无 ECDH/DH**。`tls_raw.rs` 里的 x25519 是**假 ClientHello 的随机字节**(伪装用, 非真密钥协商)。后果: 口令泄露 = 过去+未来全部流量可解, 无密钥轮换。REALITY/Hysteria2 基线都有 PFS。真协议缺口, 但 Tier-3 改两端。
- **#3 API 无限流/失败锁定**: grep src/api 无 rate-limit; token 已 subtle 常量时间比较挡时序, 但字典暴力面在。便宜可修。
- **#1 crypto 未专业审计**: 确为 LLM(Sonnet/Gemini)复核, 非安全公司。README 该加"未经专业审计"声明。
- #11 无 cargo-audit/cargo-deny (供应链门禁缺); #12 无 fuzz(解析密集却零 fuzz); #13 install.sh 只 sha256 无 GPG/cosign 签名、无容器镜像; #5 RTT 任务 async 里跑 std Mutex/RwLock/syscall 阻塞 worker; #4/#7 start_proxy 750+ 行巨石/config 模板三处漂移(踩过 direct 出站坑); #8 有 proto_ver=0x02 信号但无不兼容显式诊断(三件套 cipher_agility/tls_padding/udp_mux 同版耦合静默降级)。

## 已过时 (驳)
- **#6 clippy "24 未清零 + CI ~66"**: 已过时。PR #27 已 clippy 清零 + CI 翻 `-D warnings` 硬拦。审计基于旧快照。

## 框架不同意
- #16 "过程成为产品": CHANGELOG 可自动化认同; 但 BRAIN/多模型复核是用户选定工作法, 本会话多模型确实抓出真 bug(mux 4 条/审计 4 修), 是取舍非负担。
- #17 定位/合规: 加"负责任使用声明"合理护项目; 但"弱化抗审查表述"是产品定位选择非缺陷。

## 处置优先级 (与审计短期表略不同)
1. 便宜纯赚: #3 API 限流 + #11 cargo-audit/deny 进 CI + #1 README 未审计声明 (1-2 天)。**← 本次执行**
2. #5 阻塞改 spawn_blocking (中, 正确性)。
3. **#2 X25519 ECDH 前向保密** (Tier-3, 最大真缺口, 对标 REALITY: x25519 + 认证/加密分离, 慎设 SPEC)。
4. #12 fuzz 三目标 (config/DNS/帧)。
5. 缓: #4/#7 拆巨石(质量无行为收益) · #13 签名 · #14 bench 门禁 · #8 版本诊断 · #10 orphan CI 接回。

**How to apply**: PFS(#2)做时对标 [[tls-fingerprint-mimicry]] 不破指纹 + 两端版本门控如 cipher_agility 模式。


## timeline

- time: 2026-08-13T09:15:07
  kind: decision
  summary: "Created this page: 外部审计评估 (2026-08): PFS 是最大真缺口, clippy 已做, 便宜纯赚三件先做"
  source: "用户 2026-08 转来的外部审计报告 + 逐条核实"
  affects: [external-audit-2026-08]

- time: 2026-08-13T09:15:39
  kind: decision
  summary: Rewrote compiled_truth to the new best understanding
  source: "逐条核实 2026-08"
  affects: [external-audit-2026-08]
