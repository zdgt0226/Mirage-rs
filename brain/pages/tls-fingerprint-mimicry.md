---
id: tls-fingerprint-mimicry
title: "ClientHello 字节级仿真 + 多 profile 加权轮换"
category: decision
status: active
created: "2026-07-20T11:43:26"
updated: "2026-07-20T12:19:19"
---

## compiled_truth

**决定**:ClientHello **字节级**仿真真实客户端,并按权重轮换多个 profile 稀释单一出口指纹:
Chromium 150(~60%)、Firefox 152(~25%)、OkHttp/Android Conscrypt(~15%),由 `pick_profile()` 选择。

**为什么是字节级**:JA3/JA4 类 DPI 比对 cipher/扩展/曲线的**顺序与取值**,近似仿真会露馅。
各 profile 的差异是真实的(Firefox 无 cipher GREASE、扩展定序、`record_size_limit`;
OkHttp 有 GREASE 但无 MLKEM、padding 到 512),均取自**用户真机抓包**。

**验证方式**:`src/bin/dump_tls.rs` 是 JA4 对照 harness(`--ja4 <hexfile>` 可算抓包的 JA4),
`tests/test_tls_fingerprint.rs::ja4_locks_all_profiles` 锁死三个 profile 的 JA4 值防回归。

**已知缺口(真实,未修)**:
- **零 TLS 会话复用** —— 永远完整握手,真浏览器会 resumption。这是统计指纹,补它需把令牌从
  `legacy_session_id` 挪进 PSK identity + binder 结构仿真 = **破坏性协议变更**,两端须同时升级。
- **SNI/IP/ASN 不一致** —— 大站 SNI 打到小机房 VPS。已用 `tools/find_camouflage.py`(并入 `install.sh`)
  找同 ASN 域名缓解;注意 Reality 也有此 tell,非本项目独有。

**别做的事**:曾评估"加 15s keepalive"—— 实测长连接空闲已呈现理想的"阵发+长静默"人类特征,
加心跳 = **亲手制造**特征。


## timeline

- time: 2026-07-20T11:43:26
  kind: decision
  summary: "Created this page: ClientHello 字节级仿真 + 多 profile 加权轮换"
  source: "src/crypto/tls_raw.rs, git 83f6925/be4e8be/579e6b1"
  affects: [tls-fingerprint-mimicry]

- time: 2026-07-20T12:19:19
  kind: decision
  summary: "沉淀抗识别主线的策略与已知缺口"
  source: "src/crypto/tls_raw.rs, tests/test_tls_fingerprint.rs"
  affects: [tls-fingerprint-mimicry]
