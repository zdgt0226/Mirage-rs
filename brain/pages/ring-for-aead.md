---
id: ring-for-aead
title: "AEAD 选用 ring 的 ChaCha20-Poly1305"
category: decision
status: active
created: "2026-07-20T11:43:27"
updated: "2026-07-20T12:21:29"
---

## compiled_truth

**决定**:隧道载荷加密用 **`ring`** 的 ChaCha20-Poly1305(`LessSafeKey` + 显式 nonce 管理);
握手令牌另用 `poly1305` crate,密钥派生用 `hkdf`/`hmac`/`sha2`。

**理由**:`ring` 是经过审计的成熟实现,ChaCha20-Poly1305 在**无 AES-NI** 的设备(ARM 路由器 / 树莓派 /
低端 VPS)上显著快于 AES-GCM,而本项目的部署形态正好大量落在这类机器上。

**实现约定(改动时须知)**:
- 分帧伪装成 TLS 1.3 Application Data:`[0x17 0x03 0x03][2B len][密文]`,明文尾部追加 inner content type `0x17`;
- nonce 为单调计数器,收发方向用不同的派生密钥(`c2s` / `s2c` info);
- `send_data` 对大载荷按 **4K/8K/16K 随机分桶**切记录(模拟真实 HTTPS 碎片),UDP 侧另有机会式合帧;
- `CryptoWriter` 内嵌 64KB `BufWriter`,单次 `write_all` 送出 header+body(避免 `TCP_NODELAY` 下碎成小包)。


## timeline

- time: 2026-07-20T11:43:27
  kind: decision
  summary: "Created this page: AEAD 选用 ring 的 ChaCha20-Poly1305"
  source: "Cargo.toml, src/crypto/aead.rs"
  affects: [ring-for-aead]

- time: 2026-07-20T12:21:29
  kind: decision
  summary: "记录加密库选择"
  source: "Cargo.toml, src/crypto/aead.rs"
  affects: [ring-for-aead]
