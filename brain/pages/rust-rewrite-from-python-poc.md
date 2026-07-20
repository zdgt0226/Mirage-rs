---
id: rust-rewrite-from-python-poc
title: "从 Python POC 全量重写为 Rust + Tokio"
category: decision
status: active
created: "2026-07-20T11:43:27"
updated: "2026-07-20T12:20:56"
---

## compiled_truth

**决定**(v0.2.x):从 Python + uvloop 的 POC 全量重写为 **Rust + Tokio** 全异步无锁流水线,
继承 POC 的 Shadow-TLS + Reality 隐藏特性思路,底层彻底重构。

**协议改名**:内部命名与 JSON 配置从 `pyreality` → `mirage`,用 `#[serde(alias)]` 保留旧字段兼容,
老用户配置不破。

**一次破坏性变更**:拥塞控制字段统一为 `brutal_rate_mbps`,并**移除**旧别名
(`brutal_rate_bytes_per_sec` / `brutal_rate_bps`)。理由:单位混淆会导致 **1000 倍以上**的灾难性溢出,
宁可让用户显式迁移也不静默接受错误单位。

**影响面**:`memory-bank/` 下的 `decisions.md`/`current-state.md`/`changelog.md` 是本次重写期(v0.2–v0.3)
的历史沉淀,内容**已显著过期**(仍写着 `v0.3.0-dev`,而当前为 `0.6.0-alpha.1`),阅读时以 brain 为准。


## timeline

- time: 2026-07-20T11:43:27
  kind: decision
  summary: "Created this page: 从 Python POC 全量重写为 Rust + Tokio"
  source: memory-bank/decisions.md
  affects: [rust-rewrite-from-python-poc]

- time: 2026-07-20T12:20:56
  kind: decision
  summary: "记录项目起源与命名迁移"
  source: memory-bank/decisions.md
  affects: [rust-rewrite-from-python-poc]
