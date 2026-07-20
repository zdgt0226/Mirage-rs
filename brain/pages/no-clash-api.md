---
id: no-clash-api
title: "不做 Clash API 兼容"
category: decision
status: active
created: "2026-07-20T11:43:27"
updated: "2026-07-20T12:21:29"
---

## compiled_truth

**决定**:**不做 Clash API 兼容**,走自有 API 路径。`src/api/mod.rs:14` 有明确的设计原则注释。

**理由**:Clash API 是为其特定的 provider/proxy-group 模型设计的,兼容它会把本项目的
配置模型(JSON + 热重载 + 自有 outbound/router 语义)往那个形状上拧。内置 Neon Dashboard
直接消费自有 REST,不需要中间兼容层。

**影响面**:第三方 Clash 生态的面板/客户端**不能**直接接管本项目。这是**已定案**,
不要再作为 TODO 反复提出。


## timeline

- time: 2026-07-20T11:43:27
  kind: decision
  summary: "Created this page: 不做 Clash API 兼容"
  source: "src/api/mod.rs:14"
  affects: [no-clash-api]

- time: 2026-07-20T12:21:29
  kind: decision
  summary: "记录明确的非目标"
  source: "src/api/mod.rs:14"
  affects: [no-clash-api]
