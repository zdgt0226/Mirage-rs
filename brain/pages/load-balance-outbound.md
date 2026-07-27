---
id: load-balance-outbound
title: "负载均衡出站组 load_balance (round-robin v1); consistent-hash 待目标感知解析"
category: decision
status: active
tags: [outbound, load-balance, routing, group]
created: "2026-07-27T19:41:28"
updated: "2026-07-27T19:42:01"
---

## compiled_truth

## 决定

加出站组类型 `load_balance` (alias `load-balance`): 把连接**分摊**到多个健康成员。现有
urltest/fallback/selector 都是"选一个", 这是第一个"分摊"型。

## v1 = round-robin

resolve_leaf 里对 LoadBalance: 过滤健康成员 → 原子游标 fetch_add 取模轮流。**无需目标**,
所以不动 resolve_leaf 的无参签名, 改动最小。无健康成员则退回首个 child (不 self.clone 死路)。
健康检查复用 urltest 的 start_health_checker (url + interval)。

## 为什么不先做 consistent-hash

按目标域名哈希 (会话粘滞) 需要把**目标**传进 leaf 解析, 而 resolve_leaf() 现在无参 ——
要么改签名传目标, 要么 handler 侧感知。改动大, 推迟。round-robin 的代价 (同会话多连接可能
分到不同节点 → 查 IP 一致性的站点受影响) 已在 README/CHANGELOG 标注。

## 安全/健壮

- 未支持的 strategy (非 round-robin) 在 semantic_issues (check/启动) **报错, 不静默降级**。
- 组成员存在性/空组/自引用由现有群组校验覆盖 (加了 LoadBalance 分支)。

## 实现点

config OutboundConfig::LoadBalance (strategy/url/interval, serde snake_case load_balance +
alias); OutboundNode::LoadBalance { tag, children, next: AtomicU64 }; 全部 match 臂加
LoadBalance。单测 4 个。是"群组进订阅"的前置一环。关联 [[node-test-and-autogroup]]。


## timeline

- time: 2026-07-27T19:41:28
  kind: decision
  summary: "Created this page: 负载均衡出站组 load_balance (round-robin v1); consistent-hash 待目标感知解析"
  source: feat/load-balance
  affects: [load-balance-outbound]

- time: 2026-07-27T19:41:28
  kind: decision
  summary: "load_balance 出站组把连接分摊到健康成员(vs urltest选最优); v1 round-robin(原子游标, resolve_leaf 无需目标); consistent-hash 需把目标塞进 leaf 解析故推迟; 未支持策略 check 报错不降级"
  source: brain update-truth
  affects: [load-balance-outbound]

- time: 2026-07-27T19:42:01
  kind: note
  summary: "群组进订阅的前置: 订阅带 outbounds 时天然能带 load_balance 组 (subscription-import 页在 PR#10 分支, 合并后互链)"
  source: feat/load-balance
  affects: [load-balance-outbound]

- time: 2026-07-27T19:42:01
  kind: decision
  summary: "load_balance 出站组把连接分摊到健康成员(vs urltest选最优); v1 round-robin(原子游标, resolve_leaf 无需目标); consistent-hash 需目标感知解析故推迟; 未支持策略 check 报错不降级"
  source: brain update-truth
  affects: [load-balance-outbound]
