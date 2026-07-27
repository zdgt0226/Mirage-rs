---
id: subscription-import
title: "订阅链接: mirage-rs subscribe 批量导入 (格式=mirage:// 列表/base64)"
category: decision
status: active
tags: [cli, subscription, import, node-uri]
created: "2026-07-27T14:50:08"
updated: "2026-07-27T14:51:09"
---

## compiled_truth

## 决定

`mirage-rs subscribe <url>` 从订阅 URL 批量导入 mirage 节点为出站。

## 格式决策 (这项的前置)

订阅 URL 返回**每行一个 `mirage://` URI**; 整段是 base64 (无空白 + base64 字符集) 则先解码
(兼容经典订阅格式)。跳过空行 / `#` 注释。选这个格式因为**本项目已定义 mirage:// URI**
(node_uri 模块), 订阅就是它的列表 —— 最自然、复用最大, 不引第三方订阅格式 (clash yaml /
sing-box) 的解析负担。

## 实现 (大量复用)

- parse_subscription: base64 整体解码回落明文 + 逐行 filter mirage://。
- run_subscribe: reqwest 拉取 (timeout) → 解析 → 批量加出站 (按 server:port 去重, unique_auto_tag
  自动命名) → 可选 apply_urltest_group → atomic_write_config。
- 重构抽公共助手 mirage_outbound_json / atomic_write_config, import 也改用。
- 复用 [[node-test-and-autogroup]] 的 GroupOpts / apply_urltest_group / existing_outbound_tags。

## 范围与待做

v1 一次性拉取。**周期自动刷新未做** (手动重跑; --group 重跑会对全部节点重建组)。0 新增 + --group
仍会对已有节点建组 (重订阅刷新组的常见用法)。单测 parse_subscription (明文/base64/过滤) +
unique_auto_tag; e2e 对本地订阅 URL 验证 (去重/base64/建组/check)。

关联 [[node-test-and-autogroup]] (import/group 复用)。


## timeline

- time: 2026-07-27T14:50:08
  kind: decision
  summary: "Created this page: 订阅链接: mirage-rs subscribe 批量导入 (格式=mirage:// 列表/base64)"
  source: feat/subscription
  affects: [subscription-import]

- time: 2026-07-27T14:50:08
  kind: decision
  summary: "mirage-rs subscribe <url>: 拉订阅批量导入 mirage 出站; 格式=每行 mirage:// 或整段 base64 (本项目已有 mirage:// URI 故最自然); server:port 去重, 自动 tag, 可选 --group; 复用 node_uri+import+urltest; 周期刷新待做"
  source: brain update-truth
  affects: [subscription-import]

- time: 2026-07-27T14:51:09
  kind: decision
  summary: "mirage-rs subscribe <url>: 拉订阅批量导入 mirage 出站; 格式=每行 mirage:// 或整段 base64 (本项目已有 mirage:// URI 故最自然); server:port 去重, 自动 tag, 可选 --group; 复用 node_uri+import+urltest; 周期刷新待做"
  source: brain update-truth
  affects: [subscription-import]
