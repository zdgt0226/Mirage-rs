---
id: config-export-fragment
title: "配置导出片段 (export) 与共享格式"
category: decision
status: active
tags: [cli, export, subscription, config, share]
created: "2026-07-28T01:20:41"
updated: "2026-07-28T02:00:04"
---

## compiled_truth

`mirage-rs export` = subscribe 的反向。交互挑本地配置的 mirage 节点 (全部/`1,3,5-7` 部分) 导出为**可分享 JSON 片段**, 供他人合并/订阅 (JSON 导入侧下一版做, 现只 export)。

**输出格式** (即之前设计的 subscription-with-config 格式落定):
```
{ "nodes":[mirage 出站], "outbounds":[组 + 被引用的 direct/block],
  "routing"?:{ "rules":[...], "default_outbound":"..." }, "geo_sources"?:[...], "geodata_dir"?:"..." }
```

**匹配规则** (部分选节点时, 用户定的语义, 见 AskUserQuestion 2026-07-28):
- 组: 组内**未选成员剔除**, 剔空则跳过; 嵌套组靠 fixpoint 收敛。
- 规则: `outbound` 指向未导出出站的**丢弃**; `default_outbound` 悬空则不带。
- 被组/规则引用的 `direct`/`block` 一并带上 (内建叶子, 不算"节点")。
- rules/geo 各由交互开关控制 (默认带)。

**实现**: 核心 `build_export(root, picked, include_rules, include_geo) -> Value` 纯函数 (bin/mirage.rs), 便于单测; 交互 `run_export` 提示走 **stderr**, JSON 走 stdout (便于 `> file`)。

关联 [[subscription-import]] [[node-region-geoip]] [[node-test-and-autogroup]]。


## timeline

- time: 2026-07-28T01:20:41
  kind: decision
  summary: "Created this page: 配置导出片段 (export) 与共享格式"
  source: created via brain create-page
  affects: [config-export-fragment]

- time: 2026-07-28T01:20:42
  kind: decision
  summary: "mirage-rs export 导出可分享 JSON 片段; 也是 subscription-with-config 的落定格式"
  source: brain update-truth
  affects: [config-export-fragment]

- time: 2026-07-28T02:00:04
  kind: decision
  summary: "闭环: subscribe 支持 JSON 片段+本地文件导入 (merge_fragment), 与 export 配对"
  affects: [src/bin/mirage.rs]
