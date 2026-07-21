---
id: geo-dat-parsing-robustness
title: "geosite/geoip .dat 解析健壮性 (字段序 + fixed32/64)"
category: decision
status: active
created: "2026-07-21T09:11:51"
updated: "2026-07-21T09:12:41"
---

## compiled_truth

v2ray/v2fly 的 `geosite.dat` / `geoip.dat` 是 protobuf 编码的外部数据, 手写解析器踩过两处 bug, 均已修并带回归测试:

1. **不能假设 protobuf 字段序** (a935567): 原代码只在 `code`(国家/类目码)已知时才解析 entry;
   若某 `.dat` 把 entries 排在 code **之前**, 整个类目的规则会被**静默丢弃**。改为先收集 entries、
   与 code 收齐后再判定, 与字段序无关。

2. **fixed32/64 要跳过而非 break** (ceba36e): wire-type 1(fixed64)/5(fixed32) 原落到 `else` 直接 break,
   遇到 schema 扩展或非标 `.dat` 会截断解析、丢掉其后内容。改为正确跳 8/4 字节继续。

两处都做过**变异验证**(注入旧逻辑 → 回归测试如实变红)。教训: 手写 protobuf 解析器
①不能假设字段序; ②必须处理所有 wire-type(未知的也要能跳过, 而非 break)。

被 [[routing-rules]] 引用: 只有规则里出现 geosite/geoip 时才会加载这些 `.dat` 并触发下载 updater。


## timeline

- time: 2026-07-21T09:11:51
  kind: decision
  summary: "Created this page: geosite/geoip .dat 解析健壮性 (字段序 + fixed32/64)"
  source: "src/router/geo.rs, commits a935567/ceba36e"
  affects: [geo-dat-parsing-robustness]

- time: 2026-07-21T09:12:41
  kind: decision
  summary: "沉淀 geo .dat 解析的两处已修 bug"
  source: commits a935567/ceba36e
  affects: [geo-dat-parsing-robustness]
