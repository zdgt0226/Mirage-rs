---
id: config-write-race
title: "config.json 并发写无锁 = 丢失更新竞态 (已知限制, 边际不修)"
category: decision
status: active
tags: [config, concurrency, known-limitation]
created: "2026-08-17T09:26:39"
updated: "2026-08-17T09:27:01"
---

## compiled_truth

## 已知限制

`config.json` 有多个写入方 —— CLI `import`/`subscribe`/`export` (经 `atomic_write_config`,
mirage.rs:350) + API `POST /api/rules`。全部"读快照→内存改→原子写回 (.tmp + rename)",**原子
(不写坏文件) 但无 flock/互斥、不串行化**。并发两个写入方 → 后写者覆盖先写者 = **丢失更新**
(无感知、不报错)。非数据损坏 (rename 原子性保证文件恒完整)。

## 为何不修 (判定边际)

- **低概率**: 需两个写入方同时改配置 —— 自建单人工具里, 一边跑交互式 `import`、一边用看板 API
  存规则, 极罕见。
- **干净修法有 UX 代价**: 丢失更新窗口是"读→用户交互数秒→写"。flock 要覆盖全窗口就得在**交互
  期间锁住 config** (阻塞 API 数秒), 体验差。退一步"API 写前重读合并"便宜但不完美。
- 代价 > 收益, 故**不修**, 记为已知限制。真出问题 (用户反馈丢配置) 再上"API 写前重读合并"。

## 来源

2026-08 多视角盲审报的唯一 🟡 (那份质量高: 承认无严重漏洞、分寸准)。同批其余为非问题/已文档化
(DNS source_ip None 已在 [[source-ip-routing]] 记为故意) / 设计取舍 (process::exit 跳析构)。

关联: [[config-structure-evolution]]


## timeline

- time: 2026-08-17T09:26:39
  kind: decision
  summary: "Created this page: config.json 并发写无锁 = 丢失更新竞态 (已知限制, 边际不修)"
  source: "多视角盲审 2026-08"
  affects: [config-write-race]

- time: 2026-08-17T09:27:01
  kind: decision
  summary: "config.json 多写入方 tmp+rename 原子但无 flock, 并发写丢失更新; 低概率+修法有UX代价, 判定边际不修"
  source: brain update-truth
  affects: [config-write-race]
