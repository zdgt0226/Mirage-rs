---
id: perf-roadmap-v070
title: "性能 roadmap (v0.7.0): 加密吞吐/relay合帧/io_uring/MSS"
category: decision
status: draft
tags: [roadmap, performance]
created: "2026-07-27T08:58:17"
updated: "2026-07-27T09:00:38"
---

## compiled_truth

## 背景

用户看重性能。厘清: **统一出站流接口重构不是性能项** (架构, 最好持平, 做砸=回归)。真性能杠杆
另立, 定 v0.7.0 开始。

## 候选 (需先 profile 定位瓶颈)

1. **加密吞吐**: AEAD 热路径 (ring) 是隧道大流量主耗, 看批处理 / 硬件 AES-NI 对齐。
2. **隧道 relay 缓冲/合帧再调**: 当前 CryptoWriter BufWriter 64KB + 服务端 try_read 贪婪收割。
3. **io_uring 替代 relay read/write 循环**: 大工程, 高并发小包收益明显。
4. **MSS clamp / 网络层**: landscape 参考 P1。

## 已到顶别碰

Direct 已 splice(2) 零拷贝; Mirage relay 已调优 (合帧 + brutal CC + try_read 贪婪)。

## 决定

v0.7.0 起挑, 先 profile。关联 [[unified-outbound-stream]] (架构地基, 性能持平)。


## timeline

- time: 2026-07-27T08:58:17
  kind: decision
  summary: "Created this page: 性能 roadmap (v0.7.0): 加密吞吐/relay合帧/io_uring/MSS"
  source: "用户 2026-07-27 定 v0.7.0"
  affects: [perf-roadmap-v070]

- time: 2026-07-27T08:58:17
  kind: decision
  summary: "v0.7.0 起做性能 4 候选(加密吞吐/relay合帧/io_uring/MSS), 先 profile; 统一出站接口重构本身不提速(持平)"
  source: brain update-truth
  affects: [perf-roadmap-v070]

- time: 2026-07-27T09:00:38
  kind: decision
  summary: "v0.7.0 起做性能 4 候选(加密吞吐/relay合帧/io_uring/MSS), 先 profile; 统一出站接口重构本身不提速(持平)"
  source: brain update-truth
  affects: [perf-roadmap-v070]
