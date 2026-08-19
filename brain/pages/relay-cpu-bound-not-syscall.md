---
id: relay-cpu-bound-not-syscall
title: "relay 瓶颈是 crypto CPU 非 syscall (io_uring 不做的依据)"
category: reference
status: active
tags: [perf, relay, io-uring, benchmark]
created: "2026-08-19T22:33:39"
updated: "2026-08-19T22:33:58"
---

## compiled_truth

2026-08-19 loopback 吞吐 bench (release, nproc=4) 数据:

| 路径 | 单流 MB/s |
|---|---|
| 直连基线 (splice) | 1418 |
| 隧道单流 (ChaCha20) | 137 |
| 隧道并发 x2/x4/x8 | 193/218/216 |

## 结论
- 直连 1.4 GB/s 证明 syscall/IO 极便宜。隧道慢 10.4x 的差 = **AEAD crypto (CPU) + 分帧**, 非 syscall。
- 并发 137→218 MB/s 随核涨、4 核饱和 = 典型 **CPU-bound (crypto)** 签名, 非 IO-bound。

## 决定: io_uring 不做
io_uring 优化 syscall 开销, 而瓶颈是 crypto CPU → **优化错位, 基本零收益**。且 tokio-uring 是独立
runtime, 塞进全 tokio 代码库要整体迁移, 大工程高风险。roadmap 的「io_uring 替代 relay read/write
循环」据此**评估后不做**, 除非未来出现真机高吞吐 + 低 crypto 成本 (已上 AES-NI) 仍撞 syscall 墙的证据。

## 隧道缓冲灌大 (256KB) 也不做
同理: 非 syscall-bound, 灌大 read/BufWriter 不解 crypto 瓶颈, 反增 warm 池隧道空闲内存。本 session 已
把有据可依的上行贪婪收割不对称修了 (见 CHANGELOG perf(relay))。剩余灌大是投机。

## 唯一有效杠杆: 更快 crypto (已做)
cipher agility (两端 AES-NI 协商 AES-256-GCM ~2x) 已实现 (v0.7.0)。bench 是 lite 默认 ChaCha20;
开 agility 走 AES 单流再翻倍。且单流 1.1 Gbps 已超绝大多数真实跨境链路 —— 部署里网络是瓶颈非 relay。


## timeline

- time: 2026-08-19T22:33:39
  kind: decision
  summary: "Created this page: relay 瓶颈是 crypto CPU 非 syscall (io_uring 不做的依据)"
  source: loopback bench 2026-08-19
  affects: [relay-cpu-bound-not-syscall]

- time: 2026-08-19T22:33:58
  kind: decision
  summary: "loopback bench 证明 relay 瓶颈是 AEAD crypto CPU 非 read/write syscall; io_uring 优化错位零收益, 不做; 缓冲灌大同理"
  source: brain update-truth
  affects: [relay-cpu-bound-not-syscall]
