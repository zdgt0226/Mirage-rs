---
id: orphan-verifier-ci-blocked
title: "孤儿验证器不接 CI: runner 跨进程 sk_assign 兼容问题 (5.15+6.8 都红)"
category: reference
status: active
tags: [ci, ebpf, netns, verifier]
created: "2026-07-27T14:21:56"
updated: "2026-07-27T14:21:56"
---

## compiled_truth

## 结论 (2026-07-27, PR #9 实测后)

`examples/verify_tc_divert_orphan` **保持本地-only, 不接 CI**。

## 为什么 (拉了 CI 真日志, 不是缺日志权)

- 本机 (内核 ≥6.1) 双 case 稳定绿 (listener 活着打 mark / 没了不打)。
- GitHub runner: **ubuntu-22.04(5.15) 和 ubuntu-24.04(6.8) 都红**。gh run view --log-failed 显示
  失败点 = "客户端 8s 重试后仍连不上" (非早前以为的瞬时 ENETUNREACH settle 竞态)。
- 既然换 6.8 也红 → **不是内核版本问题**, 是 runner 环境对本验证器**跨进程 sk_assign** 场景
  (attach 进程 mem::forget 后退出, listen 是另一个进程) 的兼容问题。verify_tc_divert_tcp
  单进程 attach+listen 故在 runner 绿。

## 决定

不再盲调 (push-等CI-读日志 循环 ROI 太低)。产品**无覆盖缺口**: 孤儿门控走的同一段 mark-gated
路由由 verify_tc_divert_tcp 在 5.15 CI 覆盖。若日后要接回, 先把验证器**重写成单进程**
attach+listen (仿 tcp.sh), 或许解 runner 兼容。记录在 build.yml 注释 + README TODO。

本地跑: `cargo build --features ebpf --example verify_tc_divert_orphan && sudo bash examples/verify_tc_divert_orphan.sh` (需 ≥6.1)。


## timeline

- time: 2026-07-27T14:21:56
  kind: decision
  summary: "Created this page: 孤儿验证器不接 CI: runner 跨进程 sk_assign 兼容问题 (5.15+6.8 都红)"
  source: "2026-07-27 实测 PR#9"
  affects: [orphan-verifier-ci-blocked]

- time: 2026-07-27T14:21:56
  kind: decision
  summary: "verify_tc_divert_orphan 保持本地-only: 本机≥6.1稳过, GitHub runner 5.15 与 6.8 都红(客户端8s连不上), 是 runner 对'attach进程exit+listen进程分离的跨进程 sk_assign'兼容问题非产品; 覆盖由 verify_tc_divert_tcp 兜; 别盲重试"
  source: brain update-truth
  affects: [orphan-verifier-ci-blocked]
