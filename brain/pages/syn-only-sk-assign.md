---
id: syn-only-sk-assign
title: "只对首 SYN sk_assign, 已建流仅打 fwmark"
category: decision
status: active
created: "2026-07-20T11:43:26"
updated: "2026-07-20T12:14:27"
---

## compiled_truth

**决定**:`tc_divert` 对 TCP **只在首 SYN**(`th->syn && !th->ack`)做 `bpf_sk_assign`;
已建连接的后续包**只打 `skb->mark`**,交内核自身的 established 查找。

**理由(踩出来的)**:对已建流也 `sk_assign` 会打断 3rd ACK 的 `tcp_check_req` 把 child 送入 accept 队列的
正常流程 → **握手悬死 + RST**。等价于 iptables TPROXY 对已建流只用 `-m socket` 打标。

**配套前提(缺一不可)**:
- 透明 listener 必须是 `IP_TRANSPARENT`(child 才能绑非本地 foreign 目的);
- `sk_assign` 只设 `skb->sk`,外网目的 + `ip_forward` 仍走转发 → 必须
  `ip rule fwmark 1 lookup 100` + `ip route add local default dev lo table 100`(策略路由,非 netfilter)。

**影响面**:改动 `tc_divert.c` 的 TCP 分支时**必须**保持这个二分,否则整条透明 TCP 断。
已有 netns 验证器 `verify_tc_divert_tcp` 守住;另见 [[orphan-filter-blackhole]] 对已建流分支的额外守卫。

**教训**:光加 `IP_TRANSPARENT`(仅编译过)不够,必须 netns 实跑才暴露这个 BPF 握手 bug。


## timeline

- time: 2026-07-20T11:43:26
  kind: decision
  summary: "Created this page: 只对首 SYN sk_assign, 已建流仅打 fwmark"
  source: "ebpf-src/tc_divert.c 注释, git 936b18b"
  affects: [syn-only-sk-assign]

- time: 2026-07-20T12:14:27
  kind: decision
  summary: "沉淀 tc_divert 里最易被改坏的不变式"
  source: "ebpf-src/tc_divert.c, git 936b18b"
  affects: [syn-only-sk-assign]
