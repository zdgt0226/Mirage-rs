---
id: orphan-filter-blackhole
title: "孤儿 tc 过滤器黑洞: 已建流打 mark 前先探 listener"
category: decision
status: active
created: "2026-07-20T11:43:27"
updated: "2026-07-20T12:19:59"
---

## compiled_truth

**问题**:进程被 SIGKILL / 正常停止后,tc 过滤器**仍挂在网卡上**(tc 持有 prog 引用,不随进程消失),
而 `fwmark → local` 路由表的 `ip rule` 由独立的 `mirage-gw-nat.service` 装、只在卸载时删。
两者叠加会把 LAN 每个已建流的包引到 local 表却**无 socket 可收** → **整段非直连 TCP 黑洞**。

**决定**:已建流分支在打 `skb->mark` **之前**先 `bpf_sk_lookup_tcp` 探一下透明 listener 还在不在;
不在就 `return TC_ACT_OK` 让包走正常转发。**代理没了顶多不加速,不该断网。**

**CI 现状(工程债)**:`verify_tc_divert_orphan` 验证器**已从 CI 摘掉**(`build.yml` 里注释掉),
脚本保留、本地 ≥6.1 可跑。摘掉原因是**测试脚手架**问题而非产品问题 —— 实证链:
`verify_tc_divert_tcp` 用真实握手在 5.15 上跑通了同一段门控;orphan 验证器改真实连接驱动后仍红,
CI 日志显示失败点是 `connect: Network is unreachable`(veth carrier/路由 settle 窗口的瞬时竞态),
**根本没走到** tc_divert/sk_lookup。

**教训**:
1. 用注入延迟复现出"相同症状"只证明该路径**足以**产生此症状 ≠ 实际病因(充分非必要)。曾据此宣称
   "元凶坐实"并推修复,CI 照红。
2. 无 CI 日志访问权时别连推猜修 —— 烧了 7 次 CI 才拿到决定性日志。
3. netns 集成测试要用**真实内核流量**,别造合成包(跨内核行为不一致)。


## timeline

- time: 2026-07-20T11:43:27
  kind: decision
  summary: "Created this page: 孤儿 tc 过滤器黑洞: 已建流打 mark 前先探 listener"
  source: "ebpf-src/tc_divert.c, git b96ac23"
  affects: [orphan-filter-blackhole]

- time: 2026-07-20T12:19:59
  kind: decision
  summary: "沉淀孤儿过滤器故障模式与 CI 现状"
  source: "ebpf-src/tc_divert.c, git b96ac23"
  affects: [orphan-filter-blackhole]
