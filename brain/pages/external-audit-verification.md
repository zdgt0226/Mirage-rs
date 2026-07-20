---
id: external-audit-verification
title: "外部审计逐条核实: 术语专业但真伪参半"
category: concept
status: active
created: "2026-07-20T11:43:27"
updated: "2026-07-20T12:20:56"
---

## compiled_truth

**观察**:本项目收到过多轮外部代码审计(12 项 / 7 项 / 5 项 / 若干单条),共同特征是
**术语专业、真伪参半、severity 系统性夸大**。稳定命中率约**一半或更低**。

**已证伪的典型**(勿再当 bug 修):
- `splice.rs` "PipeGuard Drop 串包泄漏" —— 引用了一段**根本不存在**的 `Drop` impl。审计会**凭空捏造代码**。
- "探针被转发后能看到目标云厂商 TCP 指纹" —— 转发在应用层,TCP 终结在本机栈。
- "重放缓存可被无令牌 DDoS" —— Poly1305 tag 校验在缓存插入**之前**,前提不成立。
- "ALPN=h2 但首个 app-data 是 1300B 大包" —— 实际两方向首条记录都是小控制记录
  (TCP 先发 `target_header` ~39B;UDP 先发 `[0x00]` ~23B;下行先发 TIME_SYNC ~32B)。
- `rules.rs` "curl UA 豁免 CSRF" —— `User-Agent` 是 Fetch 禁止头,浏览器 JS 无法伪造。

**但核实过程本身有价值**:核第二轮审计时**顺带挖出**真缺陷 —— `dns_xdp` 在内核 ≥6.1 上
加载一直被拒(即用户网关上 XDP 极速 DNS 从未生效),比审计自己列的任何一条都实在。

**方法**:
1. **逐条对着 HEAD 的真实文件核实**,不看措辞看代码;
2. 区分"事实对"与"严重性对"—— 常见形态是事实成立但危害被放大一个量级;
3. 真修的记进 brain,证伪的**也记**(否则下轮审计会再来一遍);
4. 别被 P0 标签带节奏。


## timeline

- time: 2026-07-20T11:43:27
  kind: decision
  summary: "Created this page: 外部审计逐条核实: 术语专业但真伪参半"
  source: "多轮审计核实记录"
  affects: [external-audit-verification]

- time: 2026-07-20T12:20:56
  kind: decision
  summary: "沉淀多轮外部审计的核实方法论"
  source: "多轮审计核实记录"
  affects: [external-audit-verification]
