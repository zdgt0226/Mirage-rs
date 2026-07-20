---
id: ebpf-scope-narrowed
title: "eBPF 职责收窄为拦截/重定向, 不接管数据面"
category: decision
status: active
created: "2026-07-20T11:43:26"
updated: "2026-07-20T12:14:27"
---

## compiled_truth

**决定**:eBPF 只承担三件事 —— ① `tc_divert` 拦截转发流量并 `sk_assign` 给透明 listener;
② `cgroup/connect4` 重定向本机出向;③ `dns_xdp` 极速 DNS(默认关)。**数据搬运一律在用户态**。

**备选**:像 Landscape 那样上完整 XDP+TC chain 流水线(root→stage→exit)、eBPF 内全锥 NAT、
线速转发。

**理由**:
- 代理路径本就要经用户态隧道(加密/封帧),XDP 又**不能** `sk_assign`,把数据面搬进内核收益极低而复杂度爆炸。
- Landscape 要求内核 **≥6.9 + BTF/CO-RE**;本项目部署目标内核偏老(曾在部署机撞上 sockmap `EINVAL`),
  其 eBPF 代码并非拿来即用。
- "直连快"靠**内核旁路 + `splice(2)`** 达成(见 [[splice-over-sockmap]]),不需要 eBPF 转发。

**影响面**:限定了性能上限(非线速),但换来内核版本兼容性与可维护性。直连回程仍需 1 条 MASQUERADE ——
要彻底去掉需 vendor einat-ebpf,属高成本非紧急项。


## timeline

- time: 2026-07-20T11:43:26
  kind: decision
  summary: "Created this page: eBPF 职责收窄为拦截/重定向, 不接管数据面"
  source: "docs/landscape-analysis.md, src/ebpf/, git log"
  affects: [ebpf-scope-narrowed]

- time: 2026-07-20T12:14:27
  kind: decision
  summary: "从代码与 landscape 对比分析中提炼 eBPF 边界"
  source: "docs/landscape-analysis.md, src/ebpf/"
  affects: [ebpf-scope-narrowed]
