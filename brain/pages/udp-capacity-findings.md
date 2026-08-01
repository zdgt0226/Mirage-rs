---
id: udp-capacity-findings
title: "UDP 带机量实测: direct 网关健康, 隧道受 pool_size 封顶"
category: decision
status: active
created: "2026-07-31T02:28:45"
updated: "2026-08-02T01:03:17"
---

## compiled_truth

<current best understanding — replace this with the real content>

## timeline

- time: 2026-07-31T02:28:45
  kind: decision
  summary: "Created this page: UDP 带机量实测: direct 网关健康, 隧道受 pool_size 封顶"
  source: "旁路由 ens192 nstat/ip -s link 实测 + transparent_udp.rs:685 + config.rs:1152 pool_size=16 + scripts/bench_udp_capacity.py"
  affects: [udp-capacity-findings]

- time: 2026-08-02T01:03:17
  kind: note
  summary: "第三轮外部审查 3 条 UDP/侧信道核验 (2026-08-02)。①ct_eq: 手写常量时间累加器 Rust/LLVM 不保证不被优化破坏, 已换 ring::constant_time::verify_slices_are_equal (审计过带优化屏障), commit 见下; 实际严重度低(网络抖动盖过纳秒差+token高熵)但便宜且正确. ②WG 上游 UDP MTU 碎化黑洞(真, 窄): WG device MTU 默认 1420(default_wg_mtu), 满载 1500 UDP 塞 WG 上游超 1420 → smoltcp IPv4 分片有限+DF 丢 → 大包黑洞; MSS clamp 只管 TCP 救不了 UDP; 命中面窄(WG上游+大UDP如QUIC满帧/游戏大状态), 彻底修要 PMTU/分片非小工程, 记已知限制. ③UDP-over-TCP 队头阻塞(真, 设计固有权衡非bug): UDP 塞 TCP 隧道丢包触发重传阻塞后续 UDP → 实时流毛刺, 是TCP基代理通病/伪装代价(裸UDP更易被封); 但我们一流一隧道故 HoL 是**每流独立**(一条流丢包不连累别流); 逃生通道=WG上游 UDP 原生承载无 TCP HoL, 实时 UDP 该走 WG 上游. **关键约束并入 [[udp-tunnel-per-flow-bottleneck]] / #5 UDP mux 立项**: 若多流复用共享隧道, 每流独立 HoL 会变**跨流 HoL**(一条流丢包卡住所有复用流), 故 mux 不能无脑合并——要么只 mux 非实时流/实时流留独立隧道, 要么权衡池利用率 vs 队头隔离."
  source: "第三轮审查 3 条 + tunnel.rs default_wg_mtu=1420 + transparent_udp.rs:685 一流一隧道 + ring 依赖"
  affects: [src/api/mod.rs, src/proxy/wg/tunnel.rs, src/proxy/transparent_udp.rs]
