---
id: udp-capacity-findings
title: "UDP 带机量实测: direct 网关健康, 隧道受 pool_size 封顶"
category: decision
status: active
created: "2026-07-31T02:28:45"
updated: "2026-08-03T15:15:48"
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

- time: 2026-08-03T15:15:48
  kind: decision
  summary: "UDP mux 已实现 (PR #23, feat/udp-mux, 默认关 tuning.udp_mux+udp_mux_tunnels=4)。方案 A session-id TCP-mux (非 QUIC 终局): 认领 0x01 sentinel (旧 0x00 一流一隧道字节不变), mux 帧=旧帧超集 frameLen 后插 4B sid, 上行带目标下行带回包源客户端按 sid 分流。服务端 handle_udp_mux_relay per-sid 连接式 egress socket (两 sid 打同目标不串) + 单 AEAD writer cancel-safe, sid 上限 512, 支持 Direct+WG 上游。客户端 MuxSet/MuxTunnel: K 条共享长命隧道 (持 Weak pool 防热重载泄漏) 按 flowkey 散列, 共享 writer 跨流合帧, 单 demux 泵按 sid 回。拿掉'并发 UDP 流<=pool_size'硬伤 (mux 下由 MAX_FLOWS 4096 兜底, 不再占 legacy 256 permit)。权衡: 同隧道跨流 HoL 靠 K 路分摊+实时走 WG 逃生。测试: codec 变异 5/5, 服务端两 sid 同目标不串 e2e + 客户端全链路 e2e, full 374 passed。Sonnet 复核 3黄1蓝全修 (REGISTRY 泄漏/256 permit/unregister guard/域名截断)。待真机 bench 验带机量破 pool_size。"
  source: "PR #23 feat/udp-mux commits ddb4208+f802e98"
  affects: [src/proxy/udp_mux.rs, src/proxy/mirage_server/udp_relay.rs, src/proxy/transparent_udp.rs, src/proxy/mirage_server/control.rs, src/config.rs]
