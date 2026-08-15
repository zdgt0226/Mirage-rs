---
id: udp-capacity-findings
title: "UDP 带机量实测: direct 网关健康, 隧道受 pool_size 封顶"
category: decision
status: active
created: "2026-07-31T02:28:45"
updated: "2026-08-16T00:10:25"
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

- time: 2026-08-04T22:52:18
  kind: note
  summary: "UDP mux 真机实测通过 (2026-08-04)。拓扑: LAN 透明网关 172.16.0.162 (2 核, 旁路由 enp1s0, pool_size=100) + Mirage 服务端 144.225.246.83 (1 核)。两端从 v0.5.0 升级到 v0.8.1 (feat/udp-mux 分支, 协议 0.5<->0.8 向后兼容真实流量正常)。测法: 网关 netns 模拟 LAN 客户端 (走 sk_lookup fake-IP 路径, 因单臂网卡无法用 tc_divert bare-IP), 目标域名 muxbench.test 经 fake-IP+服务端 /etc/hosts 解到本地 echo, scripts/bench_udp_capacity.py 斜坡加压。结果 flow_ok 拐点: mux-off=20 (退化崩, 每流独占隧道压垮 1 核服务端) / mux-on 服务端 fd=1024 时=200 / mux-on 服务端 fd=65536 时=450 (100% 稳到 400 流)。20->450 = 22.5x。关键: 每道墙都是环境限 (先服务端 fd Too-many-open-files 后 1 核 CPU), 从不是 mux 设计 —— 全程无 sid 饱和告警、无 UdpRcvbufErrors; mux 还同时正确复用真实 YouTube QUIC 多流 (K=4 共享隧道)。结论: 带机量硬伤 (并发 UDP 流<=pool_size) 已解除, 特性生产可用。部署: 两端已 systemd 化 (mirage-rs.service, LimitNOFILE=65536, enable 自启), 网关 config tuning.udp_mux=true 常开, 服务端 config 补了 direct 出站 (0.8.1 校验必需)。旧二进制/配置备份在 .bak。"
  source: "真机 172.16.0.162 + 144.225.246.83 bench 三轮 mux-off/on + systemd 部署"
  affects: [src/proxy/udp_mux.rs, scripts/bench_udp_capacity.py]

- time: 2026-08-16T00:10:25
  kind: evidence
  summary: "22.5× 容量现有 CI 守卫: 抽 udp_mux::slot_index 纯函数, 测 N 流散布到全 K 槽 (复用不变量) + transparent_udp MAX_FLOWS≥1024/MAX_MIRAGE_UDP_FLOWS≥128 下限; 变异 2/2 kill。改坏复用/调低总闸即 CI 红, 不再依赖真机 bench_udp_capacity.py 手动跑。cipher 速度是 timing 噪声不进 CI 门"
  source: commit test/udp-mux-capacity-guard
  affects: [udp-capacity-findings]
