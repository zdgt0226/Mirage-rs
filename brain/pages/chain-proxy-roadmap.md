---
id: chain-proxy-roadmap
title: "链式代理 roadmap: WG/SS 双向 (入站+出站) + 自定义转发"
category: decision
status: draft
tags: [roadmap, chain-proxy, wireguard, shadowsocks, architecture]
created: "2026-07-27T01:30:56"
updated: "2026-08-05T01:25:39"
---

## compiled_truth

## 用户诉求 (2026-07-27)

后续要**链式代理**: WireGuard 和 Shadowsocks 作为对接协议, **既能作入站也能作出站**,
实现自定义转发 (如 SS 入 → WG 出, 或 Mirage 入 → SS 出 的任意编排)。

## 当前状态 (差距)

- **Shadowsocks**: 仅**出站/上游** (`UpstreamConfig::Shadowsocks`, 服务端把流量再经 SS 发上游,
  仅 TCP)。**无 SS 入站** (不能接受 SS 客户端)。
- **WireGuard**: 出站 (`OutboundConfig::Wireguard`) + 上游 (`UpstreamConfig::Wireguard`)。
  **无 WG 入站** (不能作 WG 服务端/responder 接受 peer)。
- 入站只有 Socks/Mixed/Dns/Transparent/MirageServer。

## 方向 (分阶段, 大工程 —— 不塞进小改)

1. **抽象出站流接口** (roadmap 已有): `OutboundNode::connect(target) -> Stream`, 让所有出站
   (Mirage/WG/SS/Direct) 统一; 是链式转发的地基。
2. **SS 入站**: 实现 SS 服务端协议 (SIP004/022 解密 + 目标解析), 作 inbound。
3. **WG 入站**: 实现 WG responder (boringtun 服务端侧 + smoltcp), 接受 peer, 取隧道内 TCP/UDP。
4. **自定义转发链**: 路由/出站编排让"入站 X → 出站 Y"任意组合 (类 sing-box inbound→outbound)。

## 决定

**认可方向, 但不在当前小改里做** (一次吞太大违背简单优先)。先记为 roadmap, 后续独立分阶段推进。
设计新东西时保持与此兼容 (如 dns_tcp_resolver、出站接口抽象都不挡路)。根 roadmap 见 brain/roadmap.md。

关联 [[server-dns-over-tcp]]。


## timeline

- time: 2026-07-27T01:30:56
  kind: decision
  summary: "Created this page: 链式代理 roadmap: WG/SS 双向 (入站+出站) + 自定义转发"
  source: "用户 2026-07-27 提出"
  affects: [chain-proxy-roadmap]

- time: 2026-07-27T01:30:56
  kind: decision
  summary: "未来方向(未实现): WG/SS 既能作入站也能作出站, 支持自定义转发链; 当前二者仅出站/上游, 缺入站侧实现; 大工程, 分阶段"
  source: brain update-truth
  affects: [chain-proxy-roadmap]

- time: 2026-07-27T01:31:30
  kind: decision
  summary: "未来方向(未实现): WG/SS 既能作入站也能作出站, 支持自定义转发链; 当前二者仅出站/上游, 缺入站侧实现; 大工程, 分阶段"
  source: brain update-truth
  affects: [chain-proxy-roadmap]

- time: 2026-08-02T19:48:12
  kind: decision
  summary: "链式代理(5) 设计吸收 (Gemini 方案对比, 2026-08-02)。前置 [[unified-outbound-stream]] Phase A 已给 OutboundNode::connect(target)->OutStream (building block)。链式代理的核心增量 = **underlying_dialer 注入** (Gemini 方案精华, 即 sing-box detour / 俄罗斯套娃): 让协议的 dial 可选地穿另一个 dialer 返回的流拨号, 而非物理网卡 —— 例 SS 出站注入 WG 出站作 underlying_dialer, SS.dial 时先 WG.dial(ss_server) 拿到隧道流, 再在其上做 SIP022 握手返回 Box<dyn Stream>。零耦合套装。另吸收 Address 枚举 (Domain/SocketAddr) 替 &str+split_host_port。**三个坑别照抄 Gemini**: (1) AnyStream 别加 Sync bound (MirageStream 持 BoxFuture 非 Sync, 流只需 Send); (2) 别上 #[async_trait] (加依赖+每调用装箱; Rust 1.75 原生 async trait 已稳, 或保持枚举); (3) 别整体把 OutboundNode 枚举擦成 Arc<dyn OutboundDialer> (大重写高风险) —— 优先增量: 枚举变体加 underlying_dialer 字段即可套娃, 热路径流类型保留 OutStream 枚举 (无 vtable) 而非 Box<dyn AnyStream>。handler.rs 用 connect+copy_bidirectional 去重 (Gemini Phase1 / 我们 unified-outbound Phase C) 是可选清理, 动热路径风险高, 与链式代理解耦分开做。"
  source: "Gemini 链式代理方案 vs 我们 Phase A 对比 + Rust async trait/Sync 现实"
  affects: [chain-proxy-roadmap, unified-outbound-stream, src/proxy/outbound.rs]

- time: 2026-08-02T22:46:39
  kind: decision
  summary: "子件 ⑤ 出站套娃 Mirage-over-X 已实现并入 main (2026-08-02, PR #20, Sonnet 复核 0 严重)。Mirage 出站配 underlying=<tag> → 对 server:port 的连接经该出站拨号 (物理网卡→另一出站): Mirage-over-WG / Mirage-over-Mirage 双跳。实现: 步骤1 Tunnel 传输改 enum TunnelRead/TunnelWrite {Tcp 快路径不变 | Boxed 骑 OutStream}; 步骤2 connect_upstream 分 TCP/underlying 两路 + do_fake_tls 泛型握手 + read_server_handshake 泛型 + PoolConfig.underlying + OutboundManager 拓扑排序(延后建+环报Err)+ semantic_issues 校验。已知限制(文档化, 非 bug): 嵌套隧道入池但无裸 fd → is_stale 保守判健康, 死的嵌套靠 max_age 回收+首写失败重试, 不被 sweeper 主动清; 嵌套无 brutal(CC 由 underlying 负责)。剩子件: ②SS 入站 ③WG 入站 (各自协议服务端, 独立大工程); ④编排靠现有 routing inbound 条件基本已具备(缺的只是 WG/SS 入站)。后续增强候选: 嵌套死隧道主动探活; handler 用 connect+relay 去重(Phase C, 动热路径)。"
  source: "PR #20 合并 + Sonnet 复核"
  affects: [src/proxy/tunnel.rs, src/proxy/pool.rs, src/proxy/outbound.rs, src/config.rs]

- time: 2026-08-03T02:30:05
  kind: decision
  summary: "WG 入站 (③): **不做 boringtun WG responder**, 改用**内核 WireGuard 服务端 + 现有 eBPF 透明网关** (2026-08-03, 用户'干净设备'用法确立)。用法: 移动设备用系统原生 WireGuard 接入家中网关 (设备↔家域内 WG, **不跨 GFW 不被封**), 既访问家中 LAN 又经网关 Mirage 抗审查出海; 设备上**零翻墙痕迹** (只是通用 VPN, 降查水表风险), 翻墙逻辑全在网关。此前误判 WG 入站无用 (以为 WG 必跨 GFW 被封), 实际域内 WG 有效, 用法成立。为何不用 boringtun responder: 该用法需 AllowedIPs=0.0.0.0/0 的透明 over WG (模型 B), smoltcp 用户态栈做不了透明; 而内核 WG 天生能, 且久经考验 —— 同 Tailscale 立场 (跑成熟原生件 + Mirage 管出海), 别重造 WG 轮子。技术机制 (关键): 透明拦截**按 fake-IP 目标, 非 mark/SO_MARK**; SO_MARK 只标本机进程自发 socket, 标不了 wg0 peer 转发流量, 错工具。fake-IP 拦截靠  (fake-IP 段=本机地址→本地投递→触发 sk_lookup) + **sk_lookup 挂 netns 不绑网卡** (transparent.rs:73) → **dest-based, iface 无关 → wg0 到 fake-IP 流量自动命中, 和 LAN 一样, 零额外配置/无 mark/无防火墙**。防火墙仅用于非代理直连腿的标准 ip_forward+NAT。命门=手机 WG 配 DNS=网关内网 IP (海外域名才解成 fake-IP)。bare-IP 直连 (无域名) 需 tc_divert 绑 wg0, 但手机场景罕见。待做 (小, 几乎无新 eBPF): install.sh 加家庭 WG 服务端一键配置 + wg0 纳入 (ip_forward/NAT/fake-IP local 路由) + 真机验 wg0-ingress→local 投递 + rp_filter 放行。boringtun WG 入站/responder 从计划池删。"
  source: "用户干净设备用法 + transparent_net.rs fake-IP local 路由机制 + transparent.rs:73 sk_lookup netns 挂载"
  affects: [chain-proxy-roadmap, src/proxy/transparent_net.rs, src/ebpf/transparent.rs, install.sh]

- time: 2026-08-03T02:31:01
  kind: note
  summary: "(补上条被 shell 吃掉的一句) fake-IP 拦截靠: ip route replace local 198.18.0.0/15 dev lo —— 把 fake-IP 段声明成本机地址, 使发往它的包走本地投递而非转发, 从而触发 netns 上的 sk_lookup 重定向到 Mirage。见 transparent_net.rs。"
  source: "更正上条 backtick 缺失"
  affects: [chain-proxy-roadmap]

- time: 2026-08-05T01:25:39
  kind: decision
  summary: "WG 入站'干净设备'已落地 (2026-08-05, branch feat/wg-inbound-clean-device)。install.sh 加菜单 7) 家庭 WireGuard 服务端: 装 wireguard-tools+内核 WG, 生成 wg0(10.7.0.1/24)+NAT+wg-quick@wg0 自启, 每设备生成配置(文本+二维码)幂等追加 peer, 设备 DNS 强制指向网关 wg0 IP(命门)。**零 Rust 改动** —— 决策预测的机制真机端到端验证成立: netns 模拟 WG peer → 网关 wg0-ingress → 目的 fake-IP 本地投递 → sk_lookup 命中(挂 netns 不绑网卡)→ 透明代理 → Mirage 出海, google/cloudflare HTTP 200; 国内 baidu 走直连 NAT; 被代理域名只解 fake-IP 不泄真实 IP(T2/T3)。rp_filter 网关已=0 免坑。网关坑记录: 无 iptables(纯 nft)需装 iptables, wireguard.ko 在但需 modprobe。README 加干净设备接入一节+已知限制(裸 IP 从 wg0 不被 tc_divert 拦, 罕见)。boringtun WG responder 保持否决。"
  source: "install.sh config_wg_server + 真机 172.16.0.162 netns WG peer 端到端验证"
  affects: [install.sh, README.md]
