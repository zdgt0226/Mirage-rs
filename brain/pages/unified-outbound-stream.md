---
id: unified-outbound-stream
title: "统一出站流接口: 让 geo 等进程内消费者直连隧道, 不再绕 SOCKS 自连"
category: decision
status: active
tags: [refactor, outbound, geo, architecture]
created: "2026-07-23T10:08:11"
updated: "2026-07-23T10:08:47"
---

## compiled_truth

**候选重构 (无排期)**: 抽一个 `OutboundNode::connect(target) -> impl AsyncRead + AsyncWrite`,
让**进程内**的消费者 (当前是 geo updater, 未来订阅/指纹热下发同理) 能像用普通流一样用隧道,
不再绕 SOCKS 入站自连。见 [[routing-rules]]。

## 现状: geo 借道 SOCKS 入站自连下载

geo updater 用 `reqwest`(HTTP 客户端), reqwest 只认两种出口: 直连 socket, 或 SOCKS/HTTP
代理 URL。而我们的隧道**没有干净的 `connect(target) -> Stream` 接口** —— Mirage 建连逻辑
深缠在 `handler.rs` 里: 取隧道 → 拼 target_header → 首写重试 → **立刻进双向 relay**, 它不
返回流给别人用, 自己把整条连接跑完。

所以 geo 借现成的 SOCKS 入站当出口: `socks5://127.0.0.1:1080` → 完整 `route()` →
mirage 出站 → 隧道。**这是"经隧道下载"的正确语义**, 不是绕过隧道。

## 为什么现在是这样 (三个真实原因, 非偷懒)

1. reqwest 需要 socket 或代理 URL, 隧道没有可复用的流接口。
2. 借 SOCKS 入站 = 白嫖整套路由 —— geo 下载也受路由规则控制 (可让 geo 走特定出站), 写死
   走某条隧道反而丢了这个灵活性。
3. 复用而非重造: SOCKS 入站已处理 target 解析/连接管理/错误回落。

## 代价 (已中招一次)

- **"proxy URL 丢认证"bug 就是这个绕路的直接后果**: 进程连自己的 SOCKS 入站还得过自己的
  认证 (2026-07-23 已修, 靠把凭据编进 URL)。进程内的东西为用自己的隧道要绕到网络层再连回
  自己, 架构上荒谬。
- 多一次 loopback TCP + SOCKS 握手 (开销小但非零)。
- **依赖 SOCKS/mixed 入站存在**: 纯透明网关模式若没配 socks/mixed 入站, geo 的 `via: proxy`
  没出口, 回落直连 → 大陆环境拉不到 geo。这是最实际的缺陷。

## 正确方向

抽 `OutboundNode::connect(target) -> impl AsyncRead + AsyncWrite`:
- geo 直接 `outbound.connect("github.com:443")`, 不经 SOCKS、不需认证、不依赖入站存在;
- reqwest 用自定义 connector 吃这个流;
- **WireGuard 的 `WgTcpStream` 已经是这个形状** —— 证明抽象可行, 只是 Mirage 出站还没跟上。
  做统一接口时把 handler 里那坨建连逻辑解耦成"可返回流", 双向 relay 变成流之上的一层。

## 判断

现状能用、不紧急 (`via: proxy` 有 socks 入站时正常, 认证 bug 已修)。这是**设计债**, 归为
结构性重构候选。触发时机: 哪天有第二个进程内隧道消费者 (订阅自动更新 / 指纹 profile
热下发 —— 见 [[fingerprint-hot-update]]) 时一并做, 那时"绕 SOCKS"的荒谬会被放大到值得还债。


## timeline

- time: 2026-07-23T10:08:11
  kind: decision
  summary: "Created this page: 统一出站流接口: 让 geo 等进程内消费者直连隧道, 不再绕 SOCKS 自连"
  source: "2026-07-23 讨论"
  affects: [unified-outbound-stream]

- time: 2026-07-23T10:08:47
  kind: decision
  summary: "记录候选重构: 抽 OutboundNode::connect(target)->AsyncStream, 让 geo 直连隧道而非绕 SOCKS 自连; WgTcpStream 已证明该抽象可行"
  source: "2026-07-23 讨论"
  affects: [unified-outbound-stream]
