---
slug: roadmap
title: Roadmap
role: milestones
updated: "2026-07-23T10:13:02"
---

# Roadmap

> **用户确认 (2026-07-21)**: 方向大致对, 但**当前无固定计划 / 无承诺时间表** —— 走一步看一步,
> 哪个撞到痛点就修哪个。下表是"候选池"而非排期。

## 已完成的主线(截至 v0.6.0, WireGuard 已并入 main)

- 透明网关整链路真机跑通(TCP + UDP + 隧道 + 回源)
- 抗识别:三套 ClientHello profile 轮换 + JA4 对照 harness + 同 ASN 伪装域名工具(`--prefix` 按掩码扩大)
- MSS clamp、链路自愈(netlink 变更过滤)、DNS 抗风暴、日志滚动
- **轻量模式** `lite-server`/`lite-client`(SOCKS5 全部转发, 仅 TCP), 服务名 `mirage-rs-lite-*` 与完整版区分
- **中转站**: 服务端接 Shadowsocks 上游(SIP004 + SIP022 全部加密方式; UDP 默认 block)
- **WireGuard 全套**(2026-07-22 并入 main): 客户端出站 + 服务端上游中转, TCP/UDP/隧道内 DNS 全通;
  boringtun + smoltcp 用户态实现, 不需内核模块/root/网络接口; **已对真实 WG 服务端五层验证互通**。
  为何不顺势做 Tailscale 见 [[tailscale-support-deferred]]
- **裸 IP 目标按域名分流**(2026-07-22): SNI/Host 嗅探从 transparent 扩到全部入站,
  解决"app 自己解析完送 IP 导致 domain_suffix/geosite 规则全失效"。见 [[routing-rules]]
- **路由 `inbound` 维度**(2026-07-23): 规则可按入站 tag 限定, 支持"同一域名从不同入站走
  不同出口"。已穿透 socks / mixed / transparent(TCP+UDP)/ dns 全部入站。
  ⚠️ 固有语义: DNS 查询来自 dns 入站, 故 `{"inbound":"tproxy"}` 的规则不影响 fake-IP 决策
- **SOCKS5 UDP 逐数据报路由**(2026-07-23, v0.6.0-alpha.7): 此前出站在 ASSOCIATE 时就用
  `default_outbound` 定死 —— 那时还没有数据报、目标未知, 导致 UDP **完全绕过路由规则**
  (默认直连时本该走隧道的 UDP 从本机 IP 裸奔; 写了 `block` 的目标照发)。会话按出站 tag 建
  而非按目标建(Mirage 隧道自带多路复用, 直连 socket 可 send_to 任意目标)
- **geo 更新器对齐 Python 前身**(2026-07-23): 重启不重下(meta.json 记 downloaded_at)、
  条件请求 ETag/304(真机证实 GitHub release assets 支持)、多镜像 fallback、
  落地前校验内容(数分类数而非看大小)、超时拆三段(实测同链路速度差一个数量级)
- **配置工具链**: `check`(重启前闸门)/ `format` / `import`; 启动时配置校验(未知字段 + 引用完整性)
- **入站认证**: SOCKS5(RFC 1929)/ HTTP(Basic), 修默认开放代理
- **工程债已清**: 死代码 `mss_clamp.elf` 已删; 本地 CI 脚本 `scripts/ci-local.sh`(feature 分支不触发 workflow)
- **易用性/发布**: install.sh 支持轻量模式、SS 上游、WireGuard 上游; 密码 JSON 转义、版本/文档同步流程

## 候选池(无排期)

| 项 | 性质 | 判断 |
|---|---|---|
| **rule-set 远程规则集 + 自动更新** | 路由生态 | 主流(sing-box `.srs` / mihomo rule-provider)有, 我们要手动放 geo 文件, 是维护成本大头。**但先想清安全模型**: 规则文件决定流量去哪, 被篡改 = 静默导向错误出口。须 HTTPS + 哈希/签名固定、**更新失败保留旧规则**(不可静默降级为无规则)、更新后先验证再原子切换 |
| **process_name 分流** | 路由维度 | 客户端刚需("Telegram 走代理、微信直连")。已有 cgroup/connect4 的 eBPF 基础, 拿 pid→进程名比 procfs 扫描干净。见 [[routing-rules]] |
| **指纹 profile 热下发** | 抗识别 | 服务端下发新 ClientHello profile, 免客户端发版。**数据侧可热更(我们 TLS 是假的, key_share 等填随机字节)**, 代码侧用预置编码器 + 数据选择。⚠️ 自动切最新 Chrome 反而更易识别 —— 要按装机份额且错开切换。详见 [[fingerprint-hot-update]] |
| TLS resumption | 破坏性协议变更 | 零会话复用是真实统计指纹;工装已就绪, 两端需同时升级。见 [[tls-fingerprint-mimicry]] |
| ICMP 处理 | 体验缺口 | ping/traceroute 被代理域名不通。**失败形态未在真机确认, 用户明确说等部署网关时再定** |
| **统一出站流接口** | 结构性 | 抽 `OutboundNode::connect(target)->AsyncStream`, 让 geo 等进程内消费者直连隧道, 不再绕 SOCKS 自连 ("proxy URL 丢认证"bug 就是这个绕路的后果)。WgTcpStream 已证明抽象可行。有第二个隧道消费者时一并做。详见 [[unified-outbound-stream]] |
| IPv6 全栈 | 结构性 | 见 [[ipv6-v4only-tradeoff]] |
| SS 上游 UDP | 生态 | 需求驱动: 多数 SS 服务器默认不开 UDP 且无握手, 实现了不等于能用。见 [[ss-upstream-relay]]。**注: WG 上游的 UDP 已通**, 要 UDP 同出口可直接用 WG |
| 订阅链接 | 生态 | 基础已有(node_uri + import), 但**订阅格式本身要先定义**才动手 |
| orphan 验证器接回 CI | 工程债 | 需先拿到 runner 日志访问权。见 [[orphan-filter-blackhole]] |

## 评估过但**不做**的(避免重复讨论)

| 项 | 不做的理由 |
|---|---|
| Tailscale 原生支持 | 不是"难", 是"做了体验更差"。详见 [[tailscale-support-deferred]] |
| 路由决策缓存 | **过早优化**。匹配已是 Aho-Corasick + RegexSet + trie, 单次开销极小; 真瓶颈在 DNS 与建连。要做须先测出来, 且得处理热重载失效 |
| 逻辑规则任意嵌套 (AND/OR/NOT) | 现有 `mode: "and"`(domain AND ip)够用。全嵌套是拿配置复杂度换表达力, 多数人用不上 |
| HNSW / 向量近似匹配做域名分流 | **语义就不对**: ANN 回答"哪个最像", 路由要的是确定性精确判定。`google.com` 与 `googie.com` 向量上极近却必须走不同出口 —— 相似性在这里是有害信号; 且 ANN 召回率 <100% 意味着静默走错出口。性能上也反了: 光算 query embedding 就比整次 trie 查询慢几个数量级 |
| 追平 sing-box 全部规则类型 | 定位是零配置 eBPF 透明网关, 不是通用代理框架。堆用不上的规则类型只会让配置更难懂 |
