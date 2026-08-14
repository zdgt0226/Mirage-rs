---
slug: roadmap
title: Roadmap
role: milestones
updated: "2026-08-14T20:38:48"
---

# Roadmap

> **用户确认 (2026-07-21)**: 方向大致对, 但**当前无固定计划 / 无承诺时间表** —— 走一步看一步,
> 哪个撞到痛点就修哪个。下表是"候选池"而非排期。

## 已完成的主线 (v0.7.0 – v0.9.2, 均已发布并入 main; PFS 等已进 main 待发版)

- **前向保密 PFS (审计 #2, 最大真安全缺口)** ✅ 已进 main —— opt-in 一次性 X25519 ECDH, 公钥搭
  fake-TLS random 字段交换 (零指纹变化 + 高位随机化抗指纹), `password‖ecdh` 混进 master, 口令泄露
  也解不了已录流量; 两端同开, 失配 fail-closed。详见 [[handshake-forward-secrecy]]。
- **审计尾单批** (待发版, 已进 main / PR 待合) ✅ —— #4 start_proxy 巨石拆分 (753→400, src/startup.rs) ·
  #8 握手失配统一诊断 (密码/时钟/pfs 单边, 客户端+服务端共用) · #7 实处 (install.sh 补 pfs 开关 +
  config 模板防漂移测试) · WgTcpStream::connect 同步失败泄漏 socket 修复 · RateLimiter 摊还式定期清理。
  详见 [[external-audit-2026-08]]。
- **握手模板完整性修复** (v0.9.2) ✅ —— 服务端 `handshake_cache` 只缓存**含齐 0x16+0x14+0x17 三型**的
  camouflage 模板 (纯函数 `template_is_complete` 校验; 缺型/截断/尾部残字节一律弃、回落恒完整的
  fallback)。修完整服务端↔客户端 (含轻量模式, 非轻量特有) 偶发 `read_exact tail timed out` 握手卡死:
  旧版 fetch 固定只多读 2 帧, 遇拆帧站/TLS1.2 站缓存出残模板 → 客户端永等不到三型齐、不发 tail。带
  e2e 回归 (本地残 camouflage 站, 去修复即 10s 超时 FAILED)。详见 [[handshake-template-completeness]]。
- **外部审计便宜纯赚 + 去阻塞** (v0.9.2) ✅ —— API 认证失败 per-IP 限流 (#28) · cargo-deny 供应链
  门禁 (抓出 anyhow RUSTSEC-2026-0190 → 升 1.0.104) · README 安全声明 · RTT/brutal 监控去阻塞
  (spawn_blocking) + 调速逻辑抽纯函数 (#29) · 三类 parser 补 proptest 属性测试 (#30)。
- **clippy 清零 + CI -D warnings** (v0.9.2) ✅ —— `clippy --all-targets` 清到 0, CI 门禁翻
  `-D warnings` (新 warning 即红)。**候选池"clippy → -D warnings"已落地。**
- **WG 入站"干净设备"落地** (v0.9.1) ✅ —— install.sh 菜单项 7 家庭 WireGuard 服务端 (内核 WG +
  eBPF 透明网关, 非 boringtun responder), wg0 纳入透明网关, 真机验证过。移动设备经家中网关代理零翻墙
  痕迹。**候选池"WG 入站干净设备"已落地。** 见 [[chain-proxy-roadmap]]。
- **§7 抗审查泄漏护甲** (v0.9.1) ✅ —— T2/T4 进程内泄漏测试 (fake-IP / 空 AAAA / block→NXDOMAIN)。
- **统一出站流接口** (v0.8.1) ✅ —— `OutboundNode::connect(target)->OutStream`, 帧式 async 包成
  AsyncRead+AsyncWrite (MirageStream/SsStream/WgTcpStream 适配器)。解锁链式代理 + geo 经隧道免绕
  SOCKS 自连。详见 [[unified-outbound-stream]]。**此前是候选池"结构性"地基, 已落地。**
- **链式代理** (v0.8.1) ✅ —— Mirage-over-X 套娃 (`underlying`, 隧道骑另一出站) · SS 双向
  (入站 SIP004 惰性 salt 抗探测 / 出站) · SS-over-Mirage (类 shadow-tls+ss) · geo 经隧道下载。
- **UDP mux** (v0.9.0) ✅ —— 透明 UDP 多流按 flowkey 散列复用 K=4 共享隧道, 拿掉"并发 UDP 流 ≤
  pool_size"带机量硬伤。**真机实测两端 0.5→0.9 部署: 并发拐点 20→450 (22.5×)**, 墙是服务端
  fd/CPU 非 mux。默认关 tuning.udp_mux。详见 [[udp-capacity-findings]]。QUIC Datagram 终局版仍在候选池。
- **TLS record padding** (v0.8.0) ✅ —— 抗握手后包长序列 ML 指纹, 收端恒剥零 + 发端门控。
- **cipher agility** (v0.7.0) ✅ —— 两端有 AES-NI 时协商 AES-256-GCM (~2.1×), ClientHello 零触碰。
- **IPv6 隧道传输** (v0.7.0) ✅ —— 服务端 v6 监听 + 客户端连 v6 服务端; 透明数据面 v6 epic 已否决
  (fake-IP + 服务端远程解析已让客户端 v6 数据面不必要)。
- **抗审查 §7 泄漏护甲测试 (T2/T4, 进程内)** ✅ —— 被代理域名 A→fake-IP / AAAA→空答复 (永不走本地
  UDP:53) + block→NXDOMAIN。见 docs/threat-model.md §7。剩 WG 隧道内 DNS (需 netns) + T1 转发未补。
- **外部审计修复批次** (v0.8.0 / v0.9.0) ✅ —— WG 隧道内 DNS 死代码接线 · DNS-over-TCP 校验 TXID+QR
  防注入 · 常量时间比较统一 subtle (弃 deprecated ring) · CSRF/token 加固 · UDP mux 背压。
- **install.sh 真机改进** (v0.9.0) ✅ —— 服务端生成 config 补 direct 出站 · 客户端问 udp_mux ·
  两端 systemd 化 LimitNOFILE=1048576 (真机踩坑印证)。

## 已完成的主线 (截至 v0.6.0)

- 透明网关整链路真机跑通 (TCP + UDP + 隧道 + 回源)
- 抗识别: 三套 ClientHello profile 轮换 + JA4 对照 harness + 同 ASN 伪装域名工具
- MSS clamp · 链路自愈 (netlink) · DNS 抗风暴 · 日志滚动
- **轻量模式** lite-server/lite-client (SOCKS5 全部转发, 仅 TCP)
- **中转站**: 服务端接 Shadowsocks 上游 (SIP004 + SIP022; UDP 默认 block)
- **WireGuard 全套** (客户端出站 + 服务端上游中转, TCP/UDP/隧道内 DNS 全通; boringtun+smoltcp 用户态)
- **裸 IP 目标按域名分流** (SNI/Host 嗅探扩到全部入站)
- **路由 `inbound` 维度** · **SOCKS5 UDP 逐数据报路由** · **geo 更新器对齐 Python 前身**
- **配置工具链** check/format/import + 启动校验 · **入站认证** SOCKS5/HTTP · 工程债清理

## 候选池 (无排期)

| 项 | 性质 | 判断 |
|---|---|---|
| **UDP mux → QUIC Datagram** | 传输/抗审查 | mux 终局无 HoL 版 (quinn + 握手 + 伪装整合)。TCP-mux 已缓解带机量; QUIC 解跨流队头阻塞 + 实时质量。大工程。见 [[udp-capacity-findings]] |
| **rule-set 远程规则集 + 自动更新** | 路由生态 | 维护成本大头。**先想清安全模型**: HTTPS + 哈希/签名固定 · 更新失败保留旧规则 · 先验证再原子切换 |
| **process_name 分流** | 路由维度 | 客户端刚需 (TG 走代理/微信直连)。已有 cgroup/connect4 eBPF 基础。见 [[routing-rules]] |
| **指纹 profile 热下发** | 抗识别 | 服务端下发新 ClientHello 免客户端发版 (数据侧可热更)。⚠️ 按装机份额错开切换。见 [[fingerprint-hot-update]] |
| **§7 泄漏测试补全** | 抗审查测试 | 剩 WG 隧道内 DNS (需 netns) + T1 认证失败转发伪装站 (probe.rs 部分)。 |
| TLS resumption | 破坏性协议变更 | 零会话复用是真实统计指纹; 工装就绪, 两端需同升。见 [[tls-fingerprint-mimicry]] |
| ICMP 处理 | 体验缺口 | ping/traceroute 被代理域名不通。**失败形态待真机确认, 用户说部署网关时再定** |
| IPv6 全栈 (透明数据面) | 结构性 | 见 [[ipv6-v4only-tradeoff]]; 透明 v6 epic 已降级, 隧道传输 v6 已做 |
| SS 上游 UDP | 生态 | 需求驱动; **WG 上游 UDP 已通**, 要 UDP 同出口直接用 WG。见 [[ss-upstream-relay]] |
| 订阅链接 | 生态 | 基础已有 (node_uri + import), 但订阅格式要先定义 |
| orphan 验证器接回 CI | 工程债 (审计 #10) | 需 runner 日志访问权。见 [[orphan-filter-blackhole]] |
| install.sh 二进制签名 | 分发 (审计 #13) | 现只 sha256。cosign keyless (GitHub OIDC 免存密钥) 可行, 但**需 CI 实跑验证**才知对错。价值: 供应链完整性。 |
| bench 性能门禁 | 工程债 (审计 #14) | 已有 aead cipher_bench (手写)。加 criterion + CI 门禁需基线管理; **价值边际** —— 抗审查瓶颈在网络非本地 crypto。 |
| TLS padding 后续 | 抗审查 | 记录切分 / 伪真实站点分布 / 长度模型升级 |

## 评估过但**不做**的 (避免重复讨论)

| 项 | 不做的理由 |
|---|---|
| Tailscale 原生支持 | 不是"难", 是"做了体验更差"。详见 [[tailscale-support-deferred]] |
| boringtun WG 入站 responder | 已否决, 改内核 WG + eBPF 透明网关 (干净设备用法)。见 [[chain-proxy-roadmap]] |
| 路由决策缓存 | **过早优化**。匹配已是 Aho-Corasick + RegexSet + trie; 真瓶颈在 DNS 与建连 |
| 逻辑规则任意嵌套 (AND/OR/NOT) | 现有 `mode: "and"` 够用。全嵌套是拿配置复杂度换表达力 |
| HNSW / 向量近似匹配做域名分流 | **语义就不对**: 路由要确定性精确判定, 相似性在这里是有害信号; 召回 <100% = 静默走错出口 |
| 追平 sing-box 全部规则类型 | 定位是零配置 eBPF 透明网关, 不是通用代理框架 |
