# Mirage-rs 抗审查威胁模型 (验收基准)

本文件定义 Mirage-rs 作为**抗审查透明代理/网关**的安全验收目标。每个功能改动都应对照这些
目标验收;`tests/` 里的场景/泄漏测试 (见 §7 映射) 是这些目标的可执行断言。

> 定位:零配置 eBPF 透明网关 / 旁路由。威胁方 = 有能力做主动探测、DNS 污染、流量分析、
> 时序观测的网络审查者 (GFW 级)。**不在**范围:端点被物理控制、客户端二进制被篡改。

---

## T1 抗主动探测 (anti-active-probing)

**目标**:审查者主动连接服务端端口 (`:443`) 或重放捕获的流量,无法把它和一个真实
TLS 站点区分开。

- 伪装前置是**真站点**:`:443` 本来就通,连上 ≠ 是 Mirage 服务端。
- 认证失败 → 服务端把连接**转发给伪装站** (不是关连接/回错误)。见 [[camouflage-forward-on-auth-fail]]。
- ClientHello **字节级仿真** 真实 Chrome (JA3/JA4 对照),三 profile 轮换。见 [[tls-fingerprint-mimicry]]。
- 握手控制全在**加密信道内**,ClientHello 不夹带任何明文协商位。见 [[no-plaintext-handshake-control]]。
- `session_id` 每次全新随机,与真 Chrome 不可区分,不是指纹。见 [[session-id-not-a-fingerprint]]。

**红线**:任何"仅 Mirage 服务端才有"的可观测响应差异 (特定错误、特定长度、特定时序) = 违规。

## T2 抗 DNS 污染 (anti-DNS-pollution)

**目标**:被代理 (海外) 域名的解析结果**永不采信被污染的本地/公共 UDP DNS**。

- 海外域名走 fake-IP + 服务端远程解析,不信本地解析。
- `auto_classify`:未分类域名先国内 DNS 解析,首个 A 记录经 GeoIP 判,海外则转 fake-IP。
- 国内 DNS 仅作直连域名/最终回落。

**红线**:被判为"代理"的域名,其真实目标 IP 若来自本地 UDP:53 明文解析 = 违规 (可被投毒)。

## T3 不泄漏真实 IP (no real-IP leak)

**目标**:被代理流量**永不从客户端真实 IP 出站**。

- SS 上游 UDP **默认 `block`** (不放行),否则 UDP 会从本机 IP 裸奔而 TCP 走上游,暴露真实 IP + 关联。
- 透明数据面 v6 目标当前 drop (未做 v6 数据面,避免 v6 直连泄漏)。
- fake-IP 命中 = 该域名必走隧道,不回退直连。

**红线**:任一被代理域名的数据报以客户端真实源 IP 直发目标 = 违规。

## T4 失败即关闭 (fail-closed)

**目标**:组件失败时,被代理流量**宁可断,不可泄漏成直连**。

- fake-IP 映射丢失/淘汰且无域名可恢复 → **drop**,不猜、不回退直连。
- 隧道不可用 → 被代理连接失败 (不静默改直连)。
- DNS 解析失败 → 不 fallback 到明文本地解析被代理域名。

**红线**:任何"代理路径失败 → 自动改走直连"的静默降级 = 违规。

## T5 无时序/侧信道 (no timing side-channel)

**目标**:认证与握手不泄漏可被统计区分的时序信号。

- token 校验**常量时间比较** (`ct_eq`),长度不同直接不等。
- 认证失败转发伪装站的时序应与真实反代不可区分 (不引入固定延迟/固定节拍)。
- 探测响应无"15s keepalive"之类的伪命题固定节拍 (刻意不加)。

**红线**:引入任何与"是否 Mirage/认证是否通过"相关的固定/可测时序差 = 违规。

---

## 验收流程

1. 每个新功能 PR:对照 T1–T5 自检,在描述里说明命中/无关。
2. 触碰握手/DNS/路由/出站的改动:**必须**有对应 §7 场景测试或说明为何不需要。
3. 违反红线的改动**不合并**,除非有明确的、记录在案的权衡 (如 SNI 伪装为 QoS 刻意留)。

## 7. 场景/泄漏测试映射 (tests/)

抗审查代理最重要的不是单函数正确,而是**行为保证**。下列应为 CI 场景测试 (逐步补齐):

| 目标 | 场景断言 | 状态 |
|------|---------|------|
| T3 | SS 上游 UDP 默认 block,不从本机裸奔 | ✅ `tests/test_leak_guards.rs::t3_ss_upstream_udp_defaults_to_block` |
| T3/T4 | SS 上游 udp=tunnel (未实现) → check 报错不静默降级 | ✅ `::t3_ss_upstream_tunnel_udp_rejected_at_check` |
| T4 | 未知/淘汰的 fake-IP 反查 None → 调用方 drop 而非直连 | ✅ `::t4_fakeip_unknown_inrange_ip_returns_none_not_invented` |
| T4 | fake-IP 淘汰后旧 IP 无残留反查 (防误路由) | ✅ `::t4_fakeip_eviction_leaves_no_stale_reverse_mapping` |
| T2 | 被代理域名 A 查询 → fake-IP,永不走本地 UDP:53 真解析 | ✅ `config_watcher::leak_guard_tests::t2_proxied_domain_a_query_gets_fakeip` |
| T2 | 被代理域名 AAAA 查询 → 空答复,不走本地真解析 | ✅ `::t2_proxied_domain_aaaa_query_returns_empty_not_local` |
| T4 | 被 block 域名 → NXDOMAIN,不解析不泄漏 | ✅ `::t4_blocked_domain_returns_nxdomain` |
| T2 | WG 上游隧道内 DNS 解析符合预期 (不漏到本地) | 待补 (需 netns) |
| T1 | 认证失败 → 转发伪装站 (会话密钥解不开其 TLS) | 部分 (probe.rs 有相关判定) |

> 这张表是 #7 "泄漏测试变集成测试" 的施工清单。纯用户态可判定的守卫见
> `tests/test_leak_guards.rs` 与 `config_watcher::leak_guard_tests` (进程内驱动真实
> config→CoreState→DnsForwarder.resolve_query 路径, 无 netns); 需真内核/netns 的行为由
> `examples/verify_*.sh` (CI ebpf-verify) 覆盖 (UDP mux 带机量另经真机手验, 见 brain)。
