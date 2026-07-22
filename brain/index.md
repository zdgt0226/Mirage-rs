# Brain Index

_Auto-generated. Last updated 2026-07-22T03:32:45.790Z._

- [auth-ts-bootstrap-deadlock](pages/auth-ts-bootstrap-deadlock.md) — category: decision | **故障**:两端时钟偏差 >10s 时,客户端**永久**连不上 —— 服务端刷 `auth failed`,客户端刷
- [camouflage-forward-on-auth-fail](pages/camouflage-forward-on-auth-fail.md) — category: decision | **决定**:服务端握手认证失败时**不返回任何错误**,而是把该 TCP 连接**转发到真实的伪装站**
- [ebpf-scope-narrowed](pages/ebpf-scope-narrowed.md) — category: decision | **决定**:eBPF 只承担三件事 —— ① `tc_divert` 拦截转发流量并 `sk_assign` 给透明 listener;
- [external-audit-verification](pages/external-audit-verification.md) — category: concept | **观察**:本项目收到过多轮外部代码审计(12 项 / 7 项 / 5 项 / 若干单条),共同特征是
- [fakeip-remote-resolution](pages/fakeip-remote-resolution.md) — category: decision | **决定**:被代理域名的 DNS 查询返回**保留段 fake-IP**(198.18.0.0/15),真实域名随隧道送到**墙外服务端远程解析**。
- [geo-dat-parsing-robustness](pages/geo-dat-parsing-robustness.md) — category: decision | v2ray/v2fly 的 `geosite.dat` / `geoip.dat` 是 protobuf 编码的外部数据, 手写解析器踩过两处 bug, 均已修并带回归测试:
- [ipv6-v4only-tradeoff](pages/ipv6-v4only-tradeoff.md) — category: decision | **现状**:透明路径整条 **IPv4-only**。
- [mss-clamp-merged-into-tc-divert](pages/mss-clamp-merged-into-tc-divert.md) — category: decision | **决定**(`66e0262`,方案A):把 MSS clamp **内联进 `tc_divert.c`**(`clamp_tcp_mss()`),
- [no-clash-api](pages/no-clash-api.md) — category: decision | **决定**:**不做 Clash API 兼容**,走自有 API 路径。
- [no-doh-dot](pages/no-doh-dot.md) — category: decision | **决定**:**不把 DoH/DoT 当作抗审查手段**。
- [orphan-filter-blackhole](pages/orphan-filter-blackhole.md) — category: decision | **问题**:进程被 SIGKILL / 正常停止后,tc 过滤器**仍挂在网卡上**(tc 持有 prog 引用,不随进程消失),
- [ring-for-aead](pages/ring-for-aead.md) — category: decision | **决定**:隧道载荷加密用 **`ring`** 的 ChaCha20-Poly1305(`LessSafeKey` + 显式 nonce 管理);
- [routing-rules](pages/routing-rules.md) — category: concept | tags: [routing, config] | Mirage 的路由规则维度与 sing-box/Clash 基本对齐, **域名 4 种 + IP 2 种 + 连接属性 4 种 + and/or 组合**。
- [rust-rewrite-from-python-poc](pages/rust-rewrite-from-python-poc.md) — category: decision | **决定**(v0.2.x):从 Python + uvloop 的 POC 全量重写为 **Rust + Tokio** 全异步无锁流水线,
- [splice-over-sockmap](pages/splice-over-sockmap.md) — category: decision | **决定**(v0.4.5-alpha.3, `a6535e1`):直连出站的零拷贝从 **sockmap `sk_skb`** 改为 **`splice(2)` + pipe**。
- [ss-upstream-relay](pages/ss-upstream-relay.md) — category: decision | Mirage 服务端可配 `upstream` 把流量再经 Shadowsocks 发往上游, 即作中转站:
- [syn-only-sk-assign](pages/syn-only-sk-assign.md) — category: decision | **决定**:`tc_divert` 对 TCP **只在首 SYN**(`th->syn && !th->ack`)做 `bpf_sk_assign`;
- [tls-fingerprint-mimicry](pages/tls-fingerprint-mimicry.md) — category: decision | **决定**:ClientHello **字节级**仿真真实客户端,并按权重轮换多个 profile 稀释单一出口指纹:
