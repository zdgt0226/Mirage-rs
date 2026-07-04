# Changelog - Mirage-rs

## [v0.4.5-alpha.10] - UNAUTH 限流 IPv6 /64 归一 (逃逸修复) (2026-07-05)

### fix(server): UNAUTH 限流 key IPv6 归一到 /64

**背景**: 握手审计 #4. `handshake.rs` 的 auth-fail 每 IP 限流用完整 `peer_addr.ip()`
(IPv6 128 位) 做 key. 攻击者控制一个 /64 段 (家宽/VPS 常见分配) 可造 2^64 个"独立
IP", 每个用满 100 次, **完全逃逸单 IP 限流**, 把 camouflage 路径打到 GLOBAL_UNAUTH
5000 全局上限.

**修法**: 新增 `rate_limit_key(ip)`:
- IPv4 → 原样 (单地址已是最细粒度)
- IPv6 → 清零低 64 位, 归一到 /64 前缀

同一 /64 段的所有地址共享一个限流计数 → 攻击者一个 /64 只能发 100 次 auth-fail.
`IpSlotGuard` 持有归一后的 IP, Drop 时递减同一 key, 计数一致. 日志仍打印完整
`peer_addr` (定位真实来源不受影响).

/64 是 IPv6 最小终端分配单位 (RFC 6177), 按 /64 归一既拦得住段内洪泛, 又不会误伤
不同真实用户 (不同用户在不同 /64).

### 影响面

- 仅服务端 auth-fail 限流路径; 正常认证/客户端不受影响
- 非破坏性, 无协议/配置变化

## [v0.4.5-alpha.9] - 透明代理 fake-IP 本地路由自动管理 (网关拦截修复) (2026-07-04)

### fix(transparent): sk_lookup 网关/客户端拦截静默失效的根因修复

**审计发现**: sk_lookup 只在内核【本地投递路径】的 socket 查找时触发, 而路由
决策发生在它之前 (`ip_route_input` → `ip_local_deliver` vs `ip_forward`).
fake-IP (198.18.0.0/15) 在网关/客户端上默认**不是本机地址**:

- **网关转发场景**: LAN 设备发 fake-IP 包到网关 → 内核判定"转发" → 走 ip_forward
  → 绕过本地投递 → **sk_lookup 从不运行** → 包发往默认路由 → fake-IP 不可路由丢弃
- **客户端本机场景**: app connect(fake-IP) → 输出路由走默认 → 不回本地投递 →
  sk_lookup 同样不触发

即透明拦截**静默失效**. 之前若"能用"大概率是测试环境外部/手动加过 local 路由.

**根因**: 缺一条把 fake-IP 段标记为本机可投递的路由. 全仓库 (install.sh /
Rust / systemd / README) 都没有设置它.

### 修法: 自动管理 (`transparent_net.rs` 新增)

fake-IP 透明代理启用时 (`start_transparent` attach sk_lookup 成功后) 自动装:
```
ip route replace local <fakeip_net>/<prefix> dev lo
```
让内核把 fake-IP 段当本机可投递 → 包进 socket 查找路径 → sk_lookup 触发 →
bpf_sk_assign 到 mirage listener. 进程退出 (SIGTERM/ctrl_c) 时 `ip route del`
清理. **用户无感, 跟随 fake-IP 开关生命周期** (dae/sing-box/clash 同款做法).

- `ip route replace` 幂等 (已存在不报错)
- 装失败仅 warn 不 panic (提示需 CAP_NET_ADMIN)
- 退出清理 best-effort (失败无害: fake-IP 不可路由, mirage 停后 DNS 也不再下发)

### 只装严格必需的一条路由

- **不碰 rp_filter**: 它校验的是【源地址】(LAN 客户端合法可达), fake-IP 是目标
  地址, 不受影响 —— 之前审计报告里担心的 rp_filter/martian 实际不触发
- **不碰 ip_forward / NAT**: 那是直连流量转发的网关级配置, 与 sk_lookup 拦截
  无关, 由用户/install.sh 另行负责 (`sysctl net.ipv4.ip_forward=1` +
  `iptables MASQUERADE`)

### 影响面

- 只在透明代理 + fake-IP 启用时生效; SOCKS5/HTTP/Mixed 入站不受影响
- 需要进程有 CAP_NET_ADMIN (透明模式本来就要 root 跑 eBPF attach, 权限已具备)
- 非破坏性, 无协议变化, 无配置迁移

## [v0.4.5-alpha.8] - 直连 DNS 缓存 + IPv4 优先 (国内延迟修复) (2026-07-04)

### perf(proxy): connect_smart 替代裸 TcpStream::connect(域名)

**现网诊断** (客户端 Alpine musl):
```
getent hosts jra.jd.com   → 0.12s  (DNS 解析 120ms)
curl -4 connect            → 0.065s (拿到 IP 后连接快)
IPv6                       → 受限
```

**根因**: musl libc 无内建 DNS 缓存, Alpine 默认无 nscd/systemd-resolved.
`handler.rs` Direct 分支 `TcpStream::connect(域名)` 每连接走一次完整 getaddrinfo
(~120ms, GSLB/CDN 域名更慢). 一个网页 200 子请求, 未缓存域名各 +120ms → 累积
秒级延迟. 透明代理模式下浏览器自己缓存 DNS 所以感觉快, SOCKS5h 模式把域名甩给
mirage 现场解析, 压力堆在连接热路径.

此外 tokio `TcpStream::connect` 顺序试地址无 Happy-Eyeballs, 域名有 AAAA 记录 +
IPv6 受限时会 hang 在 v6 尝试.

### 实现 (`resolver.rs` 新增)

- **DNS 缓存**: 解析结果按 60s TTL 缓存, 重复访问 0 网络开销. 容量上限 8192,
  超限先清过期项, 仍超则整体清空 (有界)
- **IPv4 优先**: 解析结果 stable sort v4 在前, 受限 IPv6 网络不 hang 在 v6
- **每尝试 3s 超时**: 单个坏地址 (如不通的 v6) 不拖垮整体, 快速 fallback 下一个
- **IP 直连短路**: target 本身是 IP 字面量 (如 180.101.49.44:443) 直接连, 不解析
  不缓存, 保持原 6ms 快路径

只改 Direct 分支 (`handler.rs`), Mirage 隧道出站不受影响 (target 域名由服务端解析).

### 60s TTL 权衡

GSLB/CDN (如 *.gslb.qianxun.com) IP 会轮转, 60s 缓存平衡"重复访问加速"与"IP
新鲜度". 家用/网关域名基数下缓存表内存可忽略.

### 未覆盖 (记录)

- 服务端 `tcp_relay` 也 `TcpStream::connect(域名)`, 但服务端通常在机房 DNS 快,
  暂不加缓存. 若未来服务端也慢再补.
- 未做真 Happy-Eyeballs (v4/v6 并发赛跑). 当前"v4 优先 + 每尝试超时"对受限 IPv6
  场景已足够, 且更简单. 若未来遇到 v4 慢 v6 快的场景再升级.

## [v0.4.5-alpha.7] - Mirage 协议握手三项安全强化 (2026-07-04)

### ⚠️ 破坏性变更: 客户端 + 服务端必须同步升级到 alpha.7+

Fake Client Finished tail 尺寸从 63B → 64B (Body 52 → 53). 旧版客户端连接新版
服务端会被 read_exact 卡 5s 超时后 close, 反之亦然. 必须成对升级.

### fix(server): ClientHello 精确 5B header + body 分段读取

**背景**: 老版 `stream.read(&mut vec![0u8; 1024])` 一次性读最多 1024B, 遇到:
- iOS Safari 完整 ECH + Encrypted SNI 扩展 → ClientHello ~1300B
- Chrome 带 4 个 QUIC ALPN + PSK ticket → ~1200B
- 会被截断 → auth 校验虽然能过 (session_id 在前 76B), 但转发到 camouflage_host
  时是**残缺 ClientHello**, 触发对面回 TLS alert, camouflage 路径失败

**修法** (`handshake.rs`):
```rust
let mut header = [0u8; 5];
stream.read_exact(&mut header).await?;
let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
if record_len > 16384 { return; } // RFC 8446 §5.1 硬 cap 2^14
let mut body = vec![0u8; record_len];
stream.read_exact(&mut body).await?;
```

TLS 记录最大合法长度 16384 (2^14), 超出即恶意报文, 静默丢包不给 camouflage
消耗对面连接. `client_random` / `session_id` offset 全部从 `body` 相对偏移
重新推导, 边界更清晰.

### fix(crypto): Fake Client Finished tail body 52 → 53B

**背景**: `build_fake_client_tail()` 假 Finished 密文体固定 52B, 但真实 TLS 1.3
Client Finished (ChaCha20-Poly1305 + SHA-256 HMAC) 加密后 record body 是:
```
4B handshake header + 32B HMAC digest + 1B content_type + 16B AEAD tag = 53B
```

52 → 53 后跟主流浏览器 Client Finished record body 长度分布完全一致, 消除
DPI histogram 潜在识别特征.

### feat(server): CamouflagePool 预热连接池, 消除 auth-fail 分支时序侧信道

**问题**: auth-fail 分支需要 `TcpStream::connect(camouflage_host:443)` 新建 TCP,
1 个 RTT (5-100ms) vs auth-succ 分支的本地模板拷贝 (~0-1ms). GFW 用大量样本
统计首字节返程时间可分类为 mirage 服务器.

**修法** (`camouflage_pool.rs`):
- 后台 task 维护 8 条 pre-warmed TCP 连接到 camouflage_host:443
- 500ms 补给间隔, 10s max_age 淘汰 (camouflage_host 通常 30s idle timeout, 留余量)
- 3s connect 超时, 对面抖动时不 hammer
- auth-fail 时 `pool.acquire()` 抢一条已建 TCP → 无 3-way RTT
- 池空 fallback 到即时 connect (跟老版行为一致)

**残余时序差**: 仍有 1 个 RTT (camouflage_host 回 ServerHello) 无法消除. 完全对齐
需要 auth-succ 分支延迟注入, 权衡后**暂不做** — 会增加合法用户 WarmPool 补给
延迟, 且残余 RTT 差异对 GFW 需要成千上万样本才能识别, 单个用户不足以触发.

### fix(crypto): ReplayCache 满桶 fail-closed (拒绝) 而非 bypass (放行)

**攻击场景**: 老版满桶 (>100k) 时直接 `return true` 放行, 攻击者 DDoS 拉高
认证请求量填桶后, 就能**无限重放**截获的合法 token 直到桶回落到阈值以下.

**修法** (`hello_auth.rs`): 满桶 → `return false` (拒绝). 满桶期间合法 token 也会
被误判重放, 但同时攻击者的 replay 也被拦, 保守安全 > 可用性.

100k 桶 = 60s 内 10 万个不同 token, 正常业务不可能触发, 只有 DDoS 才可能碰到,
拒绝是对的.

### 未修的 (残余风险, 记录):

- **UNAUTH 限流对 IPv6 无效**: `map.entry(peer_addr.ip())` 用完整 IPv6 (128 位) 做
  key, 攻击者控制 /64 段可造 2^64 独立 IP 逃逸. IPv6 应按 /64 或 /48 归一.
  留 alpha.8+ 修.
- **auth-succ 路径残余 1 RTT 时序差**: 见上面 CamouflagePool 段末. 需要 config
  开关 + startup 测 camouflage RTT + auth-succ delay_injection. alpha.8+.
- **客户端 `read_server_handshake` 12s / 1.5s 固定超时**: 客户端行为指纹, GFW
  观察客户端断连时间可识别. 优先级低, 客户端行为不是主要防御面.

## [v0.4.5-alpha.6] - splice idle watchdog 时钟单调化 (NTP 前跳防御) (2026-07-04)

### fix(proxy): ActivityTracker 从 SystemTime 换成 Instant 单调时钟

**背景**: alpha.4 引入 `ActivityTracker` 时用 `SystemTime::now().duration_since(UNIX_EPOCH)`
拿墙钟秒数. `saturating_sub` 已经防了倒流下溢, 但**前跳**没防:

- **VM 启动 RTC 不准 → NTP 突然 +30 分钟同步**: watchdog 计算 `idle_secs =
  now(墙钟) - last_touch(旧墙钟) > 900s`, **所有活跃连接被瞬间误杀**
- **VM 从 suspend 恢复**: 墙钟跳过 suspend 时长, 同样触发误杀 (虽然此场景
  连接可能确实死了, 但决策不该建立在墙钟上)

### 实现

```rust
fn monotonic_secs() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    ORIGIN.get_or_init(Instant::now).elapsed().as_secs()
}
```

- 首次调用初始化 `ORIGIN = Instant::now()` (进程启动基准)
- 之后所有 `touch()` / `idle_secs()` 都读相对秒数
- Linux 底层 `CLOCK_MONOTONIC` — 免疫 NTP 前后跳

### 副作用 (合理不改)

Linux `CLOCK_MONOTONIC` **不计 suspend 时长** (kernel 4.17+ 明确). VM 从
suspend 恢复后:
- SystemTime 视角: 已过了 20 小时, 连接被认为 idle 20h → 误杀
- Instant 视角: elapsed() 只涨了 suspend 前的相对时间 → 连接被视为"刚活跃过"

后者更合理 — 恢复后用户的第一个请求正常, 之后 15 分钟无活动才被淘汰。若真
需要计入 suspend 时长, kernel 有 `CLOCK_BOOTTIME` 可用, 但 Rust std::Instant
用的是 `CLOCK_MONOTONIC`, 目前 stable API 无法切换, 也无必要。

### 影响面

- 只有 splice_relay 里的 idle watchdog 用 tracker, 无外部 API
- 无配置迁移, 无行为破坏 (只修 NTP 边界)
- 对于 RTC 稳定的机器 (物理服务器 / 校时准确的容器), 表现跟 alpha.4 完全一致

## [v0.4.5-alpha.5] - splice pipe pool + 详细 debug 日志 (2026-07-03)

### perf(proxy): 加 pipe pool 复用, 消除每连接 pipe2()+F_SETPIPE_SZ() syscall

学 dae `control/tcp_copy_linux.go::relaySplicePipePool`:

- `OnceLock<Mutex<VecDeque<Pipe>>>` 静态 pool, 容量 64
- `acquire_pipe()` 先 pop_front, 无则 fallback 到 `Pipe::new()` (含 pipe2 +
  F_SETPIPE_SZ 两次 syscall)
- `release_pipe()` 归池, 池满则 Drop 关 fd, 无上限阻塞
- `PipeGuard` RAII: 出错走 Drop 关 fd; 成功走 `finish()` 归池 (成功路径
  in_pipe 保证为 0, 无残留数据)
- POOL_HITS / POOL_MISSES 全局 atomic, 供 debug 日志读

**收益**: 高频短连接场景 (每连接 2 个 pipe) 从 4 次 pipe 相关 syscall 降到 0.
低频场景无变化 (fallback 到 new 路径). dae 用同样机制, 生产验证过。

### fix(proxy): byte accounting 从函数末尾移到 splice 内部

alpha.4 的 `crate::monitor::add_up(n)` 在 `splice_one_way` 返回 Ok 后统一
调用 — 出错时 partial 字节数丢失。改为每次 `pipe→dst` 成功后立即 `counter(m)`,
出错也保留已传输的 partial:

```rust
async fn splice_one_way(..., counter: fn(u64)) -> io::Result<u64> {
    ...
    counter(m as u64); // 每 chunk 立即上报, 无 buffered 丢失
    ...
}
```

`splice_relay` 传 `crate::monitor::add_up` / `add_down` 函数指针, 类型安全,
无 closure lifetime 复杂度。

### feat(proxy): Direct 分支 debug 日志加详细字段

从

```
Direct splice relay to <target> closed: up=<N>B down=<N>B
```

改成

```
splice open: peer=<addr> target=<host> initial=<N>B connect=<M>ms
             pool_hits=<H> pool_misses=<M>
splice close: peer=<addr> target=<host> up=<N>B down=<N>B relay=<M>ms
              total=<M>ms pool_hits=<H> pool_misses=<M> pool_idle=<L>
splice err: peer=<addr> target=<host> reason=<class> err='<msg>'
            relay=<M>ms total=<M>ms
```

`reason` 分类: `idle_timeout` | `timeout` | `conn_reset` | `conn_aborted` |
`unexpected_eof` | `broken_pipe` | `write_zero` | `other`。

网关运维观察点: peer_addr 定位客户端, pool_hits/misses 看池命中率是否合理,
duration 分布定位慢查询, reason 分布定位问题类型。

### 无 API/config 变化, 向前兼容

pipe pool 完全内部实现, splice_relay 签名不变。debug 日志格式改变但只有
运维人肉观察, 无自动化 parser 依赖。

## [v0.4.5-alpha.4] - splice_relay idle timeout (透明网关场景准备) (2026-07-03)

### feat(proxy): splice_relay 加双向共享 idle timeout

**背景**: alpha.3 上线后 splice_relay 无任何 idle timeout — SOCKS5 客户端本地
场景下 keepalive + 短会话足够, 但**下一阶段计划让 Mirage 承担透明代理网关**
角色, 网关场景下僵尸连接会啃 fd + 内核内存, 需要主动止损. 参考 dae 也有
`relayCore.forceClose()` 靠外层 SetReadDeadline(past) 主动打断.

### 设计

- `ActivityTracker` 一个 `AtomicU64` (epoch 秒), 双向共享
- 每次 `splice()` 成功 (n > 0) 后 `tracker.touch()` — 热路径无锁, 性能可忽略
- `idle_watchdog` 每 30s 检查一次, 双向都静默 > 15 分钟 → 返回 TimedOut
- `splice_relay` 用 `tokio::select!` 包 `try_join!(up, down)` + `watchdog`,
  watchdog 触发时立刻取消双向 futures, sockets 走 Drop, kernel fd 自动释放

### 为什么是"双向共享"而非"每向独立"

若每向独立, HTTP 大文件上传场景 (up 忙, down 静默 20 分钟) 会误杀 down 方向.
双向共享确保**任一方向活跃就整条连接不 idle**, 只有真正双向都死才回收.

### 权衡: 15 分钟阈值

- 传统 SSE 心跳: 30s-5 分钟 → 安全
- WebSocket ping frame: 一般 30s-60s → 安全
- HTTP long-poll: 通常 25-30s → 安全
- 严重卡的 API (罕见 batch 处理 > 15 分钟) → 会被误杀, 但这类 API 本就该
  改设计, 不算合理场景

超时阈值可以未来提到 config, 目前硬编码常量即可.

### 影响面

- Direct 分支的 SOCKS5 客户端场景: 短连接不受影响, 长连接会在 15 分钟静默
  后被强关 (以前会挂到内核 keepalive 2 小时超时)
- 未来透明网关: 直接受益, 网关连接密度高时特别重要
- 无 API 变化, 无配置迁移

### 未做的

- 硬 max_lifetime cap (例如 24h 强制关) — 目前不需要, idle 足够兜底
- 配置化超时阈值 — 硬编码常量, 上生产观察后再决定要不要暴露
- 分方向独立超时 — 前述反例排除

## [v0.4.5-alpha.3] - 直连零拷贝换用 splice(2)+pipe (参考 dae) (2026-07-03)

### fix(proxy): sockmap sk_skb 数据面全部删除, 改 splice(2)+pipe

**背景**: alpha.1 顺序修 + alpha.2 bpf_printk 诊断跑完后, 现网仍然复现 "verdict SK_PASS
4 次但 curl 0 字节". 参考 dae 源码 `control/kern/tproxy.c:178` 官方注释:

> "BPF_PROG_TYPE_SOCK_OPS + BPF_PROG_TYPE_SK_MSG (bpf_msg_redirect_hash) combination
>  has been proven to cause Kernel Panic. We use TC-based redirect instead."

dae 团队在 sk_msg 侧遇到 kernel panic, 明确放弃整套 sockmap redirect 家族; 我们的
sk_skb + `bpf_sk_redirect_hash` 共享同一 sk_psock 底层, 表现是"静默丢包"而不是 panic,
但本质是同类问题, kernel 6.x 上不可靠。

### 换掉的技术方案

dae 数据面真身 = `control/tcp_copy_linux.go::relaySpliceCopyExact`:
- `pipe2(O_CLOEXEC | O_NONBLOCK)` 建 pipe
- `fcntl(F_SETPIPE_SZ, 256KB)` 设 pipe 缓冲
- `splice(src_sock, pipe_w, SPLICE_F_MOVE | MORE | NONBLOCK)` — 从 src socket 搬 page 到 pipe
- `splice(pipe_r, dst_sock, ...)` — 从 pipe 搬 page 到 dst socket
- 无 userspace 中转, kernel 只搬 page 引用, **真正零拷贝**

Mirage 客户端 SOCKS5 场景不需要 dae 的 tc-bpf 路由 (客户端主动 opt-in), 只搬数据面
到 splice 就够了。

### 具体改动

- **删** `src/ebpf/mod.rs::register_splice()` (aya SockHash 一整套)
- **删** `src/ebpf/mod.rs::init()` 里 SkSkb attach + sockmap fd
- **删** `ebpf-src/sockmap.c::mirage_stream_verdict` (SEC sk_skb) + `mirage_sockmap` (SOCKHASH)
  + `mirage_bpf_stats` (PERCPU_ARRAY) + alpha.2 bpf_printk
- **删** `src/proxy/handler.rs::proxy_tcp_target` Direct 分支 alpha.1 的 register_splice
  顺序修 + epoll RDHUP 等待循环 (共 ~90 行)
- **新增** `src/proxy/splice.rs`: `splice_relay(local, target)` 双向 tokio::try_join,
  每方向独立 256KB pipe, `TcpStream::async_io` 处理 EAGAIN 重试
- `EbpfEngine::get_stats()` 保留签名返回 `Ok((0, 0))`, sampler.rs/GUI 图不用改, 显示
  稳定 0 (新架构下 BPF fast-path counter 无语义)

### 保留的 eBPF 功能 (未受影响)

- ✅ `mirage_sockops` + `mirage_rtt_map` + `mirage_target_ips` — Brutal CC 动态速率反馈
- ✅ XDP DNS 加速 (`dns_xdp.c`, `mirage_dns_cache`)
- ✅ 服务端 `sk_lookup` 透明代理 (跟 sockmap redirect 是完全不同的 API)

### 客户端配置

`install.sh` `ebpf_mode: "off"` (alpha.7 起的临时 workaround) 可以在 alpha.3 上手工
测试 OK 后恢复 `"auto"`, 因为 alpha.3 不再依赖 sockmap 数据面, sockops+RTT 是纯反馈,
安全。

### 测试计划

1. cachefly 100MB 下载 (alpha.25 基线 25.8Mbps) — 期望 splice(2) 至少等同
2. `curl -x socks5://127.0.0.1:3180 https://www.baidu.com -o /dev/null -m 30` — 期望
   200 状态码, 非 0 字节, 无 timeout
3. `curl ... https://api.m.jd.com/...` — .cn 直连域名, 期望正常
4. YouTube 4K 播放 — 期望缓冲流畅 (走 Mirage 隧道, 直连路径不影响它)

## [v0.4.5-alpha.2] - eBPF verdict trace_pipe 诊断 (临时调试, 非生产) (2026-07-03)

### debug(ebpf): sockmap.c verdict 加 bpf_printk

alpha.1 顺序修复上线后现网仍复现: `curl -x socks5://... https://baidu.com -m 5`
超时 0 字节. bpftool 读 mirage_bpf_stats 显示 key=0 (SK_PASS) = 4, key=2 (SK_DROP) = 0.
矛盾: verdict fire 且 redirect_hash 声明成功, 但数据一字节都不到 curl.

**加 bpf_printk 定位 cookie/len/ret 真实值**:
```c
bpf_printk("verdict: cookie=%llu len=%u ret=%d", cookie, len, ret);
```

诊断步骤:
1. 客户端 `sudo cat /sys/kernel/debug/tracing/trace_pipe`
2. 另开 shell `curl -x socks5://127.0.0.1:3180 https://www.baidu.com -o /dev/null -m 5`
3. trace_pipe 输出的 cookie 值对比 `eBPF SockMap: spliced local_cookie=X <-> remote_cookie=Y`
   - 如 verdict 里 cookie 完全不匹配 Rust 日志 → cookie 语义错
   - 如匹配但 ret=SK_PASS 但数据不通 → EGRESS 方向反了 (需切 BPF_F_INGRESS)
   - 如 len 为 0 → skb 是空包 (只 TCP 控制帧, ACK 之类)

**警告**: bpf_printk 有 buffer 抢锁 + string table 开销, 每次生产化前 remove.

## [v0.4.5-alpha.1] - eBPF SockMap 零拷贝直连修复 (P0 长期未解 bug 根治) (2026-07-02)

### fix(ebpf): register_splice 顺序竞态修复

**背景**: alpha.7 (2026-06-24) 起 install.sh 客户端默认 `"ebpf_mode":
"off"` 因为发现 SockMap 直连零拷贝转发不工作: `register_splice()` 声
明"activated"但数据永远不流动, 浏览器超时。alpha.7 只是临时禁用整
个 BPF 客户端功能作为 workaround, 真正 root cause 未修. 影响:
- 直连 (.cn 域名) 走用户态 Tokio, 失去零拷贝加速
- 客户端 sockops RTT 反馈不可用, 动态 brutal CC 无法启用
- XDP DNS + sk_lookup 透明代理全部功能被停用

### 根因诊断

`src/proxy/handler.rs::proxy_tcp_target` 的 Direct 分支老顺序:
```
1. target_stream.write_all(&initial_payload)  ← 发到 target
2. (0-N ms 时间窗)                             ← 竞态窗口
3. register_splice(local, target_stream)      ← sk_psock 才安装到 target RX
4. epoll wait EPOLLRDHUP                      ← 只等 close
```

target (小 HTTP 请求场景, 如 .cn 门户站) 通常在 < 1ms 回响应, 响应
到达 target socket RX 队列时 sk_psock 还没安装, 数据被跳过 verdict
拦截. 然后 sk_psock 装好后已经在队列里的这段数据无人读 (handler
仅 epoll wait 不做 recv), 就永久卡在 kernel RX buffer 里. 客户端超
时后连接断开.

### 修复

`src/proxy/handler.rs:270-306` 交换 register_splice 和 write_all 顺序:
```
1. register_splice(local, target_stream)  ← 先装 sk_psock
2. target_stream.write_all(&initial_payload)  ← 用 target TX 路径, sk_psock 不拦
3. epoll wait                              ← target 响应到 RX 时 sk_psock 就位, verdict 立即 redirect
```

**为什么 write_all 在 register_splice 后仍能工作**: sk_skb/stream_verdict
BPF 程序只拦截 RX (received data) 路径, TX (send/write) 完全不受影响.
Tokio 的 `write_all` 走 tcp_sendmsg 直接送 kernel TX buffer, 与
sk_psock 的 RX 拦截正交.

### install.sh: 客户端 config 默认 ebpf_mode 改回 auto

`install.sh:754` 从 `"off"` 改回 `"auto"` (alpha.7 之前的原值). server
仍自动 skip BPF, 只有 client 启用. 新装用户直接享受零拷贝直连.

老用户 (config 里手动 `"ebpf_mode": "off"`) 升级后需要手动改成
`"auto"` 才生效:
```bash
sed -i 's/"ebpf_mode": "off"/"ebpf_mode": "auto"/' /etc/mirage-rs/config_client.json
sudo systemctl restart mirage-rs-client
```

或重跑 `install.sh` 让脚本重新生成 config.

### 影响 (再启用后恢复的功能)

- ★ 直连零拷贝 (Router 命中 direct outbound 时 kernel-side splice)
- sockops RTT_CB 收集 → 动态 brutal CC 速率调节 (客户端出站)
- XDP DNS 高速解析
- sk_lookup 透明代理 (kernel ≥ 5.9)

### 版本序列变化

v0.4.4-alpha (25 个 alpha 版本, 修了海量 bug + IO 性能) → **v0.4.5-alpha.1**
新序列开始, 主题是"eBPF 全栈重启用". 后续 alpha 若稳可能直接发 v0.4.5
stable.

## [v0.4.4-alpha.25] - 撤回 alpha.21 的显式 SO_SNDBUF/SO_RCVBUF (7× 回归元凶) (2026-07-01)

用户实测 alpha.21+ 相比 alpha.20 出现 **7× 吞吐回归** (Cloudflare 15
Mbps → 2 Mbps). 二分定位: alpha.22 已慢, 罪魁在 alpha.21 加的显式
`setsockopt(SO_SNDBUF/SO_RCVBUF = 8MB)`.

### 根因

Linux 上手动 `setsockopt(SO_SNDBUF/SO_RCVBUF)` 会**disable TCP window
auto-tuning**. auto-tune 会根据实际 BDP + 观测丢包动态调节窗口, 是
现代 Linux 的默认 (通常表现最优). 手动固定 8MB 反而在**高丢包链路**
(用户 iperf3 测出 7% 丢包) 造成 bufferbloat:

- 8MB 窗口 → TCP 允许 8MB in-flight
- 高丢包 → 大量重传排队在 8MB buffer 里
- BBR/brutal 都被拖垮, 有效吞吐掉 7×

alpha.20 没有这段代码, kernel auto-tune 智能调节, 因此稳定 15 Mbps.

### 修改

三处 socket 全撤回:
- `src/proxy/mirage_server/mod.rs`: server accept socket (server→client 方向)
- `src/proxy/mirage_server/tcp_relay.rs`: server upstream socket (server←YouTube)
- `src/proxy/pool.rs`: client outbound socket (client←server)

保留 alpha.21-24 的其他改动:
- server 读缓冲 16→64 KB (无副作用)
- alpha.22 header+body 合并 write_all (纯优化)
- alpha.23 CryptoWriter BufWriter + greedy try_read + 撤 mpsc
- alpha.24 BufWriter 容量 68KB 修算

### 教训

"手动置大值 disable auto-tune" 这种"性能优化"在**理论上正确, 实际上
灾难**. Linux TCP auto-tuning 是几十年优化沉淀的成果, 手动覆盖需要
非常精确的针对场景分析, 通用场景一律不动最好.

## [v0.4.4-alpha.24] - BufWriter 容量算错 22B×N 加密开销 (外部审计) (2026-07-01)

### fix(crypto): WRITER_BUF_CAPACITY 65536 → 68 * 1024 (69632)

外部审计精确定位: alpha.23 `WRITER_BUF_CAPACITY = 65536` **漏算了每
帧的 22 字节 AEAD/TLS 封装 overhead**, 满载时 syscall 不聚合.

### 数理推演 (逐位复核 aead.rs 源码)

单帧密文封装:
- 5 字节 TLS Header `[0x17, 0x03, 0x03, len_hi, len_lo]`
- chunk_len 字节明文
- 1 字节 inner content type `0x17` (encrypted with tag)
- 16 字节 Poly1305 tag (append after encrypt)

每帧 overhead: **22 字节**.

### Worst case 演练

上游 `tcp_relay::buf = vec![0u8; 65536]`, greedy 填满 65536 明文
后送 `send_data(65536)`. send_data 内部 chunk size 是 rng 三分桶
(50%=16384, 35%=8192, 15%=4096):

- 4 帧 16KB: 4 × 16406 = 65624 bytes (外部审计的例子)
- 16 帧 4KB (worst): 16 × 4118 = **65888 bytes** (更极端)

老 65536 容量:
- 前 3 帧 16KB 后 buffer 49218 已用
- 第 4 帧 16406 加入: 65624 > 65536 → BufWriter **flush 前 49218 一次
  syscall**, 剩 16406 buffer
- 末尾 `flush()`: 剩 16406 syscall 二次

**满载退化为 2 次 syscall**, 原本设计目标 1 次 syscall 打空.

### 修改

`const WRITER_BUF_CAPACITY: usize = 68 * 1024` (69632 bytes).

覆盖 65888 worst case + 3744 bytes headroom (未来提高 tcp_relay buf
到 65KB+ 也不必再改).

### 自审: 是否其他 send_data 调用点会超 65536

全项目 grep 确认:
- `src/proxy/mirage_server/tcp_relay.rs`: buf 65536 ✓ (主要用例)
- `src/proxy/handler.rs` upload: buf 16384 ✓ 远小
- `src/proxy/udp_relay.rs` (client): 小 UDP 帧 ✓
- `src/proxy/mirage_server/udp_relay.rs`: 小 UDP 包 ✓
- healthcheck / dns / control: 小控制帧 ✓

无其他大 send_data 输入, 68KB BufWriter 全覆盖.

## [v0.4.4-alpha.23] - BufWriter 内嵌 + server 贪婪 try_read + 客户端撤 mpsc (2026-07-01)

外部审计三方向剩余两项落地, 加上 alpha.21 客户端 mpsc 方案的撤回.

### feat(crypto): CryptoWriter 内嵌 tokio::io::BufWriter(64KB)

`src/crypto/aead.rs::CryptoWriter` 内部 `writer: W` 改为
`writer: BufWriter<W>`, 容量 64KB = 4× MAX_RECORD_SIZE.

send_data 处理一次 64KB plaintext 会内部拆 4 帧, 4× `write_all(framed)`
之前直接 4 次 syscall, 现在攒到 BufWriter 里, 末尾 flush() 一次
syscall 送出 64KB.

**关键: caller 契约完全不变**. send_data 尾部保留 flush() 主动 drain
BufWriter, healthcheck / dns / control / handler 所有 caller 全部无
需修改. BufWriter 的收益仅在 send_data 内部多帧写入时体现 (一次
send_data 处理大 plaintext), send_data 一次少 plaintext 时 flush 立即
drain 也不留任何数据.

### feat(server): tcp_relay download 用 try_read 贪婪收割 upstream

alpha.21 加大 read buf 到 64KB 只解决"能装多少", 没解决"每次装到多少":
tokio `read()` 只返回 kernel recv buffer 当前现成的数据, 剩下的等下
一轮 poll. 长 BDP 链路 kernel 里可能连续来了 64KB 但一次读只拿 8KB.

改法: blocking `read` 拿第一片后, 立刻 `try_read` 非阻塞收割 kernel
里剩余数据, 填满 64KB 或 WouldBlock 为止. 一次 `send_data(64KB)` 大
批送出 → CryptoWriter BufWriter 里 4 帧合成 1 syscall.

打破"读一片写一片"串行的碎片化.

### fix(handler): 撤回 alpha.21 的 mpsc channel 批量方案

外部审计明确指出: alpha.21 的 `mpsc::channel(32)` + producer/consumer
+ `try_recv` 攒 batch, 实际上被 tokio 抢占调度 立刻唤醒 consumer,
`try_recv` 大多找不到后续帧, 批量失效, 往往还是一帧一写.

alpha.23 撤回改回直连 `recv_data → write_all` 一对一 pattern. 简洁
+ 分析师验证无副作用. 真正的批量优化在服务端 CryptoWriter BufWriter
和 tcp_relay try_read 两处. 客户端接收侧因 CryptoReader 的 read_exact
语义无法安全加 try_recv (中途取消会丢帧半读), 保持一对一最稳.

### 综合预期

alpha.21 三方向 + alpha.22 concat + alpha.23 三处 联合起来:
- 服务端 syscall 数量: 每 64KB 从 9 次 (2 write + 1 flush × 3 帧) →
  1 次 (BufWriter 攒 3 帧 + flush drain)
- 服务端 read syscall 数量: 每 burst 从 4 次 (4 个 read) → 1 次
  (1 read + 3 try_read 非阻塞)
- 客户端复杂度: 撤 mpsc 后代码更简洁, 少 1 个 tokio task 少 1 个
  channel, 少内存占用

期望 rwnd_limited 从 alpha.22 的中间值 → 接近 POC 的 <5%.

## [v0.4.4-alpha.22] - CryptoWriter 单次 write_all 消除 3× syscall 碎片化 (2026-07-01)

外部审计指出核心 IO 瓶颈: `CryptoWriter::send_data` **每帧两次
`write_all` + `flush`**, 在 `TCP_NODELAY=on` 下 kernel 每次 `write_all`
都触发独立 segment 发送, 网络流量严重碎片化 (5B header + N KB body
分成两个 packet 各带 40B TCP header + IP header, per-byte 开销爆炸).

### 修改

- `CryptoWriter` 加 `framed: Vec<u8>` (预分配) 作出线组帧临时区
- `send_data` 每帧构造 `framed = [5B header, encrypted_body]`, 一次
  `write_all` 送出. Header 不再单独 `write_all`
- `send_close_notify` 同样合并 (但保留 flush, 因为终态需要立即刷网络层)

### 效果

单帧 syscall 数: `2× write_all + flush` → `1× write_all + flush`.
combined with TCP_NODELAY: kernel 每帧发一个 segment (16 KB), 而不是
两个 (5 B + 16 KB), 减少 TCP/IP header 开销, 提高 payload 占比.

### 未完成的分析师建议 (留 alpha.23)

分析师还提出:
- **方向一 Part 2**: 用 `tokio::io::BufWriter(64KB)` 内嵌 CryptoWriter,
  多帧写入自动聚合为一次 syscall (需重构 send_data flush 策略)
- **方向二**: 服务端 tcp_relay + 客户端 handler 用 `try_read` 贪婪收割
  kernel recv buffer 数据攒到 64KB 再一次 send. 打破"读一帧就等一帧"
  串行 (alpha.21 的 mpsc channel 方案分析师指出被 Tokio 调度器立即
  唤醒 consumer 导致批量失效)

先测本版单点改动效果, 再决定 alpha.23 深度重构范围.

## [v0.4.4-alpha.21] - IO 大缓冲 + producer/consumer 批量 (rwnd_limited 67% → 期望 <10%) (2026-07-01)

用户实测发现: 客户端 tcp 长连接 `rwnd_limited 67%` 卡住, brutal 有力
使不出. POC 版本同链路只有 2-5% rwnd_limited. 三方向系统性改造:

### 方向 1: server upstream 读缓冲 16KB → 64KB

`src/proxy/mirage_server/tcp_relay.rs:98`:
- 老 `let mut buf = [0u8; 16384];` — 单次 syscall 只搬 16KB
- 新 `let mut buf = vec![0u8; 65536];` — 一次搬 4× 数据, 减少 poll cycle 开销

用 vec! 而非 [_;N] 数组: tokio task 栈不大, 64KB 大对象放堆上更稳.

### 方向 3: 显式设 SO_SNDBUF / SO_RCVBUF = 8MB (三处 socket)

老代码只在 client outbound 设了 SO_SNDBUF=4MB, 其他 socket 完全靠
kernel auto-tune. Auto-tune 有慢启动, 长 BDP (200ms × 40Mbps ≈ 1MB)
链路起手 buffer 太小 → advertised window 撑不开 → rwnd_limited.

三处补 setsockopt (全 8MB):
1. **`src/proxy/mirage_server/mod.rs`** accept socket: SO_SNDBUF +
   SO_RCVBUF — server→client 视频下载主方向
2. **`src/proxy/mirage_server/tcp_relay.rs`** upstream socket:
   SO_SNDBUF + SO_RCVBUF — server 从 YouTube 等上游拉数据方向
3. **`src/proxy/pool.rs`** client outbound socket: SO_SNDBUF 从 4MB 抬到
   8MB, 新增 SO_RCVBUF = 8MB — server → client 视频下载客户端接收方向

8MB 匹配 install.sh `optimize_sysctl` 已经设的 `net.core.{rmem,wmem}_max
= 8388608`. kernel 内部会 clamp 到 cap, 代码有 getsockopt 校验实际值,
拿不到时 warn 一次提示用户重跑 install.sh 或手动 sysctl.

### 方向 2: client download 循环 producer/consumer + 64KB batching

`src/proxy/handler.rs` proxy_tcp_target 里 mirage outbound 的 download
分支:

- 老 `loop { recv_data().await → write_all().await }` 串行, 读到 1
  帧就得等 write 完再读下一帧, kernel recv buffer 排空慢
- 新: 单 task 读进 `mpsc::channel(capacity=32)`, consumer 从 channel
  拉多帧攒到 64KB 再一次 write_all

效果: TCP 层面读者持续排空 kernel recv buffer, advertised window 稳定
大. 应用层单次 write 搬 4 倍 payload, per-byte 开销 4× 降。

### 综合效果预期

服务端 ss -tipn 上 `rwnd_limited` 应从 67% → <10%. brutal pacing_rate
真正生效. 追平 Python POC 的应用层吞吐效率. `delivery_rate` 与
`pacing_rate` 比值从 30-40% 升到 90%+.

### 边缘 case + 兜底

- kernel clamp: 检查 getsockopt 返回值, capped 时 warn 一次
- producer panic: `unwrap_or_else(|_| panic!(...))` 静态防御, 实际
  recv_data 只返 Ok/Err 不 panic
- consumer timeout / 客户端断开: drop rx → producer tx.send Err → 循环
  正常退出, tunnel_reader 正确回收

## [v0.4.4-alpha.20] - WarmPool DEBUG 日志加当前状态快照 (2026-07-01)

### feat(pool): DEBUG 日志显示 idle / inflight / 即将过期 tunnel 数

之前的 Manager DEBUG 日志:
```
WarmPool Manager: target 2 → 3 (gets=6, wait=4 [66.7%], expired=0)
```
只在 target 变化时打, 缺当下时刻的池快照. 用户看到 wait_ratio 高时只
能猜: "是 pool 空? 是全在用? 还是全在过期挤波谷?"

改成每周期 (5s) 都打一行:
```
WarmPool: target=10 [idle=8 inflight=2 exp<10s=1] gets=15 wait=0(0.0%) expired=3
WarmPool: target=10→12 [idle=5 inflight=5 exp<10s=1] gets=30 wait=10(33.3%) expired=1
```

新字段:
- `idle`: 队列里现存可用 tunnel 数
- `inflight`: 已被 handler 借走的 tunnel 数 (in_flight AtomicUsize)
- `exp<10s`: 剩余寿命 < 10 秒的 tunnel 数 (即将波谷指示器)

诊断价值:
- wait_ratio 高 + inflight >> pool_size 想扩 pool_size
- wait_ratio 高 + idle 已经满 想查 handler 泄漏 (借走没还)
- wait_ratio 高 + exp<10s 很多 = 波谷, 想加 max_age_sec 减 refresh 频率
- wait_ratio 0 + idle 满 + expired 高 = 过供给, 可以缩 pool_size

只 DEBUG 级别, INFO 用户不受影响. 每 5s 一行, DEBUG 用户 12 行/分.
每周期 queue 遍历 O(pool_size) 微秒级. `saturating_sub` 防 elapsed
> max_age_sec 边界下溢.

## [v0.4.4-alpha.19] - 清理死字段 + README 大更新 (2026-07-01)

### chore(config): 清理 TuningConfig 里两个 dead field

- `decision_cache_max_entries: Option<usize>` — 定义了但**从没被任何代码路径引用**
- `tcp_keepalive: Option<u64>` — 同上, dead field

老用户 config 里如果写了这两个字段, serde 默认忽略未知字段, 不会
break 现有部署. 删掉是为了避免用户以为配了这两个就有效果, 属于 schema
诚实性修正.

### docs(README): 全面更新到 v0.4.4-alpha.18 现状

原 README 大量过时:
- 版本 badge 还是 v0.2.3
- 配置示例用老的 `listen_host` / `gui_listen` 单字段
- brutal 推荐值 "8-10 Mbps 上限 10" 是 alpha.4 时代的错误理解, alpha.10+
  实测正确值应该是"链路带宽 30-50%"
- 缺 install.sh / log_file / 节点 URI 导出 / 卸载 章节
- 缺"版本演进"章节让用户快速把握 alpha 系列变化

改动:
- 版本 badge 改 v0.4.4-alpha
- 装机流程首推 install.sh, 手动部署放次位
- 配置示例改成 install.sh 实际输出的结构 (schema_version + inbounds[]
  + gui 结构化 + tuning.ebpf_mode = "off" + via=proxy 等)
- brutal 章节按 alpha.5-11 苦学出的新哲学重写 (30-50% 链路带宽 /
  跨洲专线可到 150-200%, `ss -tipn` 观察 retrans 决策 rate)
- 加节点 URI 导出/导入 + 卸载章节
- 结尾加 alpha 版本演进表

保持原 README 结构 + Neon Dashboard / eBPF / Alpine 兼容性等章节不动.

## [v0.4.4-alpha.18] - alpha.17 遗留边界修复 (tuning 删除 + update_days=0) (2026-07-01)

外部审计 + 自查发现 alpha.17 方案 C 的两个边界:

### fix(config_watcher): 用户删除整个 tuning 块 (外部审计发现)

`extract_updater_state` 老实现:
```rust
let tuning = config.tuning?;   // ⚠️ 早退 None
```
用户运行中删除整个 `"tuning"` 块 (想放弃 geo) → `config.tuning` 为 None
→ 函数返 None → ConfigWatcher `if let Some(new_updater)` 跳过 update()
→ **updater 继续持有旧快照**, 每 7 天照样悄悄拉 GitHub, 违反用户意图.

修: `match config.tuning` 显式处理 None 分支, 视为空 sources, 返
`Some(UpdaterState{sources: vec![]})`. updater 收到后进入 idle 阻塞
在 `wake.notified()` 上, 不再周期性访问 GitHub.

### fix(pool ecosystem): geo_update_days = 0 tight-loop 防御 (自查发现)

顺着上面思路自查, `Duration::from_secs(update_days as u64 * 86_400)`
在 `update_days = 0` 时变成 `Duration::from_secs(0)`. tokio select! 里
`sleep(Duration::from_secs(0))` 立刻 ready → 循环无 sleep → tight loop
把 CPU 打满 + **每秒往 GitHub 猛拉直接被 IP-ban**.

老代码 (alpha.17 之前) 也有这个隐雷但没触发过, 因为默认值 7 且用户很少
误输 0. alpha.17 加了 wake 之后, sleep(0) 会立刻被 wake 覆盖后立刻醒
的组合 → tight loop 触发概率反而更高.

3 层防御 (belt+suspenders):
- L1 `src/lib.rs` 冷启动: `if d == 0 { warn + clamp 1 }`
- L2 `src/config_watcher.rs::extract_updater_state`: `MIN_UPDATE_DAYS = 1`
- L3 `src/router/geo_updater.rs` 循环: `snap.update_days.max(1)` 防守

3 层里任何一层都足够消除风险, 但也不冗余到伤脑. 未来新增其他 UpdaterState
构造路径不必额外记忆 clamp.

### 自查结论 — TuningConfig 剩下的字段都不构成类似陷阱
- `decision_cache_max_entries` / `tcp_keepalive`: 定义了但从没被用 (dead
  field, 不影响)
- `geodata_dir` / `ebpf_mode`: 非数值, 无 clamp 需求
- `geo_sources`: 空是合法状态 (updater 进 idle wait)

## [v0.4.4-alpha.17] - 外部审计 4 处纰漏修复 (2026-07-01)

外部代码审计发现 4 个真实问题, 全部修:

### fix(router): singbox JSON geosite 分支也不再静默吞错 (纰漏 1)

alpha.14 修 Issue 3 (geo integrity) 时改了 4 处 v2ray .dat load 站点,
**唯独遗漏了 `src/router/mod.rs:282` 的 geosite singbox JSON 分支**.
用户配 `"geosite": ["cn.json"]` 时若文件损坏或缺失, 依然静默跳过, 所
有依赖该 tag 的规则失效. 改成 match + tracing::error! 显式报错.

### fix(pool): WarmPool::get() timeout 分支补 wait_events (纰漏 2)

指标失真 + 反馈算法逻辑倒挂:
- 入口: `total_gets.fetch_add(1)` 一定加
- 队列拿到 tunnel 且等待 > 50ms: `wait_events.fetch_add(1)` 加
- **10s timeout 分支返 Err 时: 之前不加!**

100 请求全饿死超时 → total_gets=100 wait_events=0 → wait_ratio=0.0
→ Manager 判定"供给完美", 不但不扩容还可能触发缩容. 反馈算法在池
饿死时反而告诉自己"没问题". timeout 到这里意味着实际等了 10s 全被
阻塞, 显式计一次修 wait_events 语义.

### fix(lib): IPv6 SOCKS5 URL 加 RFC 3986 [] 包裹 (纰漏 3)

`src/lib.rs:129-130` 拼 socks5:// URL 时不区分 IPv4/IPv6:
```rust
format!("socks5://{}:{}", host, port)
```
用户配 `"listen": "::1"` → URL 变 `socks5://::1:37683` → 多个未包裹
冒号 → reqwest::Proxy::all() InvalidUrl → geo_updater 的 proxy 通
道直接崩. RFC 3986: URL 里 IPv6 主机必须 `[::1]` 包裹. `host.contains(':')
&& !starts_with('[')` 时自动加 `[...]`. 同时 `::` 通配符规范化到 `::1`
(loopback), 跟 `0.0.0.0` → `127.0.0.1` 对齐.

### feat(geo_updater, config_watcher): geo_sources 真正热更新 (纰漏 4, 方案 C)

老架构: `spawn_updater` 只在 `start_proxy` 时基于冷启动配置调一次,
task 内 sources / update_days 是 `move` 进闭包的死值. 后果:
1. 冷启动无 geo → 热改 config 加 geo → updater 永远未 spawn
2. 热改 tuning.geo_sources / geo_update_days → updater 循环用旧值

方案 C (完整热更新):
- 新增 `UpdaterState` (geodata_dir / sources / update_days / proxy_url)
- 新增 `UpdaterHandle { state: Arc<ArcSwap<UpdaterState>>, wake: Arc<Notify> }`
- `spawn_updater(handle)` 每次循环 `state.load_full()` 拿当前快照
- sources 空: 阻塞在 `wake.notified().await` 不空转
- 循环 sleep 用 `select!` 与 wake 争抢, 热改配置 100% ms 级响应
- 冷启动**无条件** spawn updater (不再有 `if !sources.is_empty()` 门)
- `ConfigWatcher` 接 `UpdaterHandle` clone. 文件变化时用
  `extract_updater_state` 重解析 tuning, 调 `handle.update(new)` 一次性
  Arc swap + notify_one. proxy_url 保留旧值 (inbounds 不热更新, 同步无意义)
- 全字段 update 幂等 (不做部分差分, 避免漏字段 bug)

行为对齐 CoreState hot-reload: 用户改 config 秒生效, 无需 restart.

### 自我审计通过项

- 0 编译警告 (default + ebpf feature 都通过)
- 18 tests 全过 (含 pool feedback + time_sync 全套)
- Rust borrow 检查通过 (NLL 保证 arc_swap Guard 生命周期)
- notify_one 语义正确 (permit-based, 顺序无关)

## [v0.4.4-alpha.16] - reload log 显示纠正 + ArcSwap guard 提前释放 (Issue 6 + drop) (2026-07-01)

### fix(config_watcher): reload log 显示真正触发 reload 的路径 (Issue 6)

之前用 `paths.first()` 取事件里第一个路径打日志:
```
INFO Watched path /etc/mirage-rs/geosite/geoip.dat.tmp changed. Attempting hot-reload...
```

但 notify 在 rename 事件里 paths 可能 `.tmp` 在前 `.dat` 在后, 而实际
的 reload 触发预测是 `.dat` (`.tmp` 被 predicate 过滤掉). log 显示的
路径跟真正被认可的路径不一致, 用户可能疑惑"是不是没原子 rename?".

修改 `src/config_watcher.rs::watch_config`:
- `paths.first()` → `paths.iter().find(<same predicate as trigger>)`
- 保证 log 显示的是真正满足 trigger 的 `.dat` 或 config 文件路径

不动 reload 触发逻辑本身, 只改 log 输出。

### perf(handler,dns): ArcSwap guard 提前 `drop()`, 让 hot-reload 后旧 state 立即可回收

3 处 (`src/dns/server.rs`, `src/proxy/handler.rs` 两处) 在提取 `Arc<OutboundNode>`
后立即 `drop(guard)`:

```rust
let leaf = outbound.resolve_leaf();
drop(current_state);  // ← 新增, guard 到此为止
match &*leaf {
    OutboundNode::Mirage { pool, .. } => {
        // 长期占用连接的 await, 此时不再引用旧 CoreState
    }
    ...
}
```

之前 guard 一直活到整个 `handle_client / proxy_tcp_target / DNS 转发`
结束 (几秒到几分钟). 期间 hot-reload swap 新 CoreState 时旧的**内存不
能立即回收**, 内存里存的是"用户所有 activeconnection 都放了 guard 才
能 drop 旧配置".

改后 guard 提取完 leaf 立刻释放, hot-reload 旧 state 内存能马上被 Arc
的 strong_count 降到 0 从而回收. 功能行为完全不变.

Rust NLL 保证 borrow 检查通过: `outbound` 引用在 `resolve_leaf()` 后
就不再使用, lifetime 已结束, `drop(current_state)` 合法.

### 影响
- Issue 6: 纯 log 显示问题, 无运行时行为改变
- drop: hot-reload 场景内存回收更快, 无功能变化
- 编译: 18 tests 全过, default + ebpf feature 都无 warning

## [v0.4.4-alpha.15] - geo_updater 30s 超时 + 空 body 拦截 (2026-07-01)

### fix(geo_updater): 补 alpha.14 审计出的 2 处纰漏

自查 alpha.14 后发现 2 个 alpha.14 引入或没解决的问题:

1. **reqwest client 无 timeout**: `build_client()` 用 `Client::builder().build()`,
   默认 timeout=None. proxy 抽风或服务端出网卡住时 `send()` 无限阻塞,
   fetch_with_fallback 里的 direct 重试永远等不到, updater 整个循环
   卡死. 加 `FETCH_TIMEOUT = 30s` 覆盖 connect + TLS + body 全流程.

2. **`bytes.len() == 0` 也会覆盖旧 .dat**: 服务端返回 200 但 body 空
   (中间 CDN 缓存 miss / 部署过程中的短暂空窗) 时, alpha.14 的
   `do_fetch` 会把 empty 字节写入 tmp 再 rename 覆盖旧 geosite.dat.
   下次 load 就报错, 全部规则失效. 加 `MIN_VALID_BYTES = 1024` 阈值,
   小于这个的 body 判定为异常, 不覆盖旧文件.

真实的 dlc.dat / geoip.dat 都 >= 1 MB, 1 KB 阈值宽松防误伤边缘 case
(理论上没有 legit 场景 < 1 KB).

## [v0.4.4-alpha.14] - log_file / geo 完整性 / geo proxy fallback (Issue 2/3/5) (2026-07-01)

### feat(log): 配置 log_file 字段生效 + log_level 真的读了 (Issue 2)

之前 `log_level` 字段 config 里定义了但**代码 hardcode `Level::DEBUG`**,
用户改 config 完全无效. `log_file` 字段甚至连 schema 都没有, install.sh
建的 /var/log/mirage-rs 目录闲置.

修改:
- `config.rs::Config` 加 `log_file: Option<String>` 字段
- `lib.rs::start_proxy` subscriber 初始化前主动读 config, 取:
  - `log_level` (info/warn/debug/error/trace, 严格 lowercase)
  - `log_file` (可选文件路径)
- 若 log_file 有效: append 打开, 用 `monitor::FileLogger` (Arc<Mutex<File>>
  + Clone + Write) 作 tracing MakeWriter, 同时保留 stdout + GLOBAL_LOGGER
  (GUI 内存 buffer). systemd journalctl 仍能抓 stdout 副本.
- 文件打开失败: eprintln + 降级到 stdout only, 不阻塞启动.
- install.sh: server 和 client config 默认写入
  `"log_file": "${LOG_DIR}/{server,client}.log"`

### fix(router): geo .dat load 失败静默 → error! 显式报错 (Issue 3)

`src/router/mod.rs` 5 处 `if let Ok(domains) = load_geosite_dat(...)` /
`load_geoip_dat` / `load_singbox_json` 静默吞错. 用户 geo 文件损坏时规
则集体消失, 无任何提示. 改成显式 `match` + `tracing::error!` 打出:
- 引用的 tag 名
- 完整文件路径
- 底层错误信息
- 提示 "Rules referencing this tag will match nothing"

方便用户知道"我这规则为啥不生效"是文件问题.

### feat(geo_updater): via=Proxy 失败真 fallback direct + install.sh 默认 via=proxy (Issue 5)

之前:
- install.sh 默认 `"via": "direct"`, 大陆用户 GitHub 直连超时/被墙,
  geo 数据永远拉不到, 路由规则全 fallback 到 default_outbound.
- geo_updater 里 via=Proxy 只在 proxy_url=None 时 fallback direct.
  实际 send/HTTP 失败**不 fallback**, 直接 return Err.

修改:
- `install.sh`: 两处 `"via": "direct"` → `"via": "proxy"`
- `geo_updater::update_one`: 拆成 `do_fetch` + `fetch_with_fallback`.
  via=Proxy 失败时自动重试 Direct 一次, info! 记录 fallback 成功.
  两次都失败 → error! 告知用户 "both proxy and direct fetch failed".

### 升级路径
现有 client 部署重装 (`sudo bash install.sh`) → 新 config 自动写
`log_file` + `via=proxy`. 手动 config 用户:
```json
"log_file": "/var/log/mirage-rs/client.log",
...
"geo_sources": [
  {"name": "geosite", "kind": "geosite", "url": "...", "via": "proxy"},
  {"name": "geoip",   "kind": "geoip",   "url": "...", "via": "proxy"}
]
```

## [v0.4.4-alpha.13] - TIME_SYNC 日志降噪 (Issue 1) (2026-07-01)

### fix(time_sync): |Δ| < 3s 的小抖动降到 DEBUG 级

Issue 1 修复. 之前 `set_offset_from_server_time` 只要 old != offset
就打 INFO, 但客户端系统时钟正常 jitter 通常 ±1s, 每条 WarmPool tunnel
建立都触发一次:

```
INFO TIME_SYNC: offset updated 0s → -1s (Δ -1s) from server...
INFO TIME_SYNC: offset updated -1s → 0s (Δ 1s) from server...
INFO TIME_SYNC: offset updated 0s → -1s (Δ -1s) from server...
```

pool_size=10 时启动就 10 行, 之后每次 tunnel refresh 又来一次, INFO
级别用户被淹没却看不到有意义的时钟事件.

修改 `src/time_sync.rs::set_offset_from_server_time`:
- `SIGNIFICANT_DELTA = 3` 秒阈值
- `|Δ| ≥ 3s`: INFO (真实时钟不同步, 用户需要知道)
- `0 < |Δ| < 3s`: DEBUG "minor drift" (小抖动, 想看细节可以调 log 级)
- `Δ == 0`: DEBUG "offset maintained" (保持原语义)

不改变 offset 存储行为, 7 项 time_sync 单测全过.

## [v0.4.4-alpha.12] - WarmPool 初始 target 修复 (alpha.11 遗漏) (2026-07-01)

### fix(pool): 初始 target 也应用 MIN_TARGET_FLOOR (alpha.11 遗漏)

alpha.11 把 decide_new_target 的缩容底线从 2 提到 10, 但**忘了改初始
化**. 用户实测日志:

```
02:23:43  WarmPool Manager: target 2 → 3 (gets=2, wait=2 [100.0%])
```

初始 target=2 (硬编码), 启动后前 2 个请求就 wait build, decide_new_target
5s 后才发现要扩, 每周期 +1 慢慢爬到 floor=10. 启动前几秒仍然卡.

修改 `src/proxy/pool.rs:331`:
- 之前: `AtomicUsize::new(2)`
- 现在: `AtomicUsize::new(MIN_TARGET_FLOOR.min(cfg.pool_size))`

现在客户端启动瞬间就有 10 (或 pool_size, 取较小者) 条常温 tunnel, 突发
真正无 wait.

## [v0.4.4-alpha.11] - WarmPool 缩容底线 2 → 10 (突发无 wait) (2026-07-01)

### fix(pool): 提高 idle 期最低 tunnel 数, 解决突发并发 66% wait build

用户实测 alpha.10 后发现:

|场景|POC (rate=10 × 多流)|mirage-rs (rate=40 单流)|
|---|---|---|
|YouTube 视频|流畅|流畅但 CPU 更低|
|突发多标签开页|流畅|明显卡顿|

client 日志确认原因:
```
WarmPool Manager: target 2 → 3 (gets=6, wait=4 [66.7%], expired=0)
```

浏览器突发 6 个 SOCKS5 CONNECT 时, adaptive pool 已缩到 target=2, 只
有 2 条 tunnel 现成, 剩 4 条得等 build (770-2000ms 每条握手), **66%
的请求实际排队**. POC 因 pool_size=20 固定不缩, 6 并发时 6 条 tunnel
立刻各分一条, 每条 rate=10 也够 → 用户感受"多流并行"很流畅.

### 修改
`src/proxy/pool.rs::decide_new_target` — 缩容底线从 2 提到 10:
- `const MIN_TARGET_FLOOR: usize = 10;`
- 实际 floor = `MIN_TARGET_FLOOR.min(max_size)`, pool_size < 10 时自动
  降为 max_size (小 pool 场景不会被卡死)

### 效果
- idle 期至少保 10 条常温 tunnel (BDP × 10 × TLS ≈ 5-10 MB RAM, 可接受)
- 常见浏览器最大并发 (Chrome/Firefox 每 host 6-8) 都能立刻分到 tunnel
- 突发 wait_ratio 应从 66% 降到 0-10%
- 高峰后 idle 仍会缩容, 只是不缩到 2 而已 (不影响资源节省的主旨)

### 用户行动
本版无需改 config, 直接部署 alpha.11 即享受. 浏览器多标签开页会明显
不卡, 突发 wait 日志应几乎消失.

未来 (alpha.12+) 可考虑加 tuning.pool_min_floor 配置字段, 让重内存
环境的用户按需调低. 本版先固定 10 观察实测.

## [v0.4.4-alpha.10] - cwnd_gain 20 → 15 跟 POC 对齐 (2026-07-01)

### perf(brutal): cwnd_gain 改回 15, 跟 Python POC 实测一致

alpha.9 砍了 autofallback 后 brutal 真的全程在跑了, 但实测速度仍不
及 Python POC. 全面对比两边 setsockopt 序列发现仅剩两处差异:

|项|POC|Rust alpha.9|备注|
|---|---|---|---|
|brutal cwnd_gain|**15**|20|本版改|
|TCP_NODELAY|未设|set_nodelay(true)|握手期间降低首包延迟, 数据阶段无影响|
|SO_KEEPALIVE|开启|未设|仅死连接检测, 无吞吐影响|

POC `_DEFAULT_CWND_GAIN = 15` 注释写"对齐参考实现". 我在 alpha.5 改成
20 是基于"apernet 内核默认 20"的判断, 但实测 POC 的 15 反而更快.
推测原因: cwnd_gain=2.0× BDP 在高丢包链路上会放大重传成本 — 同时在
途的包多了, 单个丢包会拖累更多窗口前进, 净吞吐反不如 1.5× 紧凑.

修改 (3 处必须同步, 否则 BPF 反馈环会用旧值覆盖):
- `src/proxy/brutal.rs:78`  (set_brutal_rate, accepted socket)
- `src/proxy/brutal.rs:161` (apply_brutal, client outbound)
- `src/proxy/pool.rs:608`   (update_brutal_rate, 动态调节)

不动 NODELAY: 它在 TLS 握手期间是必要的 (小包不被 Nagle 拖延首包延迟).
数据传输阶段, Mirage 应用层 AEAD send 都是大块 (≥ MSS), Nagle 本就不
会缓存它们, NODELAY 设不设没区别. POC 没设只是没人写而已, 不是因为
跟 brutal 冲突.

### alpha.5 → alpha.10 brutal 排错全表 (汇总)

|alpha|改动|结果|
|---|---|---|
|.5|cwnd_gain 15 → 20 (误判 apernet 默认)|无效, 反而是错的|
|.6|加 autofallback (5% 阈值)|本意安全网, 实测误杀 brutal|
|.7|client 关 BPF|跟 brutal 无关, 解 direct outbound 卡死|
|.8|listener 预设算法 (POC 对齐)|关键修复, 让 brutal 真生效|
|.9|砍 autofallback|brutal 全程跑, 不再被切走|
|.10|cwnd_gain 20 → 15 (POC 对齐)|**本版**, 期望追平 POC 速度|

跟 POC 还剩的不影响吞吐的小差异: SO_KEEPALIVE (仅死连接检测). 后续
有需要再加.

## [v0.4.4-alpha.9] - 砍掉 Brutal autofallback, 跟 POC 行为对齐 (2026-06-30)

### fix(brutal): 不再自动从 brutal 切回 BBR

alpha.8 修对了 brutal 应用时机 (listener 预设算法), 实测 brutal 真的
在跑, 但**速度仍达不到 Python POC 水平**. 服务端日志铁证:

```
09:00:17.066  brutal 连接建立, pacing_rate 10 Mbps, cwnd 308
09:00:27.474  WARN Brutal CC unsuitable... retrans 16.3% in 10s window.
              Auto-fallback to BBR.
```

只跑 10 秒, alpha.6 加的 autofallback 监测就因 retrans > 5% 把 brutal
切掉了. 这恰恰违反了 brutal CC 的设计哲学:

> **brutal 的工作原理就是"丢包是噪声, 死磕设定速率, 让上层应用见到稳
> 定吞吐"**. 高 retrans 是 brutal 工作过程中**正常现象**, 不是"不适合"
> 的信号. POC 实测可用就证明这条链路是 brutal-friendly 的, 重传是预期
> 的代价, 净吞吐仍优于 BBR.

修复 (src/proxy/mirage_server/mod.rs:78-93):
- 移除 accept 循环里的 `spawn_fallback_monitor(fd)` 调用
- `set_brutal_rate(fd, rate)` 保留, listener 预设算法名机制不变
- 行为现在 100% 跟 POC 对齐: 设了 brutal_rate_mbps 就硬跑到连接关闭

`spawn_fallback_monitor` 函数本身保留在 brutal.rs (含 TcpInfoExt
struct + getsockopt 包装), 留作未来 `tuning.brutal_autofallback = true`
opt-in 高级选项. 默认不调用, 代码也不删, 因为这套基础设施做对了
(SO_COOKIE 防 fd 复用 / Linux 3.15+ ABI 完整结构), 留着不浪费.

### 用户行动建议
- 不适合 brutal 的链路: 把 config 里 `"brutal_rate_mbps"` 改 0 或删掉
  字段 (server 端会自动 fallback 到系统默认 CC = BBR)
- 适合 brutal 的链路: 默认行为就是对的, 不必动

### alpha.5 → alpha.9 整段 brutal 排错总结

|alpha|改动|结论|
|---|---|---|
|.5|cwnd_gain 15 → 20|对的, 跟 apernet 默认对齐, 保留|
|.6|加 autofallback|本意是安全网, **实际是误杀 brutal**, 本版砍|
|.7|client 关 BPF|跟 brutal 无关, 解 direct outbound 卡死|
|.8|listener 预设算法 (POC 对齐)|关键修复, 让 brutal 真生效|
|.9|砍 autofallback|本版, **正式跟 POC 行为对齐**|

## [v0.4.4-alpha.8] - Brutal CC 应用时机修正 (匹配 Python POC) (2026-06-26)

### fix(brutal): listener 上预设算法名, accepted socket 只补速率

跟 Python POC (/opt/claude/mirage/server.py:349-360) 对比发现关键
应用时序差异:

Python POC:
  1. listener socket 上 setsockopt(TCP_CONGESTION, "brutal")
  2. accept → 子 socket 自动继承 brutal 算法名
  3. accepted socket 上仅 setsockopt(TCP_BRUTAL_PARAMS, rate, ...)

Rust (alpha.7 之前):
  1. listener socket 上不设, 用 kernel 默认 CC (bbr/cubic)
  2. accept → 子 socket = bbr
  3. accepted socket 上 setsockopt(TCP_CONGESTION, "brutal") 中途切换
  4. 然后 setsockopt(TCP_BRUTAL_PARAMS, rate, ...)

中途切换 CC 在 Linux 是合法的, 但 brutal kernel 模块的 init/pacing
状态过渡可能不干净 — 子 socket 已 ESTABLISHED, kernel 默认 pacing
路径已激活, 切到 brutal 后 sk_pacing_status 转换 + brutal 自己的
pacer 之间状态可能不一致, 导致实测吞吐塌方. POC 子 socket 从 SYN-ACK
起就在 brutal 算法下, kernel 状态干净, 跑得很顺.

修复 (src/proxy/brutal.rs + mirage_server/mod.rs):
- 新增 `set_brutal_on_listener(fd)` — 仅设算法名, 在 bind 后第一次
  accept 前调用一次
- 新增 `set_brutal_rate(fd, rate)` — 仅设 TCP_BRUTAL_PARAMS, 给每个
  accepted socket 用
- 保留旧 `apply_brutal(fd, rate)` 给 pool.rs (客户端出站) — 客户端
  是主动 connect, 无 listener 可继承, 只能在 connect 后 apply

### 验证方法

部署后:
```bash
sudo journalctl -u mirage-server --since "2 min ago" | grep "Brutal CC pre-set"
```
应有一行 "Brutal CC pre-set on listener fd=X (will be inherited by
accepted sockets)".

然后 ss -tipn 看 cwnd 走向 — 跟 POC 在同链路上跑应该数据相近.

cwnd_gain 仍保持 20 (apernet 默认), 不改成 Python 的 15 是因为
alpha.4 (15) 和 alpha.5/6 (20) 实测都慢, 真正瓶颈是算法应用时序,
不是 cwnd_gain 取值.

## [v0.4.4-alpha.7] - eBPF SockMap 直连转发问题临时禁用 (2026-06-26)

### fix(install): 客户端 config 默认 ebpf_mode = "off"

实测发现: 客户端访问 direct outbound 网站 (如 .cn 域名走直连) 时,
日志显示 "eBPF SockMap: spliced ... (Zero-copy bypass activated)",
但浏览器无响应, 5-15s 后超时重连, 周而复始。

根因 (代码层): `src/proxy/handler.rs:258-312` 的 direct outbound 路径
里, `EbpfEngine::register_splice()` 把两个 socket 的 cookie 插入
SockHash, 然后 handler 进入 epoll 等 EPOLLRDHUP, **完全不再 Tokio
读写**。问题:
  1. `register_splice()` 的 Ok() 仅代表 map.insert 成功
  2. 不代表 BPF stream_verdict 程序在数据到达时真能正确转发
  3. 一旦 BPF redirect 静默失败 (cookie 时序、kernel 版本 ABI 差异、
     sk_psock 初始化竞争等), 数据全静默丢, 也不会 fallback 回 Tokio

实测确认: 客户端 config 加 `"tuning": { "ebpf_mode": "off" }` 后
direct 立即正常。

短期方案 (本版): install.sh 客户端 config 默认 `ebpf_mode = "off"`,
让用户开箱即用。
长期方案 (待调研): 根治 SockMap stream_verdict 不可靠转发, 可能需要
在 register_splice 后做"健康探测"才标记 ebpf_spliced = true, 或改成
Tokio + BPF 双路监听 (BPF 接管成功则 Tokio 退出, 否则 BPF 旁路只做
统计)。

### 影响
- 本版客户端不享受 BPF zero-copy direct outbound 加速 (但 direct 走
  Tokio 性能也完全够用, 一般用户感知不到差别)
- BPF sock_ops RTT_CB / XDP DNS 等其他 BPF 功能也被一并停用 (它们都
  在 ebpf_mode 总开关下), 客户端动态 brutal 调节失效。但客户端 brutal
  默认本来就关闭, 影响面 ≈ 0
- 服务端不受影响 (服务端本就 auto-skip BPF)

## [v0.4.4-alpha.6] - Brutal CC 自适应回落 + install.sh 文本修正 (2026-06-25)

### feat(brutal): retrans 率超阈值自动 setsockopt 切回 BBR

alpha.5 把 cwnd_gain 从 15 改到 20 之后实测仍慢, ss -tipn 数据显示问
题不在 cwnd_gain 而在链路本身:

- RTT 162-190ms (跨洲)
- retrans 12-15% (链路真在丢包, 不是噪声)
- pacing_rate 5 Mbps (brutal 在按 config 走), delivery_rate 0.5 Mbps
- BBR 在同一链路上能跑满 5 Mbps 因为它感知到 RTT/loss 主动收敛

brutal CC 的设计哲学 ("丢包是噪声, 死磕速率") 与高丢包链路冲突, 死磕
导致重传放大反而吃光带宽. 这是算法本质, 不是 bug.

但服务端不能因此就放弃 brutal — 高 RTT 低丢包的跨洲专线场景 brutal
仍然胜 BBR. 取舍解法: **保留默认开启, 同时跑运行时自适应监测**.

实现 (src/proxy/brutal.rs::spawn_fallback_monitor):
- 每条 brutal-enabled accept socket 起一个轻量 tokio task
- 每 10s 调 getsockopt(TCP_INFO) 读 total_retrans / segs_out
- 单窗口 retrans > 5% 且 segs > 500 (流量足够判断) → setsockopt
  TCP_CONGESTION=bbr 立即切走, log warn 解释原因
- 连续 6 个窗口正常 (1 分钟) 认为链路稳定, 停止监测省 CPU
- 最长 3 分钟无定论也停止
- 用 SO_COOKIE 防 fd 复用错认 (socket 关闭后 fd 可能立即被新连接拿
  到, 仅靠 fd 监测会误改无关 socket)

libc 0.2.186 的 tcp_info 只到 tcpi_total_retrans, 没暴露 segs_out
等 Linux 3.15+ 字段. 自定义 TcpInfoExt 完整 struct (144 字节,
segs_out offset 136, 匹配 Linux upstream ABI), getsockopt 长度匹配,
老内核场景下尾部字段保 0, MIN_SEGS_PER_WINDOW 阈值自然兜底, 安全
降级不需特殊处理.

### fix(install): 误导的 brutal_rate 建议值

旧文本推荐 8-10 Mbps/单连接, 实际是给 100M/1G 链路设的过保守值,
单流 YouTube 直接被 cap. 新文本基于"链路带宽 30-50%"建议, 100M
出口 → 30-50 Mbps, 1G → 300-500. 自适应 fallback 兜底, 设过头
也不会比 BBR 差.

### 升级影响
- 服务端无需手改 config, 重启即享受自适应 brutal
- 用户在不合适的链路 (跨洲 CDN / 国内移动) 部署也不会比 BBR 慢
- 高 RTT 低丢包链路 (跨洲专线) brutal 加速依然有效

## [v0.4.4-alpha.5] - Brutal cwnd_gain 修正 (2026-06-25)

### perf(brutal): cwnd_gain 15 → 20 (匹配 apernet 内核默认)

实际部署反馈, 服务端启用 brutal 后 YouTube 等场景下连接速度反而比关
闭 brutal 慢. 7 组 A/B 对照表 (brutal=0/2/8/20/50, pool=1/5/50) 显示:

- pool 越大越慢 (50 > 5 > 1 → 不是 N 流互挤, 因为单视频流只占 1-2 条)
- E (rate=20, pool=5) ≈ F (rate=50, pool=5) — **rate 不是瓶颈**
- 所有 brutal 启用配置都 < 无 brutal (C)

诊断结论: cwnd_gain 是瓶颈. brutal cwnd = BDP × cwnd_gain / 10. 我们之前
代码里硬塞 `CWND_GAIN_X10 = 15` (= 1.5× BDP), 在低 RTT/高带宽链路 (国
内访问海外 CDN 经常 < 50ms) cwnd 偏紧, ACK 还没回 cwnd 就满, 实际吞
吐 < 设定 rate, 表现就是 E ≈ F (都被 cwnd 卡同一上限). apernet/tcp-brutal
内核模块默认是 `CWND_GAIN_DEFAULT 20` (= 2.0× BDP), 我们对齐.

修改:
- `src/proxy/brutal.rs:73`  CWND_GAIN_X10 15 → 20  (静态 apply_brutal)
- `src/proxy/pool.rs:608`   CWND_GAIN_X10 15 → 20  (动态 update_brutal_rate)

两处必须同步, 否则客户端 BPF 反馈 loop (lib.rs:250-318) 跑起来后会用
旧值覆盖. 此 alpha 仅一行实质改动, 待用户验证后再决定是否进一步暴露
为 advanced 可调字段.

## [v0.4.4-alpha.4] - 安装体验 + 版本治理 (2026-06-24)

### feat(install): 节点 URI 导出 / 导入
- 服务端配置完成后询问公网地址, 生成 `mirage://<url-encoded-pwd>@<host>:<port>?sni=<sni>[&brutal=<mbps>]` 单行节点串, 存到 `/etc/mirage-rs/node-export.txt` (chmod 600) 并在终端打印. 装了 `qrencode` 同时出 UTF8 二维码.
- 客户端 `config_client` 启动加 "粘贴 URI 自动填" / "手动输入" 分支. 同机部署 mode 3 时, URI 默认自动填入本机刚生成的, 一回车复用.
- URL 编解码 UTF-8 安全 (中文密码可用), 6 类非法 URI (空 / 错协议 / 缺端口 / 非数字端口 / 空 SNI / 残缺) 全拒. 不支持 `[::1]` 形 IPv6 主机 (regex 限制), 这种走手动模式.

### feat(install): 监听端口占用检测
- 服务端 port + 客户端 inbound_port 接 `ask_port()` (基于 `ss -tlnH`). 占用即 warn + 显示占用进程名, 用户可选 force-continue. `ss` 不可用 (HAVE_SS=0) 自动跳过, 不阻塞流程.

### chore(version): 三层同步 binary 版本信息
- **L1**: `Cargo.toml` 0.2.3 → 0.4.4-alpha.4. 历史欠账 — 该字段从未更新, 5 个 tag 以来 `mirage --version` 一直输出 "0.2.3".
- **L2**: `build.rs` 跑 `git describe --tags --always --dirty` 注入 `MIRAGE_GIT` env, `src/bin/mirage.rs` 用 `concat!(CARGO_PKG_VERSION, " (", MIRAGE_GIT, ")")` 作为 clap version. 现在输出:
  ```
  mirage-rs 0.4.4-alpha.4 (v0.4.4-alpha.4)
  ```
  dev build 自带 `-dirty`. rerun 钩子 watch `.git/HEAD/refs/heads/refs/tags/index`, commit/staged 都触发 rebuild.
- **L3**: `release.yml` 加 sanity check, tag vXYZ 与 Cargo.toml XYZ 不一致 CI 立刻 fail 并提示先 bump. checkout 加 `fetch-depth: 0` 让 git describe 拿全 tag 历史.

### chore(test): 综合 bug 验证脚本 `scripts/test_bugfixes.sh`
- 覆盖 v0.4.4-alpha.x 6 个 bug (pool 缩容锁死 / Geo 启动时序 / TCP 僵尸 / UDP cancel-safety / DJB2 panic / pool 雪崩). 3 种模式: `quick` 全自动 3 个 / `all` 全套需手动配合 / 指定 bug 号. 末尾自动 PASS/FAIL/SKIP 汇总.

### 升级影响
- 无代码层 bug 修复 (alpha.3 已修齐). 本版纯 DX/UX. 已部署 alpha.3 没有 OOM/panic 实战问题的不必急升.
- 升级后 `mirage --version` 会反映真实版本; 之后的 alpha.5/alpha.6 不会再静默输出 alpha.3 hash.

## [v0.4.4-alpha.3] - 2 个隐蔽生产 bug 修复 (2026-06-23)

### Critical Fixes
- **fix(ebpf): DJB2 哈希算法 Rust 溢出 panic (恶意域名远程崩溃)** — `src/ebpf/mod.rs::update_dns_cache` 的 DJB2 哈希 `hash = ((hash << 5) + hash).wrapping_add(b as u64)` 末尾 wrapping 是对的, 但前面的 `+ hash` 是普通加. Rust debug build (含任何启用 `overflow-checks = true` 的 release) 一旦 u64 溢出就 panic. **攻击者可构造超长恶意域名通过 XDP 触发, 精准 panic 用户态管控平面**. 修复: 改为 `(hash << 5).wrapping_add(hash).wrapping_add(b as u64)`, 全部 wrapping 跟 C 端 dns_xdp.c 的 u64 + 截断语义一致.
- **fix(pool): WarmPool.get() 无超时导致雪崩 OOM** — 旧签名 `pub async fn get(&self) -> Tunnel` infallible, 池子空 + builder 反复连接上游失败时只 log + sleep 1s, **永不调用 notify_one**. 每个 pool.get() 死等, 浏览器请求堆积成百上千 → FD 耗尽 → OOM 进程被 OS 强杀. 修复: 改成 `Result<Tunnel>` + 内部 10s `tokio::time::timeout`. 4 个调用点 (handler/dns/healthcheck/udp_relay) 全部更新, Err 时 log + 优雅 return.

### 实际部署影响
v0.4.4-alpha.2 也带这两个 bug:
- DJB2 panic: 配置了 fakeip + XDP 的客户端, 攻击者发恶意域名 XDP 触发崩溃
- pool 雪崩: 客户端上游服务器宕机 / 网络抽风时, 浏览器多个 tab 同时使用代理 → FD 在分钟级别耗尽

强烈建议从任何 v0.4.x 升 alpha.3.

## [v0.4.4-alpha.2] - 4 个生产级 bug 修复 (2026-06-23)

### Critical Fixes
- **fix(pool): WarmPool 空闲期缩容锁死 (资源燃烧)** — `decide_new_target` 的 `total_gets > 0` 守护误把"高峰后回到 idle"的缩容路径禁用. 高峰把 target 涨到 max_size=40 后用户睡觉流量归零 → target 永久钉死 → builder 维持 40 个 idle TLS 连接 → max_age 到期 sweeper 杀 → builder 又建 → 一整夜烧 CPU 握手. `cur_target > 2` 已是 floor 保护, 删守护即可. 删 2 个误测试, 加 3 个新测试 (含 drain-to-floor 回归).
- **fix(watcher): GeoUpdater 与 ConfigWatcher 启动时序空隙** — `spawn_watcher` 只 watch `config_path`, geo_updater 30s 后下载的 .dat 落地不触发 Router 重建, 所有 geosite/geoip 规则 silent no-op → 用户访问全部 fall back 到 `default_outbound`, 必须手动改 config.json 才能修复. 修复: 同时 watch `geodata_dir`, 不存在时主动 `create_dir_all`. 事件过滤只对 config 文件或 `.dat` 文件触发 reload (避免 .tmp 抖动).
- **fix(tcp_relay): 服务端 TCP 转发僵尸任务泄露 (30 分钟资源燃烧)** — `tokio::join!(upload, download)` 在客户端断网时只让 upload 立刻退出, download 阻塞在 `up_read.read()` 等上游响应直到 1800s 超时. 弱网环境频繁闪断重连 → FD + tokio 协程泄露累积 → 耗尽内存. 修复: 两方共享 `Arc<AtomicI32>(upstream_fd)`, 任一方退出 swap -1 并 `libc::shutdown(SHUT_RDWR)` 强制关闭 upstream socket, 另一方 read/write 立即返回 Err 退出. 不用 select!/abort 是为了避免 cancel mid-write 损坏 AEAD 帧 (见下).
- **fix(udp_relay): tokio::select! cancel-safety 导致 AEAD 帧损坏** — UDP relay 的 `tokio::select!(tunnel_uplink, tunnel_downlink)` 一方完成时暴力 drop 另一方, 若 downlink 正在 `writer.send_data` 半截 (TLS 5B header 已发出去, payload 没写完), 之后外层 `send_close_notify` 又写 alert → 客户端拼接半截帧 + alert 触发 AEAD MAC 校验崩, "bad record mac". 修复: 改用 watch 频道做协作式停止信号, 两 task 都 join (不 select!), select! 仅围绕 cancel-safe 的 read 点 (recv_data / rx.recv), AEAD 写在 select! 外永远不被中途打断.

### 实际部署影响
v0.4.4-alpha.1 的 4 个 bug 都已实际部署可触发:
- pool 缩容锁死: 任何启用 brutal + 流量有早晚峰差异的客户端
- geo 启动时序: 任何首次部署 + 配了 geo 规则的客户端 (重启过的也复现)
- tcp 僵尸泄露: 任何服务端在弱网客户端场景下 (移动用户 / WiFi 不稳)
- udp cancel-safety: 任何启用 UDP relay 的部署 (DNS/QUIC 等)

强烈建议从 v0.4.4-alpha.1 升 alpha.2.

## [v0.4.4-alpha.1] - Active BPF Tunnels Dashboard + BPF struct 扩展 (2026-06-22)

### feat(gui): Active BPF Tunnels 表格 + Brutal CC 指示灯
- Neon Dashboard 新增 "Active BPF Tunnels" 面板, 实时展示每条 BPF 跟踪的 TCP tunnel: Remote 地址 / RTT (ms, < 50 绿 / < 150 黄 / > 150 红) / Retrans 重传 / 趋势箭头 (↑↓→, JS 5 点滚动窗口跟前次比 ±10%).
- 行可点击展开详情: cookie 16-hex / cwnd / data_segs (调试视角).
- 1Hz 轮询 `/api/bpf/tunnels`. LRU 淘汰的 cookie 自动从前端历史 Map GC.
- 顶部状态条新增 "Brutal CC: ACTIVE/STATIC" 指示灯 (跟 eBPF ENGINE 并列). ACTIVE = 任一 tunnel `srtt_us > 0` (sock_ops RTT_CB 已生效).

### BPF struct 扩展 (sockmap.c::tcp_state)
- 加 `remote_ip[4]` (IPv4 在 `[0]`, IPv6 全 4 个 u32) + `remote_port` (u16) + `family` (u16). size: 16 → 36 字节.
- Rust `TcpState` 严格对齐, C/Rust offset_of! 实测一致, sizeof 均 36.
- `mirage_sockops` 沿用"ctx 字段全部 prefetch 到 locals"防御写法 (避免 v0.4.0 那个 verifier "modified ctx ptr" 坑). llvm-objdump 字节码确认无 modified ctx ptr 模式.

### API
- `/api/bpf/tunnels` 新增 `remote` 字段: 格式化成 `"192.0.2.5:443"` / `"[2001:db8::1]:443"` / `"?:?"`. IPv4 字节序: 内核 network byte order u32, 小端机加载后 `b0 = raw & 0xff` 即第一个 octet, 验证 1.2.3.4 解码无误.
- `cookie` 字段从 JSON Number 改成 JSON String 序列化, 避开 JS Number 2^53 精度上限 (理论纰漏, 物理不可触发但 belt-and-suspenders).

### 设计权衡声明 (重要)
当前 BPF `target_ips` 白名单仅登记: 客户端 → mirage 服务器 IP / 服务端 ← 客户端 IP. **不跟踪 upstream 业务连接** (github.com / youtube 等). 因此 Active Tunnels 表格里:
- 客户端: 全部 N 行 remote = mirage 服务器 IP (反映 WarmPool 健康度)
- 服务端: 各客户端 IP (反映谁在连接)

想展示业务目标域名需新增"服务端给每个 upstream 连接也注册 target_ips + 反向关联 cookie"那套, 单独立项.

## [v0.4.3-alpha.1] - 多源 Geo + 骨架重构 + 反馈算法 (2026-06-22)

### ⚠️ Breaking Schema Change (alpha 期硬升级, 无向后兼容)
- **`tuning.geosite_url` + `tuning.geoip_url` 已删除**, 改为 `tuning.geo_sources` 数组. 旧 config 启动会被 serde 拒绝 (unknown field). **必须迁移**, 迁移示例见 README "客户端配置示例".

### feat(geo): 多源 Geo 下载 + via=direct/proxy + 自定义命名
- `tuning.geo_sources: [{name, kind, url, via}]` 数组. 每个 source 独立配置:
  - `name`: 文件保存为 `<name>.dat`, 必须在 sources 内唯一 (重复直接 ERROR 不启动).
  - `kind`: `"geosite"` (域名) 或 `"geoip"` (IP CIDR).
  - `via`: `"direct"` (默认) 或 `"proxy"` (走客户端本地 socks/mixed inbound).
- 国内服务器拉 GitHub 受阻时全部设 `"via": "proxy"` 即可走代理出口.
- 配合 `routing.geo_alias` 起短名: `"geo_alias": {"ls": "loyalsoldier.dat"}` → 规则写 `"geosite": ["ls:cn"]` 自动解析.
- 新增 `tuning.geo_update_days` 配置 (默认 7 天).
- `Cargo.toml`: reqwest features 加 `"socks"`.

### refactor: 骨架重构 (严格行为等价, 0 warning)
- **`src/proxy/mirage_server.rs` (470 行 monolith) → 6 个职责单一子模块** (`mod / handshake / camouflage / control / tcp_relay / udp_relay`). 详见 commit 909cf4e.
- **`src/gui/` → `src/api/` 改名 + `mod.rs` (313 行) 拆 9 个文件** (`mod / state / sampler / handlers/{overview,bpf_tunnels,history,logs,proxies,rules}`). 匹配"API 作为独立模块"的设计意向. 详见 commit e0db37c.
- 后续功能演进 (DNS 转发器完善 / 多源 Geo per-source 配置 / 等) 都能在更清晰的模块边界上扩展.

### feat(pool): WarmPool 反馈式弹性算法 (替代 RPS*3+2 开环)
- 旧算法直接由 RPS 推 target, 高 RPS 时 pool 堆积 → 频繁裁剪触发 close_notify 噪音.
- 新算法 AIAD 闭环, 测三个指标 (wait_events / total_gets / expired_unused) 决策扩缩容.
- 不再做硬裁剪, target 只控制 builder 建货节奏, queue 自然到 max_age 被 sweeper 收掉.
- Manager 周期 2s → 5s. 详见 commit e80adb7.

### feat(ebpf): 服务端自动跳过 eBPF + ebpf_mode 三态配置
- 新增 `tuning.ebpf_mode`: `"auto"` (默认, 跟 CLI 子命令走) / `"force"` / `"off"`.
- 服务端跑 BPF 全部子系统都无价值, auto 模式服务端自动跳过. Alpine 服务端不再需要 `CONFIG_CGROUP_BPF` 内核重编. 详见 commit 1a63838.

### docs(brutal): brutal_rate_mbps 设计哲学
- install.sh 加 23 行教育性提示 + 默认 100 → 8 Mbps. README 新增 "brutal_rate_mbps 的设计哲学" 章节 (取值对比表 1G/100M × 8/10/50/100 Mbps).

## [v0.4.2-alpha.1] - 服务端 eBPF 自动跳过 + WarmPool 反馈算法 (2026-06-22)

### feat(pool): WarmPool 反馈式弹性算法
- 旧 `target = RPS*3+2` 开环算法存在"建-裁震荡"问题, 高 RPS 时频繁裁剪触发 close_notify 噪音.
- 新算法基于实际指标 (wait_events / total_gets / expired_unused) 做 AIAD 闭环:
  - `wait_ratio > 0.2` AND target < max → 扩 20% (最少 +1)
  - `wait_ratio == 0` AND `expired ≥ gets/2` AND target > 2 → 缓慢缩 -1
  - 否则维持
- **不再做硬裁剪** (删除旧 `q.len() > target+2` 那段). target 只控制 builder 建货节奏, queue 自然在 max_age 到期被 sweeper 收掉. close_notify 频率大幅下降.
- Manager 周期 2s → 5s (减噪 + 指标聚合更稳).
- decide_new_target 提取为纯函数, 新增 8 个 unit test 覆盖 idle/pressure/clamp/floor/priority/no-traffic 场景. 总测试数 32 → 40.

### feat(ebpf): 服务端自动跳过 eBPF + ebpf_mode 三态配置
- 服务端跑 eBPF 全部子系统都无价值: sockmap splice 要明文 (服务端入站加密), sockops RTT 没人消费, XDP DNS 只对本地应用有意义, sk_lookup 只劫持本地流量. 之前服务端无条件加载浪费内存/CPU, 还卡 Alpine 用户的 CGROUP_BPF 内核要求.
- CLI 子命令 server/client → `is_server` 参数透传到 `start_proxy`. 服务端默认 (auto 模式) 跳过 eBPF.
- 新增 `tuning.ebpf_mode` 三态:
  - `"auto"` (默认): client 启用, server 跳过
  - `"force"`: 任何情况强制加载 (调试)
  - `"off"`: 任何情况不加载
- README Alpine 章节同步: 服务端 stock `linux-lts` / `linux-virt` 内核可直接用, 不再需要重编内核.

### docs(brutal): brutal_rate_mbps 设计哲学
- 用户反馈默认值 100 Mbps 与 Brutal CC 设计理念背道而驰 — Brutal 是为单连接全速设计, WarmPool 并发多条 brutal 连接各自独立打满设定值, 100 配 pool_size=50 实际需求 5 Gbps, 严重过载.
- install.sh 加 23 行教育性提示 + 默认 100 → 8 Mbps + 超 10 Mbps 时 WARN.
- README 新增 "brutal_rate_mbps 的设计哲学" 章节: 含取值对比表 (8/10/50/100 Mbps × 1G/100M 链路).

## [v0.4.1-alpha.2] - Brutal CC 真·能用了 — TCP_BRUTAL_PARAMS opt 号修正 (2026-06-22)

### Critical Fix (REAL root cause)
- **`TCP_BRUTAL_PARAMS` 常量 23 → 23301**. 标准 Linux 的 `23 = TCP_FASTOPEN`, 内核协议栈先吃掉 setsockopt 不让 brutal 模块看到, TCP_FASTOPEN 在 ESTABLISHED 状态直接返 `-EINVAL`. 实测 `apernet/tcp-brutal` 上游源码确认正确值 `23301` (官方就是为避开 Linux 标准 opt 冲突). 修复两处 (`brutal.rs` + `pool.rs` 动态调节循环).
- **`struct BrutalParams` revert 回 `#[repr(C, packed)]`** (12 字节). 上一版 alpha.1 基于第三方误判把它改成 `#[repr(C)]` (16 字节), 实测拿 `brutal.c` 上游源码确认内核 `struct brutal_params { ... } __packed;` 本就是 packed, sizeof=12. Alpha.1 的"对齐修复"方向错了, alpha.2 一起还原.

### 历史诚实声明
- v0.4.0-alpha.1 ~ v0.4.1-alpha.1 任何启用 `brutal_rate_mbps` 的部署都**从未真正生效**, 因为 opt 号撞 TCP_FASTOPEN. 装了 hysteria-tcp-brutal-dkms 也白装. 静默退回 BBR/Cubic. 用户没发现是因为 `install.sh` 默认 `brutal_rate_mbps=0` 没启用过.
- alpha.2 修完之后, brutal CC 才**真正**第一次工作.

## [v0.4.1-alpha.1] - Fix BrutalParams FFI Alignment + Misleading Log Cleanup (2026-06-22)

### Critical Fix — Brutal CC 从未真正生效过
- **`src/proxy/brutal.rs` + `src/proxy/pool.rs`: `#[repr(C, packed)]` → `#[repr(C)]`**.
  Rust 这边 packed 让 `size_of::<BrutalParams>() = 12`, 但内核 apernet/tcp-brutal 模块的裸 C struct 自然 8 字节对齐 (u64 + u32 + 4B 尾部 padding) → `sizeof = 16`. `setsockopt(optlen=12)` 命中内核 `optlen < sizeof(params) → -EINVAL` 校验, 静默回退到 BBR/Cubic.
- 影响: 任何启用了 `brutal_rate_mbps` 的部署都没真正用上 Brutal CC. 装了 hysteria-tcp-brutal-dkms 模块也白装. 之前用户没报 "TCP_BRUTAL_PARAMS failed" 是因为没人真启用过 (install.sh 默认 0).

### Quality / Log Noise
- 服务端 `first_chunk` 阶段的 `close_notify` 错误降级为 DEBUG (这是 WarmPool Manager 弹性裁剪触发的客户端主动优雅关闭, 不是真错).
- 服务端 `first_chunk` 阶段的 `recv_data timed out!` 降级为 DEBUG (idle warmup 60s reap, 是预期清理).
- WarmPool Manager 主动 evict 过期 tunnel (每 2s 扫一次), 配合客户端 max_age 30-50s 不再等服务端 60s reap.
- GUI: `eBPF ENGINE: ONLINE/OFFLINE` 判定从只看 XDP 改成看 sockmap+sockops 加载状态. 服务端不挂 XDP 但有 sockmap, 之前永远 OFFLINE 误导用户.

## [v0.4.0-alpha.3] - Fix Dead Tunnel Hangs (2026-06-21)

### Critical Fix
- **修复 mixed inbound 走代理"无响应、5 分钟后超时"的诡异 bug**: 服务端 `first_chunk` 超时 5s 和客户端 `Tunnel::max_age_sec` 120-180s 严重错位 → pool 经常发出"客户端以为活着、服务端已 reap"的死 tunnel → handler send_data 写本地 TCP buffer 假成功 → tunnel_reader 永远等不到响应 → 300s 后 handler timeout "gracefully closed".
- 修复: 服务端 5s → **60s**, 客户端 max_age 120-180s → **30-50s 随机**. 两个值必须严格 max_age < first_chunk_timeout, 保证 pool 永不发死 tunnel.
- DOS 论证: first_chunk path 在 token + Poly1305 握手通过后才进入, 60s 不构成 unauth 资源放大; unauth 时段仍由 5s `read_exact tail` 把关.

### Refactor / Test
- `src/proxy/brutal.rs` 共用 helper, pool.rs 删 ~50 行重复 setsockopt 代码 (P1-1 自审项).
- `set_offset_from_server_time` 补 7 个 unit test, 覆盖正/负 offset / 边界 86400 / 异常值不冲掉已有合法值 (P1-2 自审项, 测试 25→32).

## [v0.4.0-alpha.2] - Server-side Brutal CC Actually Works (2026-06-21)

### Fix
- **服务端 brutal_rate_mbps 真接通**: 之前 `InboundConfig::MirageServer` 漏声明这个字段, install.sh 模板里填的值被 serde 静默忽略 → 服务端 accept 的 socket 从未设过 brutal CC. TCP_CONGESTION 是 per-socket per-direction 机制, 服务端这一侧决定下载速度, 比客户端 outbound 重要得多, 之前等于完全没用上.
- 新增 `src/proxy/brutal.rs` 共用 helper, mirage_server 在 accept 后 apply_brutal, 启动时 INFO `Brutal CC enabled for downloads (server→client): N Mbps`.
- 客户端 pool.rs 的动态速率调节保持不动, 后续可再迁服务端.

### Required Action
- 服务端 `config_server.json` 的 `mirage_server` inbound 块需要加 `"brutal_rate_mbps": N` (N 为期望的下载上限, Mbps). 0 或缺省 = 不启用 brutal.
- 服务端机器需装 `hysteria-tcp-brutal-dkms` 内核模块. 没装会 WARN 一次但不影响代理功能 (退回 BBR/Cubic).

## [v0.4.0-alpha.1] - In-band Time Sync + GUI BPF Tunnels API (2026-06-21)

### ⚠️ Breaking Protocol Change (v0.3 ↔ v0.4 不兼容)
- v0.4 服务端会在 crypto channel 建立后立即下发一帧 TIME_SYNC `[0x01][0x01][8B u64 BE]`. v0.3 客户端会把它误读为数据 → 必然挂. **两端必须同时升级**.
- v0.4 客户端撞 v0.3 服务端: 优雅降级 — 3s 超时后 INFO 一条 "proceeding with local time", 仍能工作.

### Protocol: In-band Time Sync (替代 NTP/HTTP 探测)
- 服务端 handshake 完成后通过加密 channel 主动下发自己的 Unix 时间, 客户端写入全局 `TIME_OFFSET`. 0 外部依赖 + 0 指纹 + 自动校正漂移.
- 删除 `src/time_sync.rs` 的 NTP/HTTP 探测代码 (~100 行) 和 `start_time_sync` 后台协程.
- 删除 `chrono` 依赖 (仅旧 HTTP Date 解析用过).
- Token 容忍 ±60s → **±10s**; ReplayCache 桶 5×60s=300s → **3×10s=30s** 窗口.

### GUI: BPF Active Tunnels API
- 新增 `/api/bpf/tunnels` endpoint, 返回 mirage_rtt_map 所有活跃 cookie 的 RTT/cwnd/重传/数据段数.
- `/api/overview` 新增 `tunnel_count` + `brutal_cc_active` 字段.
- 服务端 `mirage_server::start_server` accept 时把客户端 IP 登记到 BPF mirage_target_ips 白名单, 否则 RTT_CB 永远不写 map.

### Deployment Fixes
- **BPF ELF 对齐**: `aya::include_bytes_aligned!` 替代 `include_bytes!` (修 deployment "error parsing ELF data" 三处全部覆盖).
- **CI 加固**: release.yml pin `ubuntu-22.04` (锁 glibc 2.35); 全 target BPF 编译硬验证 (file/readelf/size + post-build ELF magic).
- **sockmap.c verifier 拒绝修复**: extract_ip 把 ctx 字段访问前置到直线代码, 避免 clang 分支合并优化产出 "dereference of modified ctx ptr" 模式.

### UX / Quality
- 服务端不下载 25MB geo 数据 (按 routing.rules 是否引用 geosite/geoip 条件化).
- TCP brutal CC 默认关闭, 配置了 `brutal_rate_mbps` 才尝试启用 (消除大多数用户启动时的 WARN 噪音).
- SockOps 失败时输出具体步骤 (program lookup → type cast → load → cgroup attach), 不再用 catch-all WARN 掩盖真因.
- 非 root 跑客户端时 RTT WARN 降级 INFO + 提示 setcap.
- README 加入内核 ≥ 5.10 兼容性矩阵 + Alpine 内核配置章节 (CGROUP_BPF 等).
- install.sh 客户端默认 `mixed` inbound + 监听 `0.0.0.0`.
- 测试 5 → 25 (新增 tests/test_fake_ip.rs + tests/test_sniff.rs).

## [v0.2.3-alpha] - XDP DNS Acceleration & Fine-Grained CC (2026-06-17)

### XDP DNS Acceleration (Zero-Copy Bypass)
- **NIC-Level Interception**: XDP program (`dns_xdp.c`) binds directly to the NIC via `xdp_interface` config. It hashes incoming DNS QNAMEs (DJB2) and checks an eBPF LRU Cache map.
- **Microsecond Fake-IP Response**: On cache hit, the XDP program modifies MAC/IP/UDP headers and directly injects the Fake-IP answer into the packet via `bpf_xdp_adjust_tail`, calling `XDP_TX` to return the response instantly without traversing the kernel network stack.
- **Decoupled Cache Sync**: XdpEngine has an independent mutex, isolating DNS cache updates from the EbpfEngine's hot paths (sk_skb / sockops / rtt polling). `EbpfEngine` and `XdpEngine` mutexes have been fully decoupled.
- **Fallback Resilience**: Attaches in `DRV_MODE` (native) and gracefully falls back to `SKB_MODE` (generic) for incompatible interfaces (e.g., virtio_net).

### Congestion Control Enhancements
- **Cumulative Loss Rate Mitigation**: Adjusted initial polling of `data_segs_out` with a `u64::MAX` sentinel value to prevent phantom TCP slow-start spikes from triggering unwarranted congestion avoidance drops.
- **Refined Triggers**: Brutal CC congestion mode now exclusively trips when actual packet loss occurs (`loss_rate > 1%`) or significant queuing delay arises (`RTT > 1.5× base`).
- **Configuration Clarity**: `brutal_rate_bps` has been semantically corrected to `brutal_rate_bytes_per_sec` (inclusive of serde alias for backward compatibility).
- **Automated Reproducibility**: `build.rs` natively tracks and compiles `dns_xdp.c` alongside existing map tools.

## [0.3.0-alpha] - 2026-06-18
### ⚠️ Breaking Changes
- `brutal_rate_bps` 和 `brutal_rate_bytes_per_sec` 字段已**移除**。请改用 `brutal_rate_mbps`（单位：Mbps，例如 8 Mbps 配 `"brutal_rate_mbps": 8`）。v0.2.x 配置文件若包含旧字段名将被静默忽略，这会导致 Brutal CC 失效，请务必手动迁移！

### New Features
- **eBPF Transparent Proxy**: Implemented native `sk_lookup` based transparent proxy for kernels >= 5.9.
- **Protocol Sniffing**: TLS SNI and HTTP Host extraction with 2s timeout from transparently hijacked TCP streams without consuming the byte stream.
- **Transparent Inbound**: Added `Transparent` inbound config type that intercepts traffic targeting `fake-ip` blocks directly from the kernel network stack to the user space router.

## [v0.2.2-alpha] - True BDP + Active Tunnel Rate Adjustment (2026-06-17)

### Network-Reactive Brutal CC v2
- **Active Tunnel Brutal Rate Update**: pool maintains `active_fds: HashSet<i32>` of in-flight Pyreality tunnels. RTT-driven dynamic rate adjustment now safely updates **both idle and active tunnels** via batched `spawn_blocking` setsockopt, completely free of RAII-violating async locks to prevent cross-process FD leaks during task aborts.
- **BDP-Derived Congestion Backoff**: dynamic rate correctly uses `cwnd × MSS / RTT` (true BDP estimation in `bytes/sec`) when congestion is detected (RTT > 1.5× base or retrans delta > 0); smooth multiplicative-increase recovery is utilized otherwise.
- **Retransmission-Triggered Backoff**: `total_retrans` increment between polls now flawlessly triggers congestion mode independently of RTT.

## [v0.2.1-alpha] - Network-Reactive Brutal CC (2026-06-17)

### Network-Reactive Brutal CC
- **BPF SOCK_OPS RTT_CB Real-Time Monitoring**: Per-connection SRTT/cwnd/retrans captured via `BPF_SOCK_OPS_RTT_CB_FLAG` in kernel hot path.
- **Dynamic Brutal Rate Adjustment**: User-configurable `brutal_base_rtt_ms` per outbound; pool's idle tunnels dynamically update their TCP_BRUTAL_PARAMS via spawn_blocking when RTT changes significantly, enabling dynamic BDP calculation.
- **IPv4 & IPv6 Sockops Support**: Target IPs elegantly handled with unified family tags in eBPF memory maps.
- **Cgroup Self-Attach Isolation**: Reads `/proc/self/cgroup` to bind `sockops` exclusively to the proxy's own cgroup, preventing system-wide TCP noise and increasing polling speed.

### Known Limitations (v0.2.1)
- Dynamic Brutal rate update currently only applies to idle/new tunnels in the pool; active tunnels keep their initial rate until reconnect.
- Default `brutal_base_rtt_ms` assumes same-city deployment (fallback 50ms); transcontinental nodes should be configured explicitly.

---

## [v0.1.0] - First Official Release (2026-06-15)

### Core Features
- **Pyreality Protocol Implementation**: Fully implemented the Pyreality AEAD protocol with advanced stealth mechanisms (`hello_auth`, timestamp anti-replay, hidden length tags).
- **WarmPool TCP Connection Pool**: Elastic auto-scaling connection pool with SYN-stagger anti-fingerprinting and per-tunnel jitter (120-180s TTL) to prevent thundering-herd reconnect.

### Router Engine (Routing & Diversion)
- **Advanced Conditional Matching**: Added support for advanced logic modes (`mode: "or"`, `mode: "and"`).
- **L2/L3 Routing**: Support for routing via Source MAC Address (`mac`) and Layer-4 Protocol (`protocol: "tcp" | "udp"`).
- **GeoIP / GeoSite Parsing**: High-performance binary parsing for V2Ray `geosite.dat` and `geoip.dat`.
- **Alias Support**: Geodata domain lists now support custom alias naming conventions (e.g., `"geosite:category-ads-all"`).
- **Dynamic Hot-Reloading**: Uses `notify` backend to detect `config.json` changes and swap routing tables instantly via `ArcSwap` without dropping existing TCP streams.

### Web GUI (Built-in Management Panel)
- **Zero Dependency**: The entire frontend SPA (HTML/CSS/JS) is embedded into the Rust binary at compile time via `include_str!`. No external web server needed.
- **Real-Time Traffic Monitor**: Sub-millisecond latency bandwidth monitoring globally tracking upstream and downstream speeds via custom Tokio `AsyncRead` wrapper (`MonitoredReader`).
- **Log Streaming Interface**: Intercepts `tracing` backend logs and exposes them via REST API to a web-based terminal simulator.
- **Node Selection & Status**: Supports parsing `Selector` and `UrlTest` node groups. Fetches and displays median Ping latency dynamically measured by health-check threads.
- **Direct Router Rule Editor**: Web-based raw JSON editor interacting securely with `config.json`, triggering instantaneous engine reloads upon save.

### CI/CD & Build System
- **GitHub Actions Integration**: Cross-compilation scripts established targeting Linux `x86_64` and `aarch64` architectures using `musl` toolchains for standalone static binaries.
- **Cross-Compilation Scripting**: Includes `build_release.sh` using `cross`.

---
## [v0.1.1] - Security & Stability Patch (2026-06-15)

### Security Fixes
- **Slow-loris DDoS Mitigation**: Moved `GLOBAL_UNAUTH` and `IpSlotGuard` rate-limit checks to the very beginning of the unauthenticated connection handler, and enforced a 5-second `timeout` on the fallback `write_all` to prevent zero-window FD exhaustion attacks.
- **CSRF Privilege Escalation Prevention**: Fortified GUI API endpoints by enforcing strict `X-Requested-With: XMLHttpRequest` checks and strictly rejecting requests missing an `Origin` header (unless explicitly identified as CLI tools), closing a critical CSRF vulnerability vector.
- **Constant-Time HMAC Comparison**: Refactored the `poly1305` tag verification in `verify_session_token` to use bitwise XOR accumulation, eliminating theoretical timing attack vectors.

### Stability & Protocol Fixes
- **Double ServerHello Elimination**: Replaced unconditional caching template playback with "Scheme A" (Pure Forwarding). Unauthenticated connections now purely forward the true Apple `ServerHello` from `camouflage_host`, and only fall back to the `HandshakeCache` template if the true host is unreachable. This prevents TLS state-machine violations (unexpected_message RST) when interacting with strict GFW probes.
- **TCP Half-Close Optimization (P2-2)**: Moved `stream.shutdown().await` in `fetch_real_server_hello` to immediately follow the request transmission. This forces the upstream server to send a FIN packet immediately after its response, completely eliminating the 2-second timeout delay previously observed on LAN/loopback environments.
- **TokenReplayCache Optimization**: Replaced `O(N)` bucket removal with `retain()` using a symmetric 300s timestamp sliding window, successfully patching the "backward clock jump" bug. Added `tracing::warn!` logging when bypassing replay checks under extreme DDoS saturation.
- **Telemetry Direction Semantics**: Standardized `is_initiator` tracking in `CryptoReader`/`CryptoWriter` to accurately account for up/down traffic. Documented double-counting behavior on mixed client/server relay nodes.
- **Resource Management**: Implemented `IpSlotGuard` (RAII) to guarantee unauth connection slot cleanup even on sudden task cancellation.
- **Cleanups**: Renamed misleading `BrutalPool` to `WarmPool`. Removed dead `direct_server` config field. Deleted empty Clash API placeholder module.

### Performance & eBPF
- **SIMD Cryptography**: Migrated from RustCrypto `chacha20poly1305` to `ring` for AVX2/SSSE3 hardware acceleration, yielding 2-3x single-core encryption throughput. Also replaced global `rand` lock with `fastrand` thread-local RNG instances.
- **Zero-Copy eBPF Bypass (opt-in)**: eBPF sockmap stream-verdict routing implemented behind `--features ebpf` (kernel ≥ 5.10, default off). Only optimizes Direct outbound paths; Pyreality (encrypted) main flow unaffected. PERCPU_ARRAY stats map, nested epoll(EPOLLRDHUP) for FIN detection, reproducible BPF compilation via `build.rs`.
- **Brutal Congestion Control**: Complete integration of `tcp_brutal` kernel module API (Hysteria2 style). Supports custom `brutal_rate_bps`, explicitly sets `TCP_BRUTAL_PARAMS` (fallback safe via `TCP_CONGESTION` double-verification), and forces 4MB `SO_SNDBUF` with smart `wmem_max` detection.
- **Connection Pool Anti-Thundering-Herd**: Introduced global randomness (Jitter) uniformly distributed between 0-60s on TCP Tunnel TTL expirations to prevent synchronized tunnel teardowns.

*Engineered by Antigravity AI*
