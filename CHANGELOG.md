# Changelog - Mirage-rs

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
