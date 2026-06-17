# Changelog - Mirage-rs

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
