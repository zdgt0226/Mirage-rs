# Changelog - Mirage-rs

## [v0.1.0] - First Official Release (2026-06-15)

### Core Features
- **Zero-Copy eBPF Bypass**: Implemented Linux eBPF SockMap for zero-copy socket forwarding, bypassing the userspace network stack.
- **Pyreality Protocol Implementation**: Fully implemented the Pyreality AEAD protocol with advanced stealth mechanisms (`hello_auth`, timestamp anti-replay, hidden length tags).
- **BrutalPool TCP Connection Pool**: Highly concurrent, lock-free connection pooling targeting extreme multiplexing efficiency.

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

*Engineered by Antigravity AI*
