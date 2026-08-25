pub mod brutal;
#[cfg(feature = "quic")]
pub mod quic;
#[cfg(feature = "quic")]
pub mod quic_cc;
#[cfg(feature = "quic")]
pub mod quic_obfs;
pub mod pool;
pub mod tunnel;
pub mod mirage_stream;
pub mod internal_socks;
pub mod ss_inbound;
pub mod ss_stream;
pub mod socks5;
pub mod handler;
pub mod udp_relay;
pub mod outbound;
pub mod mirage_server;
pub mod mixed;
pub mod healthcheck;
pub mod transparent;
pub mod transparent_udp;
pub mod udp_mux;
pub mod sniff;
pub mod splice;
pub mod resolver;
pub mod shadowsocks;
pub mod upstream;
pub mod wg;
pub mod transparent_net;
pub mod probe;
pub mod proc_lookup;
pub mod rate_limit;

/// Mirage **TCP 隧道 relay 的空闲超时** (每次 read/recv 无数据满此值才断, 非绝对寿命)。
/// 默认 1800s (30min, 给 SSH/视频/大下载/长连接留余量), 可用环境变量 `MIRAGE_RELAY_IDLE` (秒)
/// 覆盖。资源受限或高频短连接场景 (软路由 / 低配 VPS / 移动端) 可调小防僵尸连接钉住 task+缓冲
/// (移动端实测 300s 更稳)。客户端 (`handler`) 与服务端 (`mirage_server::tcp_relay`) 共用此值 ——
/// **两端须同设**才保持"一致不互相早关"。解析失败/非数字回落 1800; 下限 5s (防病态 0 无限斩断)。
/// 进程内只读一次 env (缓存)。
pub(crate) fn relay_idle() -> std::time::Duration {
    use std::sync::OnceLock;
    static V: OnceLock<std::time::Duration> = OnceLock::new();
    *V.get_or_init(|| {
        let secs = std::env::var("MIRAGE_RELAY_IDLE")
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|s| s.max(5))
            .unwrap_or(1800);
        std::time::Duration::from_secs(secs)
    })
}
