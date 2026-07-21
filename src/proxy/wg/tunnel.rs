//! WireGuard 隧道运行时: 异步 pump 把 UDP socket、boringtun `Tunn`、smoltcp 三者串起来。
//!
//! 一个 `WgTunnel` = 一条到某 WG peer 的隧道, 内部跑一个 pump 任务:
//!
//! 1. **收**: UDP recv → `Tunn::decapsulate` → 明文 IP 包 → `WgDevice::push_rx`
//! 2. **poll**: `Interface::poll` 驱动 smoltcp (它消费 rx、产出 tx)
//! 3. **发**: `WgDevice::pop_tx` → `Tunn::encapsulate` → UDP send
//! 4. **定时器**: 周期 `Tunn::update_timers` (握手重试 / 密钥轮换 / keepalive)
//!
//! 三个必须做对、做错就静默不通的点:
//!
//! - `decapsulate` 返回 `WriteToNetwork` 时**必须把包发回网络**(那是握手应答/cookie),
//!   且要**反复用空 datagram 再调**直到 `Done` —— 一次 UDP 报文可能解出多个待发包,
//!   漏了后续调用会卡在握手中间。
//! - `update_timers` 必须周期驱动: 不调则握手永不重试、密钥不轮换、keepalive 不发,
//!   表现为"连一会儿就悄悄断"。
//! - smoltcp 的 `poll` 要在 rx 入队后、tx 出队前调, 否则包在队列里空转一轮。

use super::device::WgDevice;
use super::WgConfig;
use anyhow::{Context, Result};
use boringtun::noise::{Tunn, TunnResult};
use smoltcp::iface::{Config as IfConfig, Interface, SocketSet};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify};

/// 收包缓冲。取 UDP 载荷上限, 免得对端用大 MTU 时 `recv` 静默截断 —— 截断的包
/// 认证必然失败, 表现为"隧道通但偶发丢包", 极难查。每隧道两块, 开销可忽略。
const MAX_DATAGRAM: usize = 65535;
/// boringtun 数据包头开销 (4 类型 + 4 index + 8 counter + 16 tag)。
const WG_DATA_OVERHEAD: usize = 32;
/// 允许的最大隧道 MTU。**超了 boringtun 会 panic 而非报错**
/// (`format_packet_data`: `panic!("The destination buffer is too small")`),
/// 而 pump 跑在 spawn 任务里, panic 只会让隧道静默死掉。故在建隧道时就挡住。
const MAX_MTU: usize = MAX_DATAGRAM - WG_DATA_OVERHEAD;
/// 定时器驱动间隔。WG 协议的重传/轮换都是秒级, 250ms 足够精细又不烧 CPU。
const TIMER_TICK: Duration = Duration::from_millis(250);

/// 一条 WireGuard 隧道的共享状态。pump 任务与调用方 (创建 socket 的一侧) 共用。
///
/// drop 时 pump 任务会被 abort (见 `Drop`) —— pump 持有 `inner` 的 Arc 克隆, 单靠引用计数
/// 永远归不了零, 不显式 abort 就是每条废弃隧道留一个每 250ms 空转的任务。
pub struct WgTunnel {
    pub(crate) inner: Arc<Mutex<TunnelInner>>,
    /// 隧道内本端地址, 建 smoltcp socket 时作源地址。
    pub local_addr: std::net::IpAddr,
    /// smoltcp 单调时钟起点。必须与 pump 用同一个, 否则两边时间轴对不上。
    pub(crate) start: std::time::Instant,
    /// 通知 pump "有出站数据待发", 别干等下个 tick。
    pub(crate) wake: Arc<Notify>,
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for WgTunnel {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

pub(crate) struct TunnelInner {
    pub(crate) tunn: Tunn,
    pub(crate) device: WgDevice,
    pub(crate) iface: Interface,
    pub(crate) sockets: SocketSet<'static>,
    pub(crate) udp: Arc<UdpSocket>,
}

/// smoltcp 需要一个单调时钟。用进程启动起点的相对毫秒。
fn smol_now(start: std::time::Instant) -> SmolInstant {
    SmolInstant::from_millis(start.elapsed().as_millis() as i64)
}

impl WgTunnel {
    /// 建立隧道: 绑本地 UDP、connect 到 peer endpoint、装配 smoltcp 接口, 并起 pump 任务。
    ///
    /// 注意这里**不等握手完成** —— WG 握手由首个数据触发, 或由 `update_timers` 驱动。
    /// 调用方拿到 tunnel 后直接建 socket 即可, smoltcp 的重传会兜住握手期间的丢包。
    pub async fn connect(cfg: &WgConfig) -> Result<Self> {
        if cfg.mtu == 0 || cfg.mtu > MAX_MTU {
            anyhow::bail!(
                "WireGuard mtu 非法: {} (须在 1..={}); 超限会让 boringtun 加密时 panic, \
                 隧道静默失效。常用值 1420。",
                cfg.mtu,
                MAX_MTU
            );
        }
        // 本地绑 0.0.0.0:0; connect 后 send/recv 只与该 peer 通信。
        let udp = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("WireGuard: 绑本地 UDP 失败")?;
        udp.connect(&cfg.endpoint)
            .await
            .with_context(|| format!("WireGuard: 连接 peer endpoint {} 失败", cfg.endpoint))?;
        let udp = Arc::new(udp);

        let tunn = super::build_tunn(cfg, 1);

        let mut device = WgDevice::new(cfg.mtu);
        // Medium::Ip 无硬件地址。
        let if_cfg = IfConfig::new(HardwareAddress::Ip);
        let start = std::time::Instant::now();
        let mut iface = Interface::new(if_cfg, &mut device, smol_now(start));
        iface.update_ip_addrs(|addrs| {
            let cidr = match cfg.address {
                std::net::IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(v4), 32),
                std::net::IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(v6), 128),
            };
            let _ = addrs.push(cidr);
        });

        let inner = Arc::new(Mutex::new(TunnelInner {
            tunn,
            device,
            iface,
            sockets: SocketSet::new(Vec::new()),
            udp: udp.clone(),
        }));

        let wake = Arc::new(Notify::new());
        let pump = tokio::spawn(pump(inner.clone(), udp, start, wake.clone()));

        Ok(Self { inner, local_addr: cfg.address, start, wake, pump })
    }

    /// 驱动一次 smoltcp poll 并叫醒 pump 立刻发包。
    ///
    /// 应用往 smoltcp socket 写完数据后**必须**调用: 否则出站包躺在队列里, 要等下一次
    /// UDP 收包或 250ms tick 才发得出去 —— 每个往返白加最多 250ms 延迟。
    pub(crate) async fn poll_now(&self) {
        {
            let mut g = self.inner.lock().await;
            let g = &mut *g;
            g.iface.poll(smol_now(self.start), &mut g.device, &mut g.sockets);
        }
        self.wake.notify_one();
    }
}

/// 把 `TunnResult::WriteToNetwork` 的包发出去, 并反复用空 datagram 榨干后续待发包。
///
/// **必须循环**: boringtun 一次 decapsulate 可能产生多个待发包 (握手应答 + 排队数据),
/// 只发第一个会卡在握手中途。
async fn flush_network(tunn: &mut Tunn, udp: &UdpSocket, first: Option<&[u8]>) {
    if let Some(p) = first {
        let _ = udp.send(p).await;
    }
    let mut buf = vec![0u8; MAX_DATAGRAM];
    loop {
        match tunn.decapsulate(None, &[], &mut buf) {
            TunnResult::WriteToNetwork(p) => {
                if udp.send(p).await.is_err() {
                    break;
                }
            }
            _ => break,
        }
    }
}

/// pump 主循环。任一步失败只记日志继续 —— 隧道是尽力而为, 单个包出错不该拆掉整条隧道。
async fn pump(
    inner: Arc<Mutex<TunnelInner>>,
    udp: Arc<UdpSocket>,
    start: std::time::Instant,
    wake: Arc<Notify>,
) {
    let mut net_buf = vec![0u8; MAX_DATAGRAM];
    let mut dec_buf = vec![0u8; MAX_DATAGRAM];
    let mut tick = tokio::time::interval(TIMER_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            // ── 收: UDP → decapsulate → smoltcp rx ──
            r = udp.recv(&mut net_buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::debug!("[WG] UDP recv 失败, 隧道退出: {e}");
                        return;
                    }
                };
                let mut g = inner.lock().await;
                let g = &mut *g;
                match g.tunn.decapsulate(None, &net_buf[..n], &mut dec_buf) {
                    TunnResult::WriteToNetwork(p) => {
                        // 握手应答/cookie: 发回去, 并榨干后续包。
                        let p = p.to_vec();
                        flush_network(&mut g.tunn, &udp, Some(&p)).await;
                    }
                    TunnResult::WriteToTunnelV4(pkt, _) | TunnResult::WriteToTunnelV6(pkt, _) => {
                        g.device.push_rx(pkt.to_vec());
                    }
                    TunnResult::Err(e) => tracing::debug!("[WG] decapsulate: {e:?}"),
                    TunnResult::Done => {}
                }
                g.iface.poll(smol_now(start), &mut g.device, &mut g.sockets);
                drain_tx(g, &udp).await;
            }

            // ── 定时器: 握手重试 / 密钥轮换 / keepalive ──
            _ = tick.tick() => {
                let mut g = inner.lock().await;
                let g = &mut *g;
                let mut tbuf = vec![0u8; MAX_DATAGRAM];
                if let TunnResult::WriteToNetwork(p) = g.tunn.update_timers(&mut tbuf) {
                    let _ = udp.send(p).await;
                }
                // 定时 poll: smoltcp 的重传/超时也靠它推进。
                g.iface.poll(smol_now(start), &mut g.device, &mut g.sockets);
                drain_tx(g, &udp).await;
            }

            // ── 被叫醒: 应用刚写了数据, 立刻发, 别等 tick ──
            _ = wake.notified() => {
                let mut g = inner.lock().await;
                let g = &mut *g;
                g.iface.poll(smol_now(start), &mut g.device, &mut g.sockets);
                drain_tx(g, &udp).await;
            }
        }
    }
}

/// 把 smoltcp 产出的所有出站 IP 包加密发出。
async fn drain_tx(g: &mut TunnelInner, udp: &UdpSocket) {
    let mut buf = vec![0u8; MAX_DATAGRAM];
    while let Some(pkt) = g.device.pop_tx() {
        match g.tunn.encapsulate(&pkt, &mut buf) {
            TunnResult::WriteToNetwork(p) => {
                if udp.send(p).await.is_err() {
                    return;
                }
            }
            TunnResult::Err(e) => tracing::debug!("[WG] encapsulate: {e:?}"),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 隧道能建立且不阻塞: connect 只做 bind/connect + 装配, **不等握手**。
    /// (对端是黑洞地址, 握手不会成功, 但 connect 必须立刻返回。)
    #[tokio::test]
    async fn connect_does_not_block_on_handshake() {
        let cfg = WgConfig {
            private_key: [0x01u8; 32],
            peer_public_key: [0x02u8; 32],
            preshared_key: None,
            // 保留段, 不会有回应
            endpoint: "192.0.2.1:51820".into(),
            address: "10.0.0.2".parse().unwrap(),
            mtu: 1420,
            persistent_keepalive: None,
        };
        let t = tokio::time::timeout(Duration::from_secs(3), WgTunnel::connect(&cfg))
            .await
            .expect("connect 不该阻塞等握手")
            .expect("建隧道应成功");
        assert_eq!(t.local_addr, cfg.address);
    }

    /// pump 起来后应主动发出握手 initiation —— 证明定时器真在驱动 Tunn。
    /// 用一个本地 UDP socket 冒充 peer, 收第一个包检查是不是 WG handshake-init。
    #[tokio::test]
    async fn pump_sends_handshake_to_peer() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let cfg = WgConfig {
            private_key: [0x03u8; 32],
            peer_public_key: [0x04u8; 32],
            preshared_key: None,
            endpoint: peer_addr.to_string(),
            address: "10.0.0.2".parse().unwrap(),
            mtu: 1420,
            // 开 keepalive, 让定时器有活干
            persistent_keepalive: Some(1),
        };
        let _t = WgTunnel::connect(&cfg).await.unwrap();

        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
            .await
            .expect("5s 内应收到 WG 握手包 (说明 pump 定时器在驱动)")
            .unwrap();
        assert_eq!(buf[0], 1, "应为 handshake initiation (type=1)");
        assert_eq!(n, 148, "handshake-init 固定 148 字节");
    }

    fn cfg_to(endpoint: String, mtu: usize) -> WgConfig {
        WgConfig {
            private_key: [0x05u8; 32],
            peer_public_key: [0x06u8; 32],
            preshared_key: None,
            endpoint,
            address: "10.0.0.2".parse().unwrap(),
            mtu,
            persistent_keepalive: Some(1),
        }
    }

    /// MTU 超限必须在建隧道时就报错。放过去的话 boringtun 加密时会
    /// `panic!("The destination buffer is too small")`, 而 pump 在 spawn 任务里,
    /// panic 只让隧道静默死掉 —— 用户看到的是"配好了但什么都不通", 根因指不到 MTU。
    #[tokio::test]
    async fn oversized_mtu_is_rejected_not_panicking_later() {
        let e = match WgTunnel::connect(&cfg_to("127.0.0.1:1".into(), MAX_MTU + 1)).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("超限 MTU 必须被拒"),
        };
        assert!(e.contains("mtu 非法"), "实际: {e}");
        // 0 也不合法
        assert!(WgTunnel::connect(&cfg_to("127.0.0.1:1".into(), 0)).await.is_err());
    }

    /// 隧道 drop 后 pump 任务必须停。pump 持有 inner 的 Arc 克隆, 光靠引用计数永远
    /// 归不了零 —— 不 abort 的话每条废弃隧道都留一个每 250ms 空转的任务, 长跑必然堆积。
    ///
    /// 判据是**引用计数**而非"drop 后还收不收得到包": 发完首个握手 init 后 boringtun 会
    /// 标记握手进行中, `update_timers` 在 REKEY_TIMEOUT(5s) 内一律返回 Done, 短窗口里
    /// 死活两种情况都收不到包 —— 那种测试恒过, 证明不了任何事 (本测试初版就踩了这个坑)。
    #[tokio::test]
    async fn dropping_tunnel_stops_pump() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let t = WgTunnel::connect(&cfg_to(peer_addr.to_string(), 1420)).await.unwrap();

        // 先确认 pump 活着 (收到握手包)
        let mut buf = [0u8; 2048];
        tokio::time::timeout(Duration::from_secs(5), peer.recv_from(&mut buf))
            .await
            .expect("pump 应先是活的")
            .unwrap();

        // 留一个引用, 用来观察 pump 是否释放了它那份
        let watch = t.inner.clone();
        assert!(Arc::strong_count(&watch) >= 2, "pump 应持有 inner 的克隆");

        drop(t);

        // abort 后任务在下次调度时被取消并释放捕获的 Arc。轮询等待, 最多 2s。
        let mut count = 0;
        for _ in 0..200 {
            count = Arc::strong_count(&watch);
            if count == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(count, 1, "隧道 drop 后 pump 仍持有 inner —— 任务泄漏了");
    }
}
