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
use tokio::sync::Mutex;

/// WG 数据报最大尺寸: 隧道 MTU + WG 头开销, 取 2048 足够 (标准 MTU ≤1500)。
const WG_BUF: usize = 2048;
/// 定时器驱动间隔。WG 协议的重传/轮换都是秒级, 250ms 足够精细又不烧 CPU。
const TIMER_TICK: Duration = Duration::from_millis(250);

/// 一条 WireGuard 隧道的共享状态。pump 任务与调用方 (创建 socket 的一侧) 共用。
pub struct WgTunnel {
    pub(crate) inner: Arc<Mutex<TunnelInner>>,
    /// 隧道内本端地址, 建 smoltcp socket 时作源地址。
    pub local_addr: std::net::IpAddr,
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

        tokio::spawn(pump(inner.clone(), udp, start));

        Ok(Self { inner, local_addr: cfg.address })
    }

    /// 驱动一次 smoltcp poll —— 建/用 socket 后调用, 让状态机立刻推进而非等下个 tick。
    pub(crate) async fn poll_now(&self, start: std::time::Instant) {
        let mut g = self.inner.lock().await;
        let g = &mut *g;
        g.iface.poll(smol_now(start), &mut g.device, &mut g.sockets);
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
    let mut buf = [0u8; WG_BUF];
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
async fn pump(inner: Arc<Mutex<TunnelInner>>, udp: Arc<UdpSocket>, start: std::time::Instant) {
    let mut net_buf = vec![0u8; WG_BUF];
    let mut dec_buf = vec![0u8; WG_BUF];
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
                let mut tbuf = [0u8; WG_BUF];
                if let TunnResult::WriteToNetwork(p) = g.tunn.update_timers(&mut tbuf) {
                    let _ = udp.send(p).await;
                }
                // 定时 poll: smoltcp 的重传/超时也靠它推进。
                g.iface.poll(smol_now(start), &mut g.device, &mut g.sockets);
                drain_tx(g, &udp).await;
            }
        }
    }
}

/// 把 smoltcp 产出的所有出站 IP 包加密发出。
async fn drain_tx(g: &mut TunnelInner, udp: &UdpSocket) {
    let mut buf = [0u8; WG_BUF];
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
}
