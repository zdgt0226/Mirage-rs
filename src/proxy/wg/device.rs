//! `WgDevice` —— smoltcp `phy::Device` 与 WireGuard 隧道之间的桥接层。
//!
//! smoltcp 要一个"网卡"来收发 **IP 包**。WG 隧道正好也是 IP 包进出, 所以这层不做协议转换,
//! 只做队列搬运:
//!
//! ```text
//!   pump 任务: UDP socket ─decapsulate→ push_rx(明文 IP 包)
//!                                            │
//!                                     ┌──────▼──────┐
//!                                     │  rx 队列     │
//!   smoltcp Interface::poll ──receive─┤             │
//!                            ──transmit→ tx 队列    │
//!                                     └──────┬──────┘
//!                                            │
//!   pump 任务: pop_tx(明文 IP 包) ─encapsulate→ UDP socket
//! ```
//!
//! 为什么用队列而非直接调 boringtun: smoltcp 的 `Device` 是**同步**接口 (`receive`/`transmit`
//! 不能 await), 而 UDP 收发与 `Tunn` 定时器是异步的。队列把两边解耦 —— Device 侧纯同步操作
//! VecDeque, 异步 pump 侧负责真正的加解密与网络 IO。
//!
//! 队列有上限: 隧道拥塞或对端不回时无限堆积会 OOM。满了丢最老的包 —— IP 层本就尽力而为,
//! 丢包由上层 TCP 重传兜住 (UDP 则本就允许丢)。

use smoltcp::phy::{self, Device, DeviceCapabilities, Medium};
use smoltcp::time::Instant;
use std::collections::VecDeque;

/// 单向队列的包数上限。1420B MTU 下 256 包 ≈ 363KB, 够吸收突发又不至于 OOM。
const QUEUE_CAP: usize = 256;

/// smoltcp 网卡实现: 两个 IP 包队列。
pub struct WgDevice {
    /// 待交给 smoltcp 的入站 IP 包 (已由 Tunn 解密)。
    rx: VecDeque<Vec<u8>>,
    /// smoltcp 产出、待经 Tunn 加密发出的出站 IP 包。
    tx: VecDeque<Vec<u8>>,
    mtu: usize,
}

impl WgDevice {
    pub fn new(mtu: usize) -> Self {
        Self { rx: VecDeque::new(), tx: VecDeque::new(), mtu }
    }

    /// pump 侧: 塞一个解密后的入站 IP 包给 smoltcp。队列满则丢最老的。
    pub fn push_rx(&mut self, pkt: Vec<u8>) {
        if self.rx.len() >= QUEUE_CAP {
            self.rx.pop_front();
        }
        self.rx.push_back(pkt);
    }

    /// pump 侧: 取一个 smoltcp 产出的出站 IP 包去加密发送。
    pub fn pop_tx(&mut self) -> Option<Vec<u8>> {
        self.tx.pop_front()
    }

}

pub struct WgRxToken(Vec<u8>);
pub struct WgTxToken<'a>(&'a mut VecDeque<Vec<u8>>);

impl phy::RxToken for WgRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

impl phy::TxToken for WgTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buf = vec![0u8; len];
        let r = f(&mut buf);
        // 与 rx 同样的上限保护: 隧道堵住时别把出站队列撑爆。
        if self.0.len() >= QUEUE_CAP {
            self.0.pop_front();
        }
        self.0.push_back(buf);
        r
    }
}

impl Device for WgDevice {
    type RxToken<'a> = WgRxToken where Self: 'a;
    type TxToken<'a> = WgTxToken<'a> where Self: 'a;

    fn receive(&mut self, _t: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        // 必须先取出 rx 包再借 tx 队列 —— 否则同时可变借用 self 的两个字段过不了借用检查。
        let pkt = self.rx.pop_front()?;
        Some((WgRxToken(pkt), WgTxToken(&mut self.tx)))
    }

    fn transmit(&mut self, _t: Instant) -> Option<Self::TxToken<'_>> {
        Some(WgTxToken(&mut self.tx))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut c = DeviceCapabilities::default();
        // Medium::Ip = 裸 IP 包, 无以太网头/ARP —— WG 隧道正是这个模型。
        c.medium = Medium::Ip;
        c.max_transmission_unit = self.mtu;
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::phy::{RxToken, TxToken};

    #[test]
    fn capabilities_are_ip_medium() {
        let d = WgDevice::new(1420);
        let c = d.capabilities();
        assert_eq!(c.medium, Medium::Ip, "WG 隧道跑裸 IP 包, 不能是 Ethernet");
        assert_eq!(c.max_transmission_unit, 1420);
    }

    #[test]
    fn rx_roundtrip_delivers_packet_once() {
        let mut d = WgDevice::new(1420);
        assert!(d.receive(Instant::from_millis(0)).is_none(), "空队列不该产出 token");

        d.push_rx(vec![0xAA, 0xBB, 0xCC]);
        let (rxt, _txt) = d.receive(Instant::from_millis(0)).expect("应有包");
        let got = rxt.consume(|b| b.to_vec());
        assert_eq!(got, vec![0xAA, 0xBB, 0xCC]);
        // 消费掉后队列应空 —— 同一个包不能被投递两次
        assert!(d.receive(Instant::from_millis(0)).is_none());
    }

    #[test]
    fn tx_token_enqueues_for_pump() {
        let mut d = WgDevice::new(1420);
        let t = d.transmit(Instant::from_millis(0)).unwrap();
        t.consume(4, |buf| buf.copy_from_slice(&[1, 2, 3, 4]));
        assert_eq!(d.pop_tx().unwrap(), vec![1, 2, 3, 4]);
        assert!(d.pop_tx().is_none());
    }

    #[test]
    fn queues_are_bounded_dropping_oldest() {
        let mut d = WgDevice::new(1420);
        // 灌满 + 溢出: 队列不能无限涨 (隧道堵住时会 OOM)
        for i in 0..(QUEUE_CAP + 10) {
            d.push_rx(vec![i as u8]);
        }
        let mut n = 0;
        while let Some((rxt, _)) = d.receive(Instant::from_millis(0)) {
            let first = rxt.consume(|b| b[0]);
            if n == 0 {
                // 丢的是最老的 10 个, 首包应是第 10 个
                assert_eq!(first, 10, "满队列应丢最老的包");
            }
            n += 1;
        }
        assert_eq!(n, QUEUE_CAP, "队列长度必须封顶在 QUEUE_CAP");
    }
}
