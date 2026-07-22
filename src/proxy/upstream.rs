//! 服务端的**上游出口**抽象 —— 把 Mirage 服务端当中转站时,流量从哪儿再发出去。
//!
//! ```text
//! 客户端 ──(Mirage 隧道)──▶ 本服务端 ──(SS / WireGuard)──▶ 出口 ──▶ 目标
//! ```
//!
//! 之所以要这层枚举而不是继续用 `Option<Arc<SsConfig>>`: 加 WireGuard 上游后,
//! 原先"不是 SS 就当没配上游"的写法会让**配了 WG 却静默走直连** —— 用户以为流量从
//! 落地机出去, 实际从本服务端 IP 裸奔出去, 且毫无提示。这类"悄悄发到别处"的失败模式
//! 必须在类型层面消灭。

use std::sync::Arc;

/// 上游出口。`None`(不配) = 服务端直连目标, 是原行为。
pub enum UpstreamOutlet {
    Shadowsocks(Arc<crate::proxy::shadowsocks::SsConfig>),
    Wireguard(WgUpstream),
}

/// WireGuard 上游。隧道**懒初始化** —— 服务端启动时不建, 第一条要中转的连接才建。
pub struct WgUpstream {
    pub cfg: Arc<crate::proxy::wg::WgConfig>,
    tunnel: tokio::sync::OnceCell<Arc<crate::proxy::wg::tunnel::WgTunnel>>,
    /// UDP 策略。见 [`crate::config::UdpPolicy`]。
    pub udp: crate::config::UdpPolicy,
}

impl WgUpstream {
    pub fn new(cfg: crate::proxy::wg::WgConfig, udp: crate::config::UdpPolicy) -> Self {
        Self {
            cfg: Arc::new(cfg),
            tunnel: tokio::sync::OnceCell::new(),
            udp,
        }
    }

    /// 取(或首次建立)隧道。失败不缓存, 下条连接可重试。
    pub async fn tunnel(&self) -> anyhow::Result<Arc<crate::proxy::wg::tunnel::WgTunnel>> {
        self.tunnel
            .get_or_try_init(|| async {
                crate::proxy::wg::tunnel::WgTunnel::connect(&self.cfg)
                    .await
                    .map(Arc::new)
            })
            .await
            .cloned()
    }
}

impl UpstreamOutlet {
    /// 配了上游时的 UDP 策略。
    ///
    /// - SS: UDP 未实现, 默认 `Block` —— 放行会让 UDP 从**本机 IP** 出去而 TCP 从上游出去,
    ///   出口 IP 不一致, 对落地解锁是功能性错误。
    /// - WireGuard: 默认 `Tunnel` —— WG 隧道能承载 UDP, 出口与 TCP 完全一致, 上面那个
    ///   理由不成立, 所以没必要拒绝。
    pub fn udp_policy(&self) -> crate::config::UdpPolicy {
        match self {
            Self::Shadowsocks(ss) => {
                if ss.block_udp {
                    crate::config::UdpPolicy::Block
                } else {
                    crate::config::UdpPolicy::Direct
                }
            }
            Self::Wireguard(wg) => wg.udp,
        }
    }

    /// 是否拒绝 UDP 中继。
    pub fn block_udp(&self) -> bool {
        matches!(self.udp_policy(), crate::config::UdpPolicy::Block)
    }

    /// 供日志用的简短描述。
    pub fn describe(&self) -> String {
        match self {
            Self::Shadowsocks(ss) => format!("Shadowsocks {}:{}", ss.server, ss.port),
            Self::Wireguard(wg) => format!("WireGuard {}", wg.cfg.endpoint),
        }
    }
}
