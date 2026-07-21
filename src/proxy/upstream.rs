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
    /// UDP 是否拒绝中继。见 [`crate::config::UdpPolicy`]。
    pub block_udp: bool,
}

impl WgUpstream {
    pub fn new(cfg: crate::proxy::wg::WgConfig, block_udp: bool) -> Self {
        Self {
            cfg: Arc::new(cfg),
            tunnel: tokio::sync::OnceCell::new(),
            block_udp,
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
    /// 配了上游时是否拒绝 UDP 中继。
    ///
    /// 两种上游目前都默认拒绝, 理由相同: UDP 尚未接到上游通道上, 放行会让 UDP 从
    /// **本机 IP** 直连出去而 TCP 从上游出去 —— 出口 IP 不一致, 对落地解锁是功能性错误。
    pub fn block_udp(&self) -> bool {
        match self {
            Self::Shadowsocks(ss) => ss.block_udp,
            Self::Wireguard(wg) => wg.block_udp,
        }
    }

    /// 供日志用的简短描述。
    pub fn describe(&self) -> String {
        match self {
            Self::Shadowsocks(ss) => format!("Shadowsocks {}:{}", ss.server, ss.port),
            Self::Wireguard(wg) => format!("WireGuard {}", wg.cfg.endpoint),
        }
    }
}
