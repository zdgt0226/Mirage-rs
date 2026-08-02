//! 内部临时 SOCKS5: 仅绑回环、免认证, 供**进程内消费者** (当前是 geo 下载) 经隧道出网,
//! 不依赖用户配置任何 socks/mixed 入站。
//!
//! 背景: geo `via: proxy` 要经隧道下载 (中国直连 GitHub 被墙), 但透明网关模式下没有 socks
//! 入站, 此前只能自连用户的 socks 入站 (还得过其认证, 见 brain unified-outbound-stream 记的
//! auth bug)。这里进程内自动起一个 SOCKS, reqwest 用它当代理 —— TLS/重定向/HTTP 全复用
//! reqwest, 我们只提供"经隧道拨号"。用户看不见、不用配, 等价于 sing-box 的 download_detour。
//!
//! 路由: 复用 handler::handle_client —— 每个 CONNECT 走**完整路由** (router 按规则选出站),
//! 所以 geo 仍受路由规则控制 (可让 geo 走特定出站), 不写死某条隧道。

use std::sync::Arc;

use arc_swap::ArcSwap;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::config_watcher::CoreState;

/// 绑一个仅回环的临时端口, 返回 (listener, `socks5://127.0.0.1:port`)。
/// 先绑 (拿到 URL 交给 geo updater), accept 循环等 CoreState 就绪后再由 [`serve`] 起。
pub async fn bind_loopback() -> anyhow::Result<(TcpListener, String)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    Ok((listener, format!("socks5://127.0.0.1:{port}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn bind_loopback_gives_valid_loopback_socks_url() {
        let (listener, url) = bind_loopback().await.unwrap();
        assert!(url.starts_with("socks5://127.0.0.1:"), "应是回环 socks5 URL: {url}");
        // 端口真的在监听: 能 TCP 连上 (未起 accept 循环, 连接进 backlog 即算通)。
        let port = listener.local_addr().unwrap().port();
        let _c = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    }
}

/// 起 accept 循环: 每个连接交给标准 socks 入站处理器 (免认证, 走完整路由)。
pub fn serve(listener: TcpListener, state: Arc<ArcSwap<CoreState>>) {
    let tag: Arc<str> = Arc::from("internal-geo");
    info!("内部 geo SOCKS 已就绪 (回环, 免认证, 供 via=proxy 经隧道下载)");
    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((conn, _peer)) => {
                    let st = state.clone();
                    let tg = tag.clone();
                    tokio::spawn(async move {
                        // ebpf/fake_ip 对 geo (真实域名, 经 router 正常解析) 无关, 传 None;
                        // auth None = 免认证 (仅回环, 内部用)。
                        crate::proxy::handler::handle_client(conn, st, None, None, None, Some(tg)).await;
                    });
                }
                Err(e) => {
                    warn!("内部 geo SOCKS accept 失败: {e}");
                    // 短暂退避避免忙循环 (罕见: fd 耗尽等)。
                    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                }
            }
        }
    });
}
