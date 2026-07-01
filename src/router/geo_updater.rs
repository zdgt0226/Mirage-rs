//! 多源 Geo 数据下载与定期更新.
//!
//! v0.4.3 起支持多源 + via=proxy 走代理. 每个 source 独立配置 URL +
//! 下载通道. 文件保存为 `<source.name>.dat`, 路由规则通过 filename:tag 引用
//! (或借助 routing.geo_alias 起短名).
//!
//! via=proxy 会用客户端本地的 socks/mixed inbound 作 SOCKS5 代理. 找不到
//! 可用代理时 fallback direct + WARN.

use anyhow::{anyhow, Result};
use std::collections::HashSet;
use std::path::Path;
use std::time::Duration;
use tracing::{debug, error, info, warn};

use crate::config::{GeoSource, GeoVia};

/// 启动后台 Geo 数据更新协程.
///
/// `proxy_url` 为客户端本地 SOCKS5 代理 (从 inbounds 推导), 形如
/// `socks5://127.0.0.1:1080`. 仅 `via=proxy` 的 source 会用它; 没传或为 None
/// 时 via=proxy 的 source 会 fallback direct + WARN.
pub async fn spawn_updater(
    geodata_dir: String,
    sources: Vec<GeoSource>,
    update_days: u32,
    proxy_url: Option<String>,
) {
    if sources.is_empty() {
        info!("GeoUpdater: no geo_sources configured, skipping.");
        return;
    }

    // 校验 name 唯一性 (不同 source 写同 name 会互相覆盖文件, 拒绝启动)
    let mut seen = HashSet::new();
    for s in &sources {
        if !seen.insert(s.name.clone()) {
            error!(
                "GeoUpdater: duplicate source name '{}' in tuning.geo_sources. \
                 Two sources sharing a name will overwrite each other's .dat file. \
                 Updater not started.",
                s.name
            );
            return;
        }
    }

    tokio::spawn(async move {
        // 初次启动先等 30 秒，避免影响主干流程的启动速度 + 让 inbound listener 就绪
        tokio::time::sleep(Duration::from_secs(30)).await;

        let interval = Duration::from_secs(update_days as u64 * 86_400);
        loop {
            info!("GeoUpdater: Starting periodic check for {} source(s).", sources.len());

            for source in &sources {
                let _ = update_one(&geodata_dir, source, proxy_url.as_deref()).await;
            }

            tokio::time::sleep(interval).await;
        }
    });
}

async fn update_one(dir: &str, source: &GeoSource, proxy_url: Option<&str>) -> Result<()> {
    let filename = format!("{}.dat", source.name);
    let path = Path::new(dir).join(&filename);
    let tmp_path = Path::new(dir).join(format!("{}.tmp", filename));

    debug!(
        "GeoUpdater: Downloading {} (kind={:?}, via={:?}) from {}",
        source.name, source.kind, source.via, source.url
    );

    // Fetch with automatic fallback: via=proxy 失败时 (connect/HTTP error /
    // body read error) 自动重试一次 direct. 大陆用户 config 默认 via=proxy
    // 走 mirage 代理拿, 服务端出网了就能穿墙 GitHub; 代理不通时也仍能靠
    // 直连拉回来 (至少偶尔 GitHub 直连能过).
    let bytes = fetch_with_fallback(source, proxy_url).await?;

    // 写到 .tmp 再原子重命名, 避免下载中途文件损坏被读
    if !Path::new(dir).exists() {
        std::fs::create_dir_all(dir)?;
    }
    if let Err(e) = std::fs::write(&tmp_path, &bytes) {
        error!("GeoUpdater: Failed to write tmp file for {}: {:?}", source.name, e);
        return Err(anyhow!("Write tmp failed"));
    }
    if let Err(e) = std::fs::rename(&tmp_path, &path) {
        error!("GeoUpdater: Failed to rename tmp file for {}: {:?}", source.name, e);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow!("Rename failed"));
    }

    info!("GeoUpdater: Successfully updated {} ({} bytes)", filename, bytes.len());
    Ok(())
}

fn build_client(
    via: GeoVia,
    proxy_url: Option<&str>,
    source_name: &str,
) -> Result<reqwest::Client> {
    match via {
        GeoVia::Direct => Ok(reqwest::Client::builder().build()?),
        GeoVia::Proxy => match proxy_url {
            Some(url) => {
                debug!("GeoUpdater: source '{}' via proxy {}", source_name, url);
                Ok(reqwest::Client::builder()
                    .proxy(reqwest::Proxy::all(url)?)
                    .build()?)
            }
            None => {
                warn!(
                    "GeoUpdater: source '{}' set via=proxy but no socks/mixed inbound configured. \
                     Falling back to direct fetch.",
                    source_name
                );
                Ok(reqwest::Client::builder().build()?)
            }
        },
    }
}

/// 单次 fetch: send → check status → read body. 所有失败都返 Err.
async fn do_fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await
        .map_err(|e| anyhow!("send: {}", e))?;
    if !resp.status().is_success() {
        return Err(anyhow!("HTTP {}", resp.status()));
    }
    resp.bytes().await
        .map(|b| b.to_vec())
        .map_err(|e| anyhow!("read body: {}", e))
}

/// 带 fallback 的 fetch: 主要按 source.via 走, 失败且原是 Proxy 时自动
/// 重试一次 Direct. 便于配置默认 via=proxy 时不至于因为 mirage 出网抖动
/// 而拉不到 geo. 两次都失败视为整体失败.
async fn fetch_with_fallback(
    source: &GeoSource,
    proxy_url: Option<&str>,
) -> Result<Vec<u8>> {
    let primary_client = build_client(source.via, proxy_url, &source.name)?;
    match do_fetch(&primary_client, &source.url).await {
        Ok(b) => Ok(b),
        Err(e) if matches!(source.via, GeoVia::Proxy) => {
            warn!(
                "GeoUpdater: source '{}' via proxy failed ({}), retrying via direct",
                source.name, e
            );
            let direct_client = build_client(GeoVia::Direct, None, &source.name)?;
            match do_fetch(&direct_client, &source.url).await {
                Ok(b) => {
                    info!("GeoUpdater: direct fallback succeeded for '{}'", source.name);
                    Ok(b)
                }
                Err(e2) => {
                    error!(
                        "GeoUpdater: source '{}' both proxy and direct failed. proxy err: {}, direct err: {}",
                        source.name, e, e2
                    );
                    Err(anyhow!("both proxy and direct fetch failed"))
                }
            }
        }
        Err(e) => {
            error!("GeoUpdater: source '{}' fetch failed: {}", source.name, e);
            Err(anyhow!("Fetch failed"))
        }
    }
}
