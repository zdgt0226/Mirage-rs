use anyhow::{anyhow, Result};
use std::path::Path;
use std::time::Duration;
use tracing::{debug, error, info};

/// 后台自动下载与更新 Geo 文件
pub async fn start_updater(geodata_dir: String, geosite_url: String, geoip_url: String) {
    tokio::spawn(async move {
        // 初次启动先等 30 秒，避免影响主干流程的启动速度
        tokio::time::sleep(Duration::from_secs(30)).await;
        
        loop {
            info!("GeoUpdater: Starting periodic check for Geo data updates.");

            let _ = update_file(&geodata_dir, "geosite.dat", &geosite_url).await;
            let _ = update_file(&geodata_dir, "geoip.dat", &geoip_url).await;

            // 每天检查一次更新
            tokio::time::sleep(Duration::from_secs(86400)).await;
        }
    });
}

async fn update_file(dir: &str, filename: &str, url: &str) -> Result<()> {
    let path = Path::new(dir).join(filename);
    let tmp_path = Path::new(dir).join(format!("{}.tmp", filename));

    // 1. 发起 HTTP GET 请求
    // 我们不需要显式比较 ETag，因为 CDN/GitHub 通常有缓存机制，直接下载最新版即可。
    // 如果有更高的要求，可以通过 HEAD 请求比对 Last-Modified/ETag，由于文件小，这里直接下载
    debug!("GeoUpdater: Downloading {} from {}", filename, url);
    let resp = match reqwest::get(url).await {
        Ok(r) => r,
        Err(e) => {
            error!("GeoUpdater: Failed to fetch {}: {:?}", url, e);
            return Err(anyhow::anyhow!("Fetch failed"));
        }
    };

    if !resp.status().is_success() {
        error!("GeoUpdater: HTTP error {} for {}", resp.status(), url);
        return Err(anyhow!("HTTP error"));
    }

    let bytes = resp.bytes().await?;

    // 2. 将数据写入临时文件
    // 如果目录不存在则自动创建
    if !Path::new(dir).exists() {
        std::fs::create_dir_all(dir)?;
    }
    std::fs::write(&tmp_path, &bytes)?;

    // 3. 执行原子替换 (Atomic Rename)
    // 这一步极为关键，因为 rename 是原子的，如果在这个时候恰好 Router 正在读取文件，
    // 它依然能通过旧的 inode 把文件读完。同时，这会触发系统的 Inotify 事件，
    // 被我们的 ConfigWatcher 捕获，从而触发 RouterEngine 的无感知热重载。
    if let Err(e) = std::fs::rename(&tmp_path, &path) {
        error!("GeoUpdater: Failed to replace old {}: {}", filename, e);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow!("Rename failed"));
    }

    info!("GeoUpdater: Successfully updated {} ({} bytes)", filename, bytes.len());

    Ok(())
}
