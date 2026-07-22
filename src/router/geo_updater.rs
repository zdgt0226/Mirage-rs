//! 多源 Geo 数据下载与定期更新.
//!
//! v0.4.3 起支持多源 + via=proxy 走代理. 每个 source 独立配置 URL +
//! 下载通道. 文件保存为 `<source.name>.dat`, 路由规则通过 filename:tag 引用
//! (或借助 routing.geo_alias 起短名).
//!
//! via=proxy 会用客户端本地的 socks/mixed inbound 作 SOCKS5 代理. 找不到
//! 可用代理时 fallback direct + WARN.

use anyhow::{anyhow, Result};
use arc_swap::ArcSwap;
use std::collections::HashSet;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

use crate::config::{GeoSource, GeoVia};

/// Updater 的运行时状态. Clone 廉价 (Vec + String, per-reload 才拷).
/// 由 lib.rs 冷启动 + ConfigWatcher 热更新共同维护.
#[derive(Clone)]
pub struct UpdaterState {
    pub geodata_dir: String,
    pub sources: Vec<GeoSource>,
    pub update_days: u32,
    pub proxy_url: Option<String>,
}

/// 更新任务的共享句柄. 内部 ArcSwap 让 updater loop 读到"最新" state,
/// Notify 让 ConfigWatcher 更新后能立刻唤醒 updater (不必等 sleep 结束).
///
/// - `state`: 用 ArcSwap 无锁并发读, updater 循环每次迭代 `.load()` 取快照
/// - `wake`: ConfigWatcher 每次 `update()` 后 `notify_one()`, updater 若在
///   `select!` 里等 sleep 会立刻醒来重跑一轮 (含 sources 由空变非空的场景)
///
/// 修 Issue 4: 老架构 spawn_updater 只在冷启动跑一次, 冷启动无 geo + 热加载
/// 加 geo 会永远不 spawn; 热改 sources/interval 也不生效. 现在冷启动无条件
/// 拉起 updater, sources 空就阻塞在 wake 上不空转, 加了立刻响应.
#[derive(Clone)]
pub struct UpdaterHandle {
    pub state: Arc<ArcSwap<UpdaterState>>,
    pub wake: Arc<Notify>,
}

impl UpdaterHandle {
    pub fn new(initial: UpdaterState) -> Self {
        Self {
            state: Arc::new(ArcSwap::from(Arc::new(initial))),
            wake: Arc::new(Notify::new()),
        }
    }

    /// 更新 state + 唤醒 updater. 幂等, 可从任意线程/协程调.
    pub fn update(&self, new_state: UpdaterState) {
        self.state.store(Arc::new(new_state));
        self.wake.notify_one();
    }
}

/// 启动后台 Geo 数据更新协程. 无条件 spawn, sources 空时阻塞等 wake.
pub async fn spawn_updater(handle: UpdaterHandle) {
    tokio::spawn(async move {
        // 初次启动先等 30 秒，避免影响主干流程的启动速度 + 让 inbound listener 就绪
        tokio::time::sleep(Duration::from_secs(30)).await;

        loop {
            let snap = handle.state.load_full();

            if snap.sources.is_empty() {
                info!("GeoUpdater: no geo_sources configured, waiting for hot-reload...");
                handle.wake.notified().await;
                continue;
            }

            // 校验 name 唯一 (每周期都校验, 用户热改可能引入重名)
            let mut seen = HashSet::new();
            let mut dup = false;
            for s in &snap.sources {
                if !seen.insert(s.name.clone()) {
                    error!(
                        "GeoUpdater: duplicate source name '{}' in tuning.geo_sources. \
                         Two sources sharing a name will overwrite each other's .dat file. \
                         Skipping this cycle, please fix config.",
                        s.name
                    );
                    dup = true;
                    break;
                }
            }
            if dup {
                // 等下一次热改或 60s 后重试
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60)) => {}
                    _ = handle.wake.notified() => {}
                }
                continue;
            }

            info!("GeoUpdater: Starting periodic check for {} source(s).", snap.sources.len());
            for source in &snap.sources {
                let _ = update_one(
                    &snap.geodata_dir,
                    source,
                    snap.proxy_url.as_deref(),
                    snap.update_days,
                )
                .await;
            }

            // 用当前 update_days 决定 interval. drop snap 后再 sleep, 释放 Arc.
            // 防御性 clamp: 主 clamp 在 lib.rs 冷启动 + config_watcher::extract_updater_state
            // 两处. 这里再 max(1) 是 belt+suspenders, 万一将来新增其他 UpdaterState
            // 构造路径没走那两个 clamp, update_days=0 也不会 tight-loop 打满 CPU.
            let days = snap.update_days.max(1) as u64;
            let interval = Duration::from_secs(days * 86_400);
            drop(snap);

            // 定期 sleep, 期间若热更新触发 wake 立刻退出 sleep 重跑
            tokio::select! {
                _ = tokio::time::sleep(interval) => {}
                _ = handle.wake.notified() => {
                    info!("GeoUpdater: woken by config hot-reload, re-running immediately.");
                }
            }
        }
    });
}

async fn update_one(
    dir: &str,
    source: &GeoSource,
    proxy_url: Option<&str>,
    update_days: u32,
) -> Result<()> {
    let filename = format!("{}.dat", source.name);
    let path = Path::new(dir).join(&filename);
    let tmp_path = Path::new(dir).join(format!("{}.tmp", filename));

    // 已有文件且**足够新**就跳过 —— 用文件 mtime 当"上次下载时间"。
    //
    // 少了这一步, 每次进程启动都会无条件重下全部源: 调配置反复重启、崩溃重启循环,
    // 就是一次次几 MB 的重复下载; 弱网/走隧道时更慢, 还可能被 GitHub 限流。
    // (Python 版用 meta.json 存 downloaded_at 解决同一问题; 这里用 mtime 免掉一个
    //  额外的元数据文件 —— rename 后 mtime 就是落地时间, 语义等价。)
    if let Some(age) = file_age(&path) {
        let max_age = Duration::from_secs(update_days.max(1) as u64 * 86_400);
        if age < max_age {
            info!(
                "GeoUpdater: {} 已是最新 (距上次下载 {:.1} 天 < {} 天), 跳过下载",
                filename,
                age.as_secs_f64() / 86_400.0,
                update_days.max(1)
            );
            return Ok(());
        }
        debug!(
            "GeoUpdater: {} 距上次下载 {:.1} 天, 超过 {} 天, 重新下载",
            filename, age.as_secs_f64() / 86_400.0, update_days.max(1)
        );
    }

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
    // ⚠️ **落地前先解析验证**: 能下下来 ≠ 是有效的 geo 数据。
    //
    // 只看大小挡不住"200 但返回 HTML 错误页 / 限流页"这类响应 —— 那种页面几 KB,
    // 能过大小阈值, 却会直接覆盖掉本来好用的 .dat, 导致**规则集体失效**且只有下次
    // 加载时才暴露。这里用真正的解析器过一遍, 解析不了就保留旧文件。
    if let Err(e) = validate_dat(&tmp_path, source.kind) {
        let _ = std::fs::remove_file(&tmp_path);
        error!(
            "GeoUpdater: {} 下载内容不是有效的 {:?} 数据 ({}), 保留原文件不覆盖",
            filename, source.kind, e
        );
        return Err(anyhow!("downloaded data failed validation"));
    }

    if let Err(e) = std::fs::rename(&tmp_path, &path) {
        error!("GeoUpdater: Failed to rename tmp file for {}: {:?}", source.name, e);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow!("Rename failed"));
    }

    info!("GeoUpdater: Successfully updated {} ({} bytes)", filename, bytes.len());
    Ok(())
}

/// 文件距今多久 (拿不到 mtime 或文件不存在返回 None)。
fn file_age(path: &Path) -> Option<Duration> {
    let mtime = std::fs::metadata(path).ok()?.modified().ok()?;
    // 时钟回拨会让 elapsed() 报错; 那种情况按"很旧"处理, 重下一次总比永远不更新好。
    mtime.elapsed().ok()
}

/// 验证下载内容确实是 geo 数据。
///
/// ⚠️ 不能只看"解析有没有报错": `load_geosite_dat`/`load_geoip_dat` 是**宽容**的 ——
/// 不认识的字段直接跳过, 什么都没匹配上时返回 `Ok(空表)`。HTML 错误页/限流页因此也能
/// "解析成功"。改判**里面到底有几个分类**: 真实数据几百个, 垃圾数据 0 个。
fn validate_dat(path: &Path, _kind: crate::config::GeoKind) -> Result<()> {
    let n = crate::router::geo::count_categories(path)?;
    if n == 0 {
        return Err(anyhow!(
            "解析出 0 个分类 —— 多半是 HTML 错误页/限流页而非 geo 数据"
        ));
    }
    Ok(())
}

// 每次 fetch 尝试的最大耗时. 覆盖 connect + TLS + body 全流程. proxy 抽风或
// 服务端出网卡住时不至于挂死整个 updater 循环 (老版本 timeout=None 会永远等).
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
// 下载后至少 N 字节才认为是合法响应. 200 但空 body 的 CDN 边缘缓存 miss 场景
// 直接覆盖旧 .dat 会导致下次 load 失败, 规则集体失效. dlc.dat / geoip.dat
// 正常都 > 1MB, 1 KB 阈值宽松防误伤.
const MIN_VALID_BYTES: usize = 1024;

fn build_client(
    via: GeoVia,
    proxy_url: Option<&str>,
    source_name: &str,
) -> Result<reqwest::Client> {
    let base = reqwest::Client::builder().timeout(FETCH_TIMEOUT);
    match via {
        GeoVia::Direct => Ok(base.build()?),
        GeoVia::Proxy => match proxy_url {
            Some(url) => {
                debug!("GeoUpdater: source '{}' via proxy {}", source_name, url);
                Ok(base.proxy(reqwest::Proxy::all(url)?).build()?)
            }
            None => {
                warn!(
                    "GeoUpdater: source '{}' set via=proxy but no socks/mixed inbound configured. \
                     Falling back to direct fetch.",
                    source_name
                );
                Ok(base.build()?)
            }
        },
    }
}

/// 单次 fetch: send → check status → read body → 校验 body 大小. 所有失败都返 Err.
async fn do_fetch(client: &reqwest::Client, url: &str) -> Result<Vec<u8>> {
    let resp = client.get(url).send().await
        .map_err(|e| anyhow!("send: {}", e))?;
    if !resp.status().is_success() {
        return Err(anyhow!("HTTP {}", resp.status()));
    }
    let bytes = resp.bytes().await
        .map(|b| b.to_vec())
        .map_err(|e| anyhow!("read body: {}", e))?;
    if bytes.len() < MIN_VALID_BYTES {
        return Err(anyhow!(
            "body too small ({} bytes < {}), refusing to overwrite existing .dat",
            bytes.len(), MIN_VALID_BYTES
        ));
    }
    Ok(bytes)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GeoKind;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("geoupd_{}_{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// HTML 错误页 / 限流页必须被拦下 —— 它能过大小阈值, 却会把好用的 .dat 覆盖掉,
    /// 导致规则**集体失效**, 而且要到下次加载才暴露。
    #[test]
    fn html_error_page_fails_validation() {
        let d = tmpdir("html");
        let p = d.join("x.dat");
        // 典型的 GitHub 限流/404 页, 几 KB, 远超 MIN_VALID_BYTES
        let html = format!("<!DOCTYPE html><html><body>{}</body></html>", "rate limited ".repeat(200));
        std::fs::write(&p, &html).unwrap();
        assert!(html.len() > MIN_VALID_BYTES, "构造的样本要能过大小阈值才有意义");

        assert!(
            validate_dat(&p, GeoKind::Geosite).is_err(),
            "HTML 错误页通过了校验 —— 会覆盖掉有效的 .dat"
        );
        assert!(validate_dat(&p, GeoKind::Geoip).is_err());
    }

    /// 截断的文件同样必须被拦下。
    #[test]
    fn truncated_data_fails_validation() {
        let d = tmpdir("trunc");
        let p = d.join("x.dat");
        // 一个声称后面还有很长内容、实际戛然而止的 protobuf 片段
        std::fs::write(&p, [0x0a, 0xff, 0xff, 0x03, 0x01, 0x02]).unwrap();
        assert!(validate_dat(&p, GeoKind::Geosite).is_err(), "截断数据应校验失败");
    }

    /// 正向用例: 合法结构必须**通过**校验。
    ///
    /// 只测"拒绝垃圾"是不够的 —— 校验写太严会把真数据也拦掉, 表现为 geo 永远更新不了,
    /// 而且日志只说"下载内容无效", 根因完全指不到校验本身。
    #[test]
    fn well_formed_dat_passes_validation() {
        fn varint(mut v: u64) -> Vec<u8> {
            let mut o = Vec::new();
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 { o.push(b); break; } else { o.push(b | 0x80); }
            }
            o
        }
        // 顶层 repeated Entry(fn=1,wt=2); Entry 内 code(fn=1,wt=2)
        fn entry(code: &str) -> Vec<u8> {
            let mut inner = varint(1 << 3 | 2);
            inner.extend(varint(code.len() as u64));
            inner.extend(code.as_bytes());
            let mut out = varint(1 << 3 | 2);
            out.extend(varint(inner.len() as u64));
            out.extend(inner);
            out
        }
        let d = tmpdir("ok");
        let p = d.join("x.dat");
        let mut buf = Vec::new();
        for c in ["CN", "GOOGLE", "NETFLIX"] {
            buf.extend(entry(c));
        }
        std::fs::write(&p, &buf).unwrap();

        assert_eq!(crate::router::geo::count_categories(&p).unwrap(), 3);
        assert!(
            validate_dat(&p, GeoKind::Geosite).is_ok(),
            "合法结构被校验拦下了 —— geo 将永远更新不了"
        );
    }

    /// 新鲜度判据: 刚落地的文件不该被重复下载。
    ///
    /// 少了这条, 每次进程启动都会无条件重下全部源 —— 反复重启就是反复几 MB 下载,
    /// 弱网/走隧道更慢, 还可能被上游限流。
    #[test]
    fn fresh_file_is_considered_up_to_date() {
        let d = tmpdir("fresh");
        let p = d.join("x.dat");
        std::fs::write(&p, b"whatever").unwrap();

        let age = file_age(&p).expect("刚写的文件应能取到 age");
        let max_age = Duration::from_secs(7 * 86_400);
        assert!(age < max_age, "刚写的文件 age={age:?} 应远小于 7 天");

        // 不存在的文件必须返回 None (交给下载路径), 而不是被当成"很新"
        assert!(
            file_age(&d.join("nope.dat")).is_none(),
            "文件不存在应返回 None, 否则会被误判成最新而永远不下载"
        );
    }
}
