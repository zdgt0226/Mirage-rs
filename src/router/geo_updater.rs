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
            let mut meta = read_meta(&snap.geodata_dir);
            for source in &snap.sources {
                let _ = update_one(
                    &snap.geodata_dir,
                    source,
                    snap.proxy_url.as_deref(),
                    snap.update_days,
                    &mut meta,
                )
                .await;
            }
            // 一轮结束统一落盘: 逐源写会放大 IO, 且中途崩溃时两种写法的损失一样
            // (meta 丢了最多多下一次, 不影响正确性)。
            write_meta(&snap.geodata_dir, &meta);

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

/// 更新元数据: 每个源记下条件请求验证器与落地时间。
///
/// 存在的理由: ETag/Last-Modified 必须**跨进程重启**保留才有意义 —— 否则每次启动都是
/// 无条件全量下载。`downloaded_at` 同理, 且比文件 mtime 更可靠 (304 时文件没被重写,
/// mtime 不会变, 只有显式记一笔才能让新鲜度判据往前走)。
#[derive(Default, serde::Serialize, serde::Deserialize)]
struct MetaFile {
    #[serde(default)]
    sources: std::collections::HashMap<String, SourceMeta>,
}

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct SourceMeta {
    #[serde(default, flatten)]
    validators: Validators,
    /// Unix 秒。
    #[serde(default)]
    downloaded_at: u64,
}

fn meta_path(dir: &str) -> std::path::PathBuf {
    Path::new(dir).join("meta.json")
}

/// 读元数据。任何问题 (不存在/损坏) 都退回空表 —— 元数据只是优化, 丢了最多多下一次。
fn read_meta(dir: &str) -> MetaFile {
    std::fs::read_to_string(meta_path(dir))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

/// 原子写元数据 (tmp + rename), 写失败只记日志不影响主流程。
fn write_meta(dir: &str, meta: &MetaFile) {
    let path = meta_path(dir);
    let tmp = path.with_extension("json.tmp");
    match serde_json::to_vec_pretty(meta) {
        Ok(bytes) => {
            if std::fs::write(&tmp, bytes).is_ok() && std::fs::rename(&tmp, &path).is_ok() {
                return;
            }
            let _ = std::fs::remove_file(&tmp);
            warn!("GeoUpdater: 写 meta.json 失败, 下次启动会退回无条件下载");
        }
        Err(e) => warn!("GeoUpdater: 序列化 meta.json 失败: {}", e),
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

async fn update_one(
    dir: &str,
    source: &GeoSource,
    proxy_url: Option<&str>,
    update_days: u32,
    meta: &mut MetaFile,
) -> Result<()> {
    let filename = format!("{}.dat", source.name);
    let path = Path::new(dir).join(&filename);
    let tmp_path = Path::new(dir).join(format!("{}.tmp", filename));
    let exists = path.exists();

    // ── 新鲜度: 够新就完全不发请求 ──
    //
    // 少了这一步, 每次进程启动都会重下全部源 —— 调配置反复重启、崩溃重启循环, 就是一次次
    // 几 MB 的重复下载; 弱网或走隧道时更慢, 还可能被上游 (GitHub) 限流。
    // downloaded_at 优先取 meta (304 时文件没被重写, mtime 不动, 只有 meta 记得住);
    // meta 丢了则退回文件 mtime。
    let max_age = Duration::from_secs(update_days.max(1) as u64 * 86_400);
    if exists {
        let age = meta
            .sources
            .get(&source.name)
            .filter(|m| m.downloaded_at > 0)
            .map(|m| Duration::from_secs(now_secs().saturating_sub(m.downloaded_at)))
            .or_else(|| file_age(&path));
        if let Some(age) = age {
            if age < max_age {
                info!(
                    "GeoUpdater: {} 已是最新 (距上次 {:.1} 天 < {} 天), 跳过",
                    filename,
                    age.as_secs_f64() / 86_400.0,
                    update_days.max(1)
                );
                return Ok(());
            }
        }
    }

    // ── 条件请求验证器: **仅当本地文件还在时**才带 ──
    //
    // 否则会出现"上游回 304 说你已是最新, 而本地 .dat 早被删了"的尴尬 —— 结果是永远
    // 拿不到文件。(Python 版踩过同款, 明确注释了这点。)
    let cond = if exists {
        meta.sources.get(&source.name).map(|m| m.validators.clone())
    } else {
        None
    };

    debug!(
        "GeoUpdater: 下载 {} (kind={:?}, via={:?}, {} 个镜像)",
        source.name, source.kind, source.via, source.url.len()
    );

    let (bytes, validators) = match fetch_with_fallback(source, proxy_url, cond.as_ref()).await? {
        FetchOutcome::NotModified => {
            // 上游没变: 不重下, 但要把"刚校验过"记一笔, 否则每个周期都会再问一次。
            info!("GeoUpdater: {} 上游未变更 (304), 复用本地文件", filename);
            let e = meta.sources.entry(source.name.clone()).or_default();
            e.downloaded_at = now_secs();
            return Ok(());
        }
        FetchOutcome::Body(b, v) => (b, v),
    };

    // 写到 .tmp 再原子重命名, 避免下载中途文件损坏被读
    if !Path::new(dir).exists() {
        std::fs::create_dir_all(dir)?;
    }
    if let Err(e) = std::fs::write(&tmp_path, &bytes) {
        error!("GeoUpdater: 写 {} 的临时文件失败: {:?}", source.name, e);
        return Err(anyhow!("Write tmp failed"));
    }

    // ⚠️ **落地前先校验**: 能下下来 ≠ 是有效的 geo 数据。
    //
    // 只看大小挡不住"200 但返回 HTML 错误页/限流页"这类响应 —— 那种页面几 KB, 能过大小
    // 阈值, 却会直接覆盖掉本来好用的 .dat, 导致**规则集体失效**且只有下次加载时才暴露。
    if let Err(e) = validate_dat(&tmp_path, source.kind) {
        let _ = std::fs::remove_file(&tmp_path);
        error!(
            "GeoUpdater: {} 下载内容不是有效的 {:?} 数据 ({}), 保留原文件不覆盖",
            filename, source.kind, e
        );
        return Err(anyhow!("downloaded data failed validation"));
    }

    if let Err(e) = std::fs::rename(&tmp_path, &path) {
        error!("GeoUpdater: 重命名 {} 失败: {:?}", source.name, e);
        let _ = std::fs::remove_file(&tmp_path);
        return Err(anyhow!("Rename failed"));
    }

    let e = meta.sources.entry(source.name.clone()).or_default();
    e.validators = validators;
    e.downloaded_at = now_secs();

    info!("GeoUpdater: {} 已更新 ({} 字节)", filename, bytes.len());
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

/// 一次 fetch 的结果。
pub(crate) enum FetchOutcome {
    /// 拿到了新内容。
    Body(Vec<u8>, Validators),
    /// 上游回 304: 本地文件仍是最新的, 不用重下。
    NotModified,
}

/// 条件请求用的缓存验证器。
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, PartialEq)]
pub(crate) struct Validators {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etag: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_modified: Option<String>,
}

/// 单次 fetch: 带条件请求头 send → 304 直接返回 → 否则 check status → read body → 校验大小。
async fn do_fetch(
    client: &reqwest::Client,
    url: &str,
    cond: Option<&Validators>,
) -> Result<FetchOutcome> {
    let mut req = client.get(url);
    // 条件请求: 上游没变就回 304, 省掉几 MB 的重复传输。
    if let Some(v) = cond {
        if let Some(e) = &v.etag {
            req = req.header(reqwest::header::IF_NONE_MATCH, e);
        }
        if let Some(lm) = &v.last_modified {
            req = req.header(reqwest::header::IF_MODIFIED_SINCE, lm);
        }
    }
    let resp = req.send().await.map_err(|e| anyhow!("send: {}", e))?;

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(FetchOutcome::NotModified);
    }
    if !resp.status().is_success() {
        return Err(anyhow!("HTTP {}", resp.status()));
    }

    let hdr = |n: reqwest::header::HeaderName| {
        resp.headers().get(n).and_then(|v| v.to_str().ok()).map(String::from)
    };
    let validators = Validators {
        etag: hdr(reqwest::header::ETAG),
        last_modified: hdr(reqwest::header::LAST_MODIFIED),
    };

    let bytes = resp.bytes().await
        .map(|b| b.to_vec())
        .map_err(|e| anyhow!("read body: {}", e))?;
    if bytes.len() < MIN_VALID_BYTES {
        return Err(anyhow!(
            "body too small ({} bytes < {}), refusing to overwrite existing .dat",
            bytes.len(), MIN_VALID_BYTES
        ));
    }
    Ok(FetchOutcome::Body(bytes, validators))
}

/// 逐个镜像尝试, 每个镜像先按 `source.via` 走、失败且原是 Proxy 时再试一次 Direct。
///
/// 两层 fallback 的理由不同:
/// - **镜像层**: GitHub 在部分网络下时通时不通, 多给一两个镜像能显著提高拿到规则的概率。
/// - **通道层**: 配 `via=proxy` 时若自家代理出网抖动, 直连有时反而能过。
///
/// 全部失败才算整体失败 —— 调用方据此**保留旧文件**, 绝不覆盖。
async fn fetch_with_fallback(
    source: &GeoSource,
    proxy_url: Option<&str>,
    cond: Option<&Validators>,
) -> Result<FetchOutcome> {
    let total = source.url.len();
    let mut last_err = anyhow!("no url configured");

    for (i, url) in source.url.iter().enumerate() {
        let primary_client = build_client(source.via, proxy_url, &source.name)?;
        match do_fetch(&primary_client, url, cond).await {
            Ok(out) => {
                if total > 1 {
                    debug!("GeoUpdater: '{}' 镜像 {}/{} 成功: {}", source.name, i + 1, total, url);
                }
                return Ok(out);
            }
            Err(e) => {
                if matches!(source.via, GeoVia::Proxy) {
                    warn!(
                        "GeoUpdater: '{}' 镜像 {}/{} 经代理失败 ({}), 改试直连",
                        source.name, i + 1, total, e
                    );
                    let direct_client = build_client(GeoVia::Direct, None, &source.name)?;
                    match do_fetch(&direct_client, url, cond).await {
                        Ok(out) => {
                            info!("GeoUpdater: '{}' 镜像 {}/{} 直连回落成功", source.name, i + 1, total);
                            return Ok(out);
                        }
                        Err(e2) => {
                            warn!(
                                "GeoUpdater: '{}' 镜像 {}/{} 代理与直连均失败 (proxy: {}, direct: {})",
                                source.name, i + 1, total, e, e2
                            );
                            last_err = anyhow!("proxy: {}; direct: {}", e, e2);
                        }
                    }
                } else {
                    warn!("GeoUpdater: '{}' 镜像 {}/{} 失败: {}", source.name, i + 1, total, e);
                    last_err = e;
                }
            }
        }
    }

    error!(
        "GeoUpdater: '{}' 全部 {} 个镜像都失败, 保留现有 .dat 不覆盖。最后一次错误: {}",
        source.name, total, last_err
    );
    Err(anyhow!("all {} mirror(s) failed: {}", total, last_err))
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

    /// meta.json 必须能跨"进程重启"往返 —— 这正是 ETag 有意义的前提。
    /// 存不住就等于每次启动都无条件全量下载。
    #[test]
    fn meta_roundtrips_validators() {
        let d = tmpdir("meta");
        let dir = d.to_str().unwrap();

        let mut m = MetaFile::default();
        let e = m.sources.entry("ls".into()).or_default();
        e.validators = Validators {
            etag: Some("\"abc123\"".into()),
            last_modified: Some("Wed, 21 Oct 2026 07:28:00 GMT".into()),
        };
        e.downloaded_at = 1_700_000_000;
        write_meta(dir, &m);

        let back = read_meta(dir);
        let got = back.sources.get("ls").expect("应能读回该源");
        assert_eq!(got.validators.etag.as_deref(), Some("\"abc123\""));
        assert_eq!(
            got.validators.last_modified.as_deref(),
            Some("Wed, 21 Oct 2026 07:28:00 GMT")
        );
        assert_eq!(got.downloaded_at, 1_700_000_000);
    }

    /// meta.json 损坏/不存在必须退回空表, **不能**让 updater 崩掉或卡住 ——
    /// 元数据只是优化, 丢了最多多下一次。
    #[test]
    fn corrupt_meta_degrades_to_empty() {
        let d = tmpdir("badmeta");
        let dir = d.to_str().unwrap();
        assert!(read_meta(dir).sources.is_empty(), "不存在应为空表");

        std::fs::write(d.join("meta.json"), b"{ this is not json").unwrap();
        assert!(read_meta(dir).sources.is_empty(), "损坏应退回空表而非 panic");
    }

    /// 单个 URL 与数组都要能解析成镜像列表 (配置易用性)。
    #[test]
    fn geo_source_url_accepts_string_or_array() {
        let one: crate::config::GeoSource = serde_json::from_str(
            r#"{ "name": "ls", "kind": "geosite", "url": "https://a/x.dat" }"#,
        )
        .expect("单值应能解析");
        assert_eq!(one.url, vec!["https://a/x.dat"]);

        let many: crate::config::GeoSource = serde_json::from_str(
            r#"{ "name": "ls", "kind": "geosite", "url": ["https://a/x.dat", "https://b/x.dat"] }"#,
        )
        .expect("数组应能解析");
        assert_eq!(many.url.len(), 2, "多镜像应全部保留");
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
