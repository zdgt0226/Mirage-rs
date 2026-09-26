//! Web API handlers. 每个 endpoint 一个文件 (或几个相关 endpoint 一组).
//!
//! 所有 handler 函数都接收 `State<AppState>` 作为 axum 路由参数.

/// 串行化配置文件 RMW: rules / profiles 两个写端点共用 config.json + 同名 `.tmp`。无锁时
/// 并发 (或两端点交错) POST 会撕裂 `.tmp`, 或"读旧→各自改→后写覆盖前写"丢更新。整段读改写
/// 在此锁下串行。
pub(crate) static CONFIG_WRITE_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

pub mod overview;
pub mod connections;
pub mod stats;
pub mod domains;
pub mod devices;
pub mod clients;
pub mod profiles;
pub mod tls_capture;
pub mod bpf_tunnels;
pub mod history;
pub mod logs;
pub mod proxies;
pub mod rules;
pub mod users;

/// 原子写配置文件: 以 **0600** 创建 `<path>.tmp`, 写入并 flush 后原子 rename 覆盖目标文件。
/// 裸 `fs::write` 按 umask 建成 0644, rename 后会把原 0600 配置打回全员可读 (口令/私钥/token 泄露)。
/// 恒 0600 (不沿用原权限): 让早期安装留下的 0644 配置在下一次 API 写入时自愈。
pub(crate) async fn atomic_write_config(path: &str, content: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;

    let tmp = format!("{path}.tmp");
    #[cfg(unix)]
    let mode: u32 = 0o600;

    let mut opts = tokio::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        opts.mode(mode);
    }

    let write_res: std::io::Result<()> = async {
        let mut file = opts.open(&tmp).await?;
        file.write_all(content.as_bytes()).await?;
        file.flush().await?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(mode)).await;
        }
        tokio::fs::rename(&tmp, path).await?;
        Ok(())
    }
    .await;

    if write_res.is_err() {
        let _ = tokio::fs::remove_file(&tmp).await;
    }
    write_res
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn atomic_write_config_tightens_to_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("mirage_awc_{}.json", std::process::id()));
        let p = path.to_str().unwrap();
        let mode = |q: &std::path::Path| std::fs::metadata(q).unwrap().permissions().mode() & 0o777;

        // 新建: 0600
        atomic_write_config(p, "{\"a\":1}").await.unwrap();
        assert_eq!(mode(&path), 0o600, "新建配置应为 0600");

        // 早期安装遗留的 0644 → 写一次后收紧为 0600, 内容已更新
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        atomic_write_config(p, "{\"a\":2}").await.unwrap();
        assert_eq!(mode(&path), 0o600, "0644 配置经写入后应收紧为 0600");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "{\"a\":2}");
        assert!(!std::path::Path::new(&format!("{p}.tmp")).exists(), "tmp 不应残留");

        let _ = std::fs::remove_file(&path);
    }
}
