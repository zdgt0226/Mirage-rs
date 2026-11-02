//! selector 手动选择持久化模块
//!
//! 在 API 切换 selector 节点时将选择原子持久化到状态文件 (权限 0600)；
//! 启动和出站重建时恢复选择，若组或成员已失效则清理并回退。

use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use std::sync::LazyLock;

static SELECTOR_PERSIST_LOCK: LazyLock<std::sync::Mutex<()>> =
    LazyLock::new(|| std::sync::Mutex::new(()));

/// 从文件加载所有 selector 组的手动选择记录。
/// 文件不存在或无法读取返回空字典；文件损坏仅 warn 并返回空字典。
pub fn load_selector_choices(path: &str) -> HashMap<String, String> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return HashMap::new(),
    };
    match serde_json::from_str::<HashMap<String, String>>(&content) {
        Ok(map) => map,
        Err(e) => {
            tracing::warn!(
                "[SELECTOR] 解析持久化选择文件 `{path}` 失败 ({e})，忽略损坏文件并回落默认"
            );
            HashMap::new()
        }
    }
}

/// 保存单个 selector 组的选择记录到文件 (原子写入，权限 0600)。
/// 失败仅 warn，不影响代理转发。
pub fn save_selector_choice(path: &str, group: &str, target: &str) {
    let _guard = SELECTOR_PERSIST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut map = load_selector_choices(path);
    map.insert(group.to_string(), target.to_string());
    write_selector_choices_locked(path, &map);
}

/// 保存某组"此刻"的选择: 拿到持久化锁后才调用 `current` 取值再写。
/// API 切换把落盘丢到阻塞线程池, 连切 A→B 时两个任务的先后不保证; 由于每个任务都在锁内读最新值,
/// 最后完成的那次写入的一定是内存里的最终选择。`current` 返回 None 时不写。
pub fn save_selector_current(path: &str, group: &str, current: impl FnOnce() -> Option<String>) {
    let _guard = SELECTOR_PERSIST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(target) = current() else { return };
    let mut map = load_selector_choices(path);
    if map.get(group) == Some(&target) {
        return;
    }
    map.insert(group.to_string(), target);
    write_selector_choices_locked(path, &map);
}

/// 从持久化文件中移除指定的组选择记录 (如组已被删除或成员已失效)。
pub fn remove_selector_choices(path: &str, groups: &[String]) {
    let _guard = SELECTOR_PERSIST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let mut map = load_selector_choices(path);
    let mut changed = false;
    for g in groups {
        if map.remove(g).is_some() {
            changed = true;
        }
    }
    if changed {
        write_selector_choices_locked(path, &map);
    }
}

fn write_selector_choices_locked(path: &str, map: &HashMap<String, String>) {
    let json = match serde_json::to_string_pretty(map) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("[SELECTOR] 序列化持久化选择失败: {e}");
            return;
        }
    };

    // 软链接: 写到它指向的目标 (目标尚不存在时 canonicalize 会失败, 用 read_link 解析), 不把链接本身替换掉
    let resolved = std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| match std::fs::read_link(path) {
            Ok(target) => Path::new(path)
                .parent()
                .map(|d| d.join(&target))
                .unwrap_or(target)
                .to_string_lossy()
                .into_owned(),
            Err(_) => path.to_string(),
        });
    if let Some(parent) = Path::new(&resolved).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // 临时文件名带 pid + 随机数: 跨进程并发写不会互相截断同一个 .tmp
    let tmp = format!("{resolved}.tmp.{}.{}", std::process::id(), fastrand::u32(..));

    #[cfg(unix)]
    let mode: u32 = 0o600;

    let res: std::io::Result<()> = (|| {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            use std::os::unix::fs::PermissionsExt;
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(mode)
                .open(&tmp)?;
            f.write_all(json.as_bytes())?;
            f.flush()?;
            let _ = f.set_permissions(std::fs::Permissions::from_mode(mode));
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &resolved)?;
        }
        #[cfg(not(unix))]
        {
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp)?;
            f.write_all(json.as_bytes())?;
            f.flush()?;
            f.sync_all()?;
            drop(f);
            std::fs::rename(&tmp, &resolved)?;
        }
        Ok(())
    })();

    if let Err(e) = res {
        tracing::warn!("[SELECTOR] 写入持久化选择文件 `{resolved}` 失败 (不影响代理转发): {e}");
        let _ = std::fs::remove_file(&tmp);
    }
}
