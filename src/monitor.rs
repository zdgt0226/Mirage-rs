use std::io::Write;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::collections::VecDeque;

pub static GLOBAL_UP: AtomicU64 = AtomicU64::new(0);
pub static GLOBAL_DOWN: AtomicU64 = AtomicU64::new(0);
pub static DROPPED_LOGS: AtomicU64 = AtomicU64::new(0);

pub fn add_up(bytes: u64) {
    GLOBAL_UP.fetch_add(bytes, Ordering::Relaxed);
}

pub fn add_down(bytes: u64) {
    GLOBAL_DOWN.fetch_add(bytes, Ordering::Relaxed);
}

#[derive(Clone)]
pub struct MemoryWriter {
    tx: std::sync::mpsc::SyncSender<String>,
    buffer: Arc<Mutex<VecDeque<String>>>,
}

impl MemoryWriter {
    pub fn new() -> Self {
        let (tx, rx) = std::sync::mpsc::sync_channel(1000);
        let buffer = Arc::new(Mutex::new(VecDeque::with_capacity(500)));
        let bg_buf = buffer.clone();
        
        std::thread::spawn(move || {
            while let Ok(s) = rx.recv() {
                let mut q = bg_buf.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= 500 {
                    q.pop_front();
                }
                q.push_back(s);
            }
        });
        
        Self {
            tx,
            buffer,
        }
    }

    pub fn get_logs(&self) -> Vec<String> {
        let q = self.buffer.lock().unwrap_or_else(|e| e.into_inner());
        q.iter().cloned().collect()
    }
}

impl Write for MemoryWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let s = String::from_utf8(buf.to_vec())
            .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());
        if s.trim().is_empty() {
            return Ok(buf.len());
        }
        
        if self.tx.try_send(s).is_err() {
            DROPPED_LOGS.fetch_add(1, Ordering::Relaxed);
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

lazy_static::lazy_static! {
    pub static ref GLOBAL_LOGGER: MemoryWriter = MemoryWriter::new();
}

/// 单个日志文件超过此大小即滚动 (rotate)。
const LOG_ROTATE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
/// 保留的历史归档数 (server.log.1.gz ... server.log.N.gz), 超出的最老归档删除。
/// 归档经 gzip 压缩 (日志约 10:1), 10 份 ≈ 磁盘 ~10MB。
const LOG_KEEP_ARCHIVES: usize = 10;

/// 在 `path` 后接 `.{i}.gz` 生成归档名 (不改变原扩展名, 便于 `ls server.log*`)。
fn archive_name(path: &std::path::Path, i: usize) -> std::path::PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(format!(".{}.gz", i));
    std::path::PathBuf::from(s)
}

/// gzip 压缩 src → dst (纯 Rust flate2/miniz_oxide, 无外部 gzip 依赖)。
fn gzip_file(src: &std::path::Path, dst: &std::path::Path) -> std::io::Result<()> {
    let input = std::fs::File::open(src)?;
    let mut reader = std::io::BufReader::new(input);
    let output = std::fs::File::create(dst)?;
    let mut encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
    std::io::copy(&mut reader, &mut encoder)?;
    encoder.finish()?;
    Ok(())
}

struct RotatingFile {
    path: std::path::PathBuf,
    file: std::fs::File,
    written: u64,
    rotate_at: u64,
}

impl RotatingFile {
    /// 滚动: 归档号后移 (.i.gz→.(i+1).gz, 删最老), 当前日志改名为临时文件后重开一个新的,
    /// 再在后台线程 gzip 临时文件为 .1.gz。压缩在后台跑, 不阻塞日志写入热路径。
    /// 全程 best-effort: 任一步失败只 eprintln, 绝不让日志写入本身失败。
    fn rotate(&mut self) {
        let _ = self.file.flush();
        let path = self.path.clone();

        // 1. 删最老归档
        let _ = std::fs::remove_file(archive_name(&path, LOG_KEEP_ARCHIVES));
        // 2. .i.gz → .(i+1).gz (从高到低, 避免覆盖)
        for i in (1..LOG_KEEP_ARCHIVES).rev() {
            let from = archive_name(&path, i);
            if from.exists() {
                let _ = std::fs::rename(&from, archive_name(&path, i + 1));
            }
        }
        // 3. 当前日志 → 唯一临时名 (纳秒后缀防并发/未压缩完的碰撞), 再重开新日志
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let mut pending = path.as_os_str().to_owned();
        pending.push(format!(".{}.pending", nanos));
        let pending = std::path::PathBuf::from(pending);

        if std::fs::rename(&path, &pending).is_err() {
            // 改名失败 (罕见): 放弃本次滚动, 继续用当前文件, 下次再试。
            self.written = 0; // 复位避免每条日志都重试滚动刷屏
            return;
        }
        match std::fs::OpenOptions::new().create(true).append(true).open(&path) {
            Ok(f) => {
                self.file = f;
                self.written = 0;
            }
            Err(e) => {
                // 重开失败: 尽量把 pending 改回原名保住写入, 否则后续写入会丢。
                eprintln!("[log-rotate] reopen {} failed: {}", path.display(), e);
                let _ = std::fs::rename(&pending, &path);
                return;
            }
        }
        // 4. 后台压缩 pending → .1.gz, 完成后删 pending
        let target = archive_name(&path, 1);
        std::thread::spawn(move || {
            if let Err(e) = gzip_file(&pending, &target) {
                eprintln!("[log-rotate] gzip {} failed: {}", pending.display(), e);
            }
            let _ = std::fs::remove_file(&pending);
        });
    }
}

/// 磁盘日志写入器 (带按大小自动滚动 + gzip 压缩归档)。
/// 用 Arc<Mutex<RotatingFile>> 支持 Clone (每次 tracing 事件触发都要 make_writer,
/// 要能廉价 clone). Mutex 保证多线程 append 不错乱且滚动串行化。
/// config.log_file 设了才会实例化。
#[derive(Clone)]
pub struct FileLogger(std::sync::Arc<std::sync::Mutex<RotatingFile>>);

impl FileLogger {
    /// 打开 (append 模式) 并按当前文件大小初始化已写字节数 —— 重启后接着已有大文件
    /// 也能及时滚动, 不会等重新累积 10MB。
    pub fn new(path: impl Into<std::path::PathBuf>) -> std::io::Result<Self> {
        Self::with_rotate_bytes(path, LOG_ROTATE_BYTES)
    }

    fn with_rotate_bytes(path: impl Into<std::path::PathBuf>, rotate_at: u64) -> std::io::Result<Self> {
        let path = path.into();
        let file = std::fs::OpenOptions::new().create(true).append(true).open(&path)?;
        let written = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self(std::sync::Arc::new(std::sync::Mutex::new(RotatingFile {
            path,
            file,
            written,
            rotate_at,
        }))))
    }
}

impl std::io::Write for FileLogger {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut g = self.0.lock().unwrap_or_else(|e| e.into_inner());
        g.file.write_all(buf)?;
        g.written += buf.len() as u64;
        if g.written >= g.rotate_at {
            g.rotate();
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.lock().unwrap_or_else(|e| e.into_inner()).file.flush()
    }
}

use tokio::io::{AsyncRead, ReadBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct MonitoredReader<R> {
    inner: R,
    is_up: bool,
}

impl<R> MonitoredReader<R> {
    pub fn new(inner: R, is_up: bool) -> Self {
        Self { inner, is_up }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for MonitoredReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        let after = buf.filled().len();
        
        let read_bytes = (after - before) as u64;
        if read_bytes > 0 {
            if self.is_up {
                add_up(read_bytes);
            } else {
                add_down(read_bytes);
            }
        }
        res
    }
}

#[cfg(test)]
mod log_rotate_tests {
    use super::*;
    use std::io::{Read, Write};

    fn tmp_path(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("mirage_logtest_{}_{}", nanos, name))
    }

    /// 轮询等待 gz 归档写全并成功解压 (背景压缩线程完成), 返回其明文。超时 panic。
    fn wait_read_gz(path: &std::path::Path) -> String {
        for _ in 0..60 {
            if path.exists() {
                if let Ok(f) = std::fs::File::open(path) {
                    let mut dec = flate2::read::GzDecoder::new(f);
                    let mut s = String::new();
                    if dec.read_to_string(&mut s).is_ok() && !s.is_empty() {
                        return s;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        panic!("timed out waiting for gz archive {}", path.display());
    }

    #[test]
    fn archive_name_format() {
        let p = std::path::Path::new("/var/log/mirage/server.log");
        assert_eq!(archive_name(p, 1), std::path::PathBuf::from("/var/log/mirage/server.log.1.gz"));
        assert_eq!(archive_name(p, 10), std::path::PathBuf::from("/var/log/mirage/server.log.10.gz"));
    }

    #[test]
    fn gzip_roundtrip() {
        let src = tmp_path("src.txt");
        let dst = tmp_path("src.txt.gz");
        std::fs::write(&src, b"hello mirage log rotation\n").unwrap();
        gzip_file(&src, &dst).unwrap();
        assert_eq!(wait_read_gz(&dst), "hello mirage log rotation\n");
        let _ = std::fs::remove_file(&src);
        let _ = std::fs::remove_file(&dst);
    }

    #[test]
    fn rotation_compresses_and_resets() {
        let log = tmp_path("server.log");
        let mut fl = FileLogger::with_rotate_bytes(&log, 1024).unwrap();

        // 单次大写 (>1024) 触发滚动: 写在旧文件后 rotate → 归档含它、当前文件重置为空
        let first = "FIRST-BATCH-".repeat(200); // ~2400B > 1024
        fl.write_all(first.as_bytes()).unwrap();
        // 滚动后写第二批到新文件
        fl.write_all(b"SECOND-ONLY\n").unwrap();
        fl.flush().unwrap();

        // 归档 .1.gz 应含第一批
        let archived = wait_read_gz(&archive_name(&log, 1));
        assert!(archived.contains("FIRST-BATCH"), "归档应含滚动前日志");

        // 当前 log 应是新文件: 含第二批, 不含已归档内容
        let current = std::fs::read_to_string(&log).unwrap();
        assert!(current.contains("SECOND-ONLY"), "新日志应含滚动后写入");
        assert!(!current.contains("FIRST-BATCH"), "新日志不应含已归档内容");

        let _ = std::fs::remove_file(&log);
        let _ = std::fs::remove_file(archive_name(&log, 1));
    }

    #[test]
    fn second_rotation_shifts_archives() {
        let log = tmp_path("app.log");
        let big = "X".repeat(2048);
        let mut fl = FileLogger::with_rotate_bytes(&log, 1024).unwrap();

        // 第一次滚动 → .1.gz (含 AAA)
        fl.write_all(b"AAA-marker ").unwrap();
        fl.write_all(big.as_bytes()).unwrap();
        fl.flush().unwrap();
        let first_archive = wait_read_gz(&archive_name(&log, 1)); // 等第一次压缩完成后再触发第二次
        assert!(first_archive.contains("AAA-marker"));

        // 第二次滚动 → 原 .1.gz 移到 .2.gz, 新 .1.gz (含 BBB)
        fl.write_all(b"BBB-marker ").unwrap();
        fl.write_all(big.as_bytes()).unwrap();
        fl.flush().unwrap();

        // .2.gz = 第一批 (AAA), .1.gz = 第二批 (BBB)
        assert!(wait_read_gz(&archive_name(&log, 2)).contains("AAA-marker"), ".2.gz 应是移位后的第一批");
        assert!(wait_read_gz(&archive_name(&log, 1)).contains("BBB-marker"), ".1.gz 应是最新第二批");

        for p in [log.clone(), archive_name(&log, 1), archive_name(&log, 2)] {
            let _ = std::fs::remove_file(p);
        }
    }
}
