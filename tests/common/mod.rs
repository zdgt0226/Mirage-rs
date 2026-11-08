//! 共享测试辅助模块 (E2E 测试端口分配、就绪等待、临时文件与清理).
#![allow(dead_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// 离线保留伪装域名 (RFC 2606 / RFC 6761 保留 TLD, 不会解析公网 IP, 走合成模板回落).
pub const TEST_CAMOUFLAGE_HOST: &str = "camouflage.test";

/// 动态分配 `n` 个互不相同的空闲端口。
/// 同时绑定 `n` 个 `127.0.0.1:0` 监听器并在全部获得后统一释放，
/// 避免"逐个获取释放"在高并发测试时拿到相同端口。
pub fn free_ports(n: usize) -> Vec<u16> {
    let listeners: Vec<TcpListener> = (0..n)
        .map(|_| TcpListener::bind("127.0.0.1:0").expect("bind 127.0.0.1:0"))
        .collect();
    let ports = listeners
        .iter()
        .map(|l| l.local_addr().expect("local_addr").port())
        .collect();
    drop(listeners);
    ports
}

/// 同步轮询直到 TCP 地址可连, 每次间隔 50ms, 最多等待 `timeout`。
pub fn wait_tcp_ready(addr: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if std::net::TcpStream::connect(addr).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    false
}

/// 异步轮询直到 TCP 地址可连, 每次间隔 50ms, 最多等待 `timeout`。
pub async fn wait_tcp_ready_async(addr: &str, timeout: Duration) -> bool {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// 子进程守卫: 无论测试正常退出还是 panic，drop 时强杀子进程并回收。
pub struct Kid(pub Child);

impl Drop for Kid {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// 测试独立的临时目录守卫: drop 时递归清理该目录, 绝不残留到工作区。
pub struct TempTestDir {
    path: PathBuf,
}

impl TempTestDir {
    pub fn new(prefix: &str) -> Self {
        let pid = std::process::id();
        let rand: u64 = fastrand::u64(..);
        let path = std::env::temp_dir().join(format!("mirage_test_{}_{}_{:016x}", prefix, pid, rand));
        std::fs::create_dir_all(&path).expect("create test temp dir");
        Self { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn write_file(&self, filename: &str, content: &str) -> PathBuf {
        let p = self.path.join(filename);
        std::fs::write(&p, content).expect("write temp test file");
        p
    }
}

impl Drop for TempTestDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 获取 mirage 编译产物路径。
pub fn mirage_bin() -> PathBuf {
    let mut p = std::env::current_exe().unwrap();
    p.pop();
    p.pop();
    p.push("mirage");
    p
}

/// 启动 mirage 子进程并用 Kid 守卫包裹。
pub fn spawn_mirage(sub: &str, cfg: &Path) -> Kid {
    Kid(Command::new(mirage_bin())
        .args([sub, "-c", cfg.to_str().unwrap()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap())
}
