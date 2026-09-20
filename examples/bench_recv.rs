//! P0 bench: recv_data(owned) vs recv_data_borrowed 的解密热路径吞吐 + 每帧分配对比。
//!   cargo run --release --example bench_recv
//! counting global allocator 只在解密循环前后取样, 隔离每帧 alloc。

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use mirage_rs::crypto::aead::{CryptoReader, CryptoWriter};

static ALLOCS: AtomicUsize = AtomicUsize::new(0);

struct Counting;
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        System.dealloc(p, l)
    }
}
#[global_allocator]
static A: Counting = Counting;

const MASTER: [u8; 32] = [0x42; 32];

#[tokio::main(flavor = "current_thread")]
async fn main() {
    mirage_rs::crypto::cipher::set_tls_padding(false);

    // 编码 ~64MB 明文 → 一串加密帧 (writer 按分桶切记录, 主要是 16KB)。
    let blob = vec![0xA5u8; 64 * 1024 * 1024];
    let mut sink: Vec<u8> = Vec::with_capacity(blob.len() + blob.len() / 16);
    {
        let mut w = CryptoWriter::new(&mut sink, &MASTER, true);
        w.send_data(&blob).await.unwrap();
    }
    let total_plain = blob.len();
    let iters = 8usize;
    let total_bytes = (total_plain * iters) as f64;

    // 计一遍帧数 (borrowed, 顺带 warmup)
    let mut frames = 0u64;
    {
        let mut r = CryptoReader::new(&sink[..], &MASTER, false);
        while r.recv_data_borrowed().await.is_ok() {
            frames += 1;
        }
    }

    // ---- owned: recv_data (每帧 to_vec) ----
    let a0 = ALLOCS.load(Ordering::Relaxed);
    let t0 = Instant::now();
    let mut sum_owned = 0usize;
    for _ in 0..iters {
        let mut r = CryptoReader::new(&sink[..], &MASTER, false);
        while let Ok(d) = r.recv_data().await {
            sum_owned += d.len();
        }
    }
    let dt_owned = t0.elapsed().as_secs_f64();
    let alloc_owned = ALLOCS.load(Ordering::Relaxed) - a0;

    // ---- borrowed: recv_data_borrowed (复用 scratch) ----
    let a1 = ALLOCS.load(Ordering::Relaxed);
    let t1 = Instant::now();
    let mut sum_bor = 0usize;
    for _ in 0..iters {
        let mut r = CryptoReader::new(&sink[..], &MASTER, false);
        while let Ok(d) = r.recv_data_borrowed().await {
            sum_bor += d.len();
        }
    }
    let dt_bor = t1.elapsed().as_secs_f64();
    let alloc_bor = ALLOCS.load(Ordering::Relaxed) - a1;

    assert_eq!(sum_owned, sum_bor, "owned/borrowed 解密字节总量必须一致");
    let frames_total = frames * iters as u64;

    let mbps = |bytes: f64, dt: f64| bytes / dt / 1e6;
    println!("== recv 解密热路径 bench (明文 {} MB × {} 轮, {} 帧/轮) ==",
        total_plain / 1024 / 1024, iters, frames);
    println!("owned    recv_data          : {:>7.1} MB/s | {:.3}s | allocs={} ({:.2}/帧)",
        mbps(total_bytes, dt_owned), dt_owned, alloc_owned, alloc_owned as f64 / frames_total as f64);
    println!("borrowed recv_data_borrowed : {:>7.1} MB/s | {:.3}s | allocs={} ({:.2}/帧)",
        mbps(total_bytes, dt_bor), dt_bor, alloc_bor, alloc_bor as f64 / frames_total as f64);
    println!("提速 {:.1}% | 每帧 alloc {} → {}",
        (dt_owned / dt_bor - 1.0) * 100.0,
        alloc_owned as f64 / frames_total as f64,
        alloc_bor as f64 / frames_total as f64);
}
