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

    bench_framing();
}

/// P1: 隔离 framing 拷贝开销 (无 AES) —— 旧法 buffer→framed 拼接 vs 新法 header/body 两次写。
/// **只量被改的那一步**; 真实路径里 AES seal 远大于此, 故这是 P1 改动的上界, 非全路径提速。
fn bench_framing() {
    use std::io::Write;
    let body = vec![0xC3u8; 16384 + 16]; // 满 16KB record + tag
    let n = 2_000_000usize;
    let cap = 68 * 1024;

    // 旧法: 每帧 clear + 拼 header + 拼 body 进 framed, 再写 BufWriter
    let mut framed: Vec<u8> = Vec::with_capacity(5 + body.len());
    let t0 = Instant::now();
    let mut sink_o = std::io::BufWriter::with_capacity(cap, std::io::sink());
    for _ in 0..n {
        let bl = (body.len() as u16).to_be_bytes();
        framed.clear();
        framed.extend_from_slice(&[0x17, 0x03, 0x03, bl[0], bl[1]]);
        framed.extend_from_slice(&body);
        sink_o.write_all(&framed).unwrap();
    }
    sink_o.flush().unwrap();
    let dt_old = t0.elapsed().as_secs_f64();

    // 新法: header + body 分两次写 BufWriter (省掉拼 framed 的 memcpy)
    let t1 = Instant::now();
    let mut sink_n = std::io::BufWriter::with_capacity(cap, std::io::sink());
    for _ in 0..n {
        let bl = (body.len() as u16).to_be_bytes();
        let header = [0x17, 0x03, 0x03, bl[0], bl[1]];
        sink_n.write_all(&header).unwrap();
        sink_n.write_all(&body).unwrap();
    }
    sink_n.flush().unwrap();
    let dt_new = t1.elapsed().as_secs_f64();

    let gb = (n * body.len()) as f64;
    println!("\n== P1 framing 隔离 bench (无 AES, {} 帧 × 16KB) ==", n);
    println!("旧 buffer→framed 拼接写 : {:>7.1} MB/s | {:.3}s", gb / dt_old / 1e6, dt_old);
    println!("新 header/body 分写     : {:>7.1} MB/s | {:.3}s", gb / dt_new / 1e6, dt_new);
    println!("framing 环节提速 {:.1}% (真实路径里被 AES seal 稀释, 全路径增益远小于此)",
        (dt_old / dt_new - 1.0) * 100.0);
}
