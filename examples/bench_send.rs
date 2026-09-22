//! send 路径 copy2 基线 bench: 隔离测「sealed body → BufWriter 内部」那一遍 memcpy 的真实占比。
//!   cargo run --release --example bench_send
//!
//! 对照三条:
//!   1. real  = 生产 CryptoWriter::send_data (copy1 plaintext→buffer + seal + copy2 buffer→BufWriter + flush→sink)
//!   2. A     = 手工复刻现状 framing (buffer + 64KB 累积器模拟 BufWriter, 含 copy2)
//!   3. B     = single-copy framing (framed 累积 + seal_in_place_separate_tag, 无 copy2)
//!
//! A vs B 的差 = copy2 的净成本。real 用来确认手工 A 与生产同量级。
//! 全部 seal 用真 ring ChaCha20-Poly1305, 写进复用 Vec sink (extend = 代表 syscall 那次 memcpy)。

use std::time::Instant;

use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, CHACHA20_POLY1305};
use mirage_rs::crypto::aead::CryptoWriter;

const MASTER: [u8; 32] = [0x42; 32];
const REC: usize = 16384; // 主导记录大小 (握手后无 padding, 分桶主要落 16KB)
const TAG: usize = 16;
const ACCUM_CAP: usize = 64 * 1024; // 与生产 WRITER_BUF_CAPACITY 一致

fn key() -> LessSafeKey {
    LessSafeKey::new(UnboundKey::new(&CHACHA20_POLY1305, &MASTER).unwrap())
}

fn nonce(n: u64) -> Nonce {
    let mut b = [0u8; 12];
    b[4..12].copy_from_slice(&n.to_be_bytes());
    Nonce::assume_unique_for_key(b)
}

fn mb_s(bytes: f64, secs: f64) -> f64 {
    bytes / secs / (1024.0 * 1024.0)
}

/// 现状: 每记录 seal 进复用 buffer, 再把 header+buffer 拷进 64KB 累积器 (=BufWriter), 满则 flush→sink。
fn strategy_a(plain: &[u8], sink: &mut Vec<u8>) {
    let k = key();
    let mut nonce_ctr = 0u64;
    let mut buffer: Vec<u8> = Vec::with_capacity(REC + 1 + TAG);
    let mut accum: Vec<u8> = Vec::with_capacity(ACCUM_CAP);
    sink.clear();
    let mut off = 0;
    while off < plain.len() {
        let end = (off + REC).min(plain.len());
        buffer.clear();
        buffer.extend_from_slice(&plain[off..end]); // copy1
        buffer.push(0x17);
        k.seal_in_place_append_tag(nonce(nonce_ctr), Aad::empty(), &mut buffer)
            .unwrap();
        nonce_ctr += 1;
        let bl = (buffer.len() as u16).to_be_bytes();
        let header = [0x17, 0x03, 0x03, bl[0], bl[1]];
        // BufWriter 语义: 装不下就先 flush 再装
        if accum.len() + header.len() + buffer.len() > ACCUM_CAP {
            sink.extend_from_slice(&accum); // flush (=syscall memcpy)
            accum.clear();
        }
        accum.extend_from_slice(&header); // copy2
        accum.extend_from_slice(&buffer); // copy2 (sealed body 再拷一遍)
        off = end;
    }
    sink.extend_from_slice(&accum);
}

/// single-copy: 每记录直接 seal 进 framed 的记录槽 (separate_tag), 全部记录攒完单次 flush→sink, 无 copy2。
fn strategy_b(plain: &[u8], sink: &mut Vec<u8>) {
    let k = key();
    let mut nonce_ctr = 0u64;
    let mut framed: Vec<u8> = Vec::with_capacity(ACCUM_CAP + REC);
    sink.clear();
    let mut off = 0;
    while off < plain.len() {
        let end = (off + REC).min(plain.len());
        let body_len = (end - off) + 1 + TAG; // plaintext + content_type + tag
        let hdr_at = framed.len();
        framed.extend_from_slice(&[0x17, 0x03, 0x03, 0, 0]); // header 占位
        let rec_at = framed.len();
        framed.extend_from_slice(&plain[off..end]); // copy1 (进 framed 的记录槽)
        framed.push(0x17);
        // 就地 seal, tag 单独返回后 append 进 framed
        let tag = k
            .seal_in_place_separate_tag(nonce(nonce_ctr), Aad::empty(), &mut framed[rec_at..])
            .unwrap();
        framed.extend_from_slice(tag.as_ref());
        nonce_ctr += 1;
        // 回填 header 长度
        let bl = (body_len as u16).to_be_bytes();
        framed[hdr_at + 3] = bl[0];
        framed[hdr_at + 4] = bl[1];
        off = end;
        // framed 逼近容量则单次 flush (与 A 同样的 flush 次数量级, 但每记录省了 copy2)
        if framed.len() >= ACCUM_CAP {
            sink.extend_from_slice(&framed);
            framed.clear();
        }
    }
    sink.extend_from_slice(&framed);
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    mirage_rs::crypto::cipher::set_tls_padding(false);

    let blob = vec![0xA5u8; 64 * 1024 * 1024];
    let iters = 8usize;
    let total = (blob.len() * iters) as f64;
    let mut sink: Vec<u8> = Vec::with_capacity(blob.len() + blob.len() / 16);

    // warmup
    strategy_a(&blob, &mut sink);
    strategy_b(&blob, &mut sink);

    // ---- real: 生产 send_data (含内部 BufWriter) ----
    let t = Instant::now();
    for _ in 0..iters {
        sink.clear();
        let mut w = CryptoWriter::new(&mut sink, &MASTER, true);
        w.send_data(&blob).await.unwrap();
    }
    let real = mb_s(total, t.elapsed().as_secs_f64());

    // ---- A: 手工复刻现状 (含 copy2) ----
    let t = Instant::now();
    for _ in 0..iters {
        strategy_a(&blob, &mut sink);
    }
    let a = mb_s(total, t.elapsed().as_secs_f64());

    // ---- B: single-copy (无 copy2) ----
    let t = Instant::now();
    for _ in 0..iters {
        strategy_b(&blob, &mut sink);
    }
    let b = mb_s(total, t.elapsed().as_secs_f64());

    // ---- 纯 memcpy 上限参考 ----
    let mut dst = vec![0u8; blob.len()];
    let t = Instant::now();
    for _ in 0..iters {
        dst.copy_from_slice(&blob);
    }
    let memcpy = mb_s(total, t.elapsed().as_secs_f64());

    println!("send-path bench  (64MB×{iters}, ChaCha20-Poly1305, 16KB records)");
    println!("  real send_data : {real:8.1} MB/s  (生产路径, 含内部 BufWriter)");
    println!("  A  copy2 版    : {a:8.1} MB/s  (手工复刻现状)");
    println!("  B  single-copy : {b:8.1} MB/s  (省 copy2)");
    println!("  memcpy 上限     : {memcpy:8.1} MB/s  (纯内存带宽参考)");
    let gain = (b - a) / a * 100.0;
    println!("  → B vs A 提升   : {gain:+.1}%   (= copy2 的净成本占比)");
}
