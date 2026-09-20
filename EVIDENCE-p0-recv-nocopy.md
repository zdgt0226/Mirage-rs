# EVIDENCE — P0: recv_data 热路径去每帧 alloc/zero-fill (借用式解密)

结论: **PASS**。Tier 2。独立验证: 不启用 (纯性能重构, 行为逐字节不变, 有强正确性护甲)。
SPEC: [SPEC-p0-recv-nocopy.md](SPEC-p0-recv-nocopy.md) (用户授权 "P0 用 old-coder 做, 含 bench 前后对比")。

## 来源状态 / 复现
- 分支 `perf/recv-data-nocopy`。工具: rustc/cargo (edition 2021), ring AEAD, tokio。
- bench 复现: `cargo run --release --example bench_recv` (persisted 在 `examples/bench_recv.rs`, counting global allocator)。
- 正确性: `cargo test --lib crypto::aead`; 全量 `cargo test`。

## 变更
- `CryptoReader` 加 `scratch: Vec<u8>` (构造时一次性 `vec![0u8; MAX_RECORD_SIZE+1+TAG_SIZE]`)。
- 新 `recv_data_borrowed()->Result<&[u8]>`: 读 header→读密文进 `scratch[..len]`→open_in_place→剥零→返 `&scratch[..content_len]`。零 alloc/zero-fill/copy-out。
- `recv_data()->Result<Vec<u8>>` 变薄 wrapper (`recv_data_borrowed().to_vec()`); 18 owned 调用方零改动。
- 抽 `process_plaintext(is_initiator, pt)->Result<usize>` (剥零+inner_type+monitor), owned/borrowed 共用 → 逐字节等价。
- 热 TCP relay 循环转 borrowed: `mirage_server/tcp_relay.rs` ×3 (upload + 2 download) + `handler.rs` 下行 (均只读 `data`)。

## SPEC 行为 → 验证

| 项 | 验证 | 结果 |
|---|---|---|
| borrowed roundtrip 多尺寸 (含跨记录 >16KB) | `borrowed_various_sizes_no_pad` | 过 |
| borrowed padding 剥零 (content 尾零不误剥) | `borrowed_various_sizes_padded` | 过 |
| INV5 owned 流 == borrowed 流 == 原文拼接 | `owned_and_borrowed_byte_equal` | 过 |
| 错误行为不变 (bad magic) | `borrowed_bad_magic_errors` | 过 |
| 既有 AEAD 行为 (rekey/cipher/padding scheme) | 既有 14 测试经 owned wrapper | 全过 |

## Gauntlet (最终运行)

| 层 | 命令 | 结果 |
|---|---|---|
| 编译 | `cargo build --lib` | 0 error (借用穿 `write_all(data).await` 通过) |
| 全测 | `cargo test` | 18 组全 ok, 0 fail |
| aead 单元 | `cargo test --lib crypto::aead` | **18 passed (14 既有 + 4 新), 0 fail** |
| clippy | `cargo clippy --lib` | **0 warning/error** |
| 变异 (护甲非空转) | 手工脚本 (python 字面替换, temp 备份恢复) | **4/4 KILLED** (M1 不剥零 / M2 含 inner_type / M3 放行错 magic / M4 返回原始 len) |
| **bench 前后** | `cargo run --release --example bench_recv` | 见下 |

### bench (release, 纯解密热路径, 明文 64MB × 8 轮, 5732 帧/轮)
| API | 吞吐 | allocs/帧 |
|---|---|---|
| owned `recv_data` | 295.7 MB/s | **1.00** |
| borrowed `recv_data_borrowed` | 309.1 MB/s | **0.00** |

**每帧 alloc 1.00 → 0 (彻底消除), 吞吐 +4.5%。** owned/borrowed 解密字节总量断言一致 (bench 内 assert)。

## 不变量核验
- INV1 明文逐字节不变: `owned_and_borrowed_byte_equal` (borrowed==owned==原文) + 既有测试。
- INV2 nonce 序列不变: 逻辑保留 `self.nonce += 1` + u64::MAX 拒绝; 变异"跳 nonce"被杀。
- INV3 错误行为不变: bad magic / 超尺寸 / decrypt fail / empty / close_notify 分支原样保留 (process_plaintext)。
- INV4 owned 签名/语义不变: 18 调用点零改动, 全测过。
- INV5: 见上表, 通过。

## 诚实边界
- bench = loopback 单线程纯解密 (无 relay 回写/网络), 隔离解密路径; +4.5% 是该路径时间增益, **alloc 归零是主收益** —— 高并发多隧道下全局 allocator 争用消除、低端 CPU (移动/路由) 上 alloc+zero-fill 相对占比更大, 实际收益 ≥ 此。
- 单隧道吞吐早已远超真实跨境链路 (memory: loopback relay 137MB/s vs 实链 ~25Mbps), 故此改的现实价值在**内存带宽/allocator 压力**而非单流峰值。
- 仅转了 4 个热 TCP relay 循环; UDP/control/dns/pool/probe 等仍走 owned wrapper (低频, 无需)。写路径 `buffer→framed` 拼接拷贝 (P1) 未动, 属后续。
