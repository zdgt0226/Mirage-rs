# SPEC — P0: recv_data 热路径去每帧 alloc/zero-fill (借用式解密)

状态: 用户已授权 ("P0 用 old-coder 做, 含 bench 前后对比")。
Tier: 2 (改核心 AEAD 读热路径, 全 relay 流量经过; 行为必须逐字节不变 → 强正确性护甲)。
分支隔离: `perf/recv-data-nocopy`。

## 背景 (实测热点)
`src/crypto/aead.rs::recv_data` 每帧 `vec![0u8; len]` (分配 + **清零** len≤16401B) 再 read_exact 覆盖 (清零纯浪费) → open_in_place → 返 owned Vec。137MB/s 下 ~8400 帧/s/隧道: 每帧 1 alloc + 1 zero-fill + 1 free。crypto 已是瓶颈, 削其周边内存搅动是"老一辈压榨"的正着。

## 变更 (最小爆炸半径)
- `CryptoReader` 加内部 `scratch: Vec<u8>`, **构造时一次性** `vec![0u8; MAX_RECORD_SIZE + 1 + TAG_SIZE]` (一次 alloc+zero, 之后永不再分配/清零)。
- 新 `recv_data_borrowed(&mut self) -> Result<&[u8]>`: 读 header→校验→读密文进 `self.scratch[..len]` (无每帧 alloc/zero)→nonce→open_in_place(scratch[..len])→剥零→返 `&self.scratch[..plaintext_len]`。**零 alloc / 零 zero-fill / 零 copy-out**。
- `recv_data(&mut self) -> Result<Vec<u8>>` 改薄 wrapper: `Ok(self.recv_data_borrowed().await?.to_vec())`。**owned 调用方 (18 处) 全不改** (跨 channel 的 UDP/control/dns/probe/pool/test 仍拿 owned)。
- 仅把**热 TCP relay 下/上行循环**转 borrowed (只读用 `data`: write_all + len):
  - `src/proxy/mirage_server/tcp_relay.rs` (3 处循环)
  - `src/proxy/handler.rs` (客户端 relay 循环)
  这些 `reader` 与写出的 `up_write/target` 分离, slice 借用跨 `write_all(data).await` 期间不碰 reader → 安全。

## 不变量 (must not change — EVIDENCE 逐条验)
- INV1 明文逐字节不变 (含尾零剥离语义)。
- INV2 nonce 序列不变 (每帧 +1, u64::MAX 耗尽拒绝)。
- INV3 错误行为不变: bad magic / 超 MAX / decrypt fail / empty plaintext 均同样报错。
- INV4 owned `recv_data()` 外部签名/语义不变 (18 调用点零改动)。
- INV5 借用式与 owned 式对同一密文流产出**逐帧字节相同**。

## RED (先失败)
- 新测 `recv_data_borrowed` roundtrip: CryptoWriter 编 N 帧 → CryptoReader 借用式逐帧读, 断言 == 原文。方法未实现 → 编译/断言失败 (RED)。
- 新测 INV5: 同一密文流, owned 与 borrowed 逐帧字节相等。

## GREEN
实现上述; 全 `cargo test` 绿。

## GAUNTLET
| 层 | 命令 | 门槛 |
|---|---|---|
| 语法/编译 | `cargo build` | 0 error |
| 全测 | `cargo test` (含 crypto::aead + 集成) | 0 fail |
| clippy | `cargo clippy --all-targets` | 0 新 warning |
| 变异 (证正确性护甲非空转) | 手工: ①open_in_place 换 seal ②漏 nonce+1 ③剥零改保留 ④scratch 复用漏 clear/越界 —— 每个断言测试须杀; git restore | 全杀 |
| **bench 前后对比** | 新 `benches` 或 example: 预编 M 帧 (16KB), tight loop 解密 N 轮, 测 MB/s + **alloc 计数** (counting global allocator); baseline=recv_data(owned) vs after=recv_data_borrowed | after 吞吐↑ 且 per-frame alloc: 有→0 |
| 真执行 | loopback 单隧道 curl 大下载, 确认功能 + 粗吞吐 | http 200, 不劣化 |

## EVIDENCE
SPEC 映射 + 各层实测数 (bench MB/s before/after + alloc/frame before/after) + 不变量核验 + 诚实边界 (单隧道已远超真实链路; 本改削的是内存带宽/allocator 压力, 高并发聚合与低端 CPU 上更明显)。

## Setup
分支 `perf/recv-data-nocopy`; bench 落 `benches/recv_data_bench.rs` 或 `src/bin` 一次性; 无新运行时依赖 (counting allocator 手写)。CHANGELOG 条目随 commit。
