# quinn-proto 0.11.17 —— Mirage 补丁

本目录是 crates.io 上 `quinn-proto 0.11.17` 的原样副本（`src/`、`Cargo.toml`、许可证），经根 `Cargo.toml` 的
`[patch.crates-io]` 替换上游版本。**只改了一处**：

| 文件 | 改动 |
|---|---|
| `src/connection/assembler.rs` | `MAX_CHUNKS` 由 `1024` 改为 `8192` |

## 为什么改

`MAX_CHUNKS` 是接收端单条流可缓存的乱序数据段数上限（defragment 之后仍超限即 `TooManyChunks`，以
`INTERNAL_ERROR "too many gaps in stream buffer"` 断开连接）。上游为修复 RUSTSEC-2026-0185 引入该上限，
防止恶意对端用碎片帧迫使接收端反复整理内存。0.11.19 仍为 1024。

在高 RTT + 高丢包链路上，要跑满带宽，流控窗口需约 2.5 × BDP（100 Mbps、180ms RTT 时约 6–8MB）：丢包形成的空洞需约
1.5 个 RTT 才能被重传补齐，期间后续数据只能缓存。空洞数约等于「丢包率 × 窗口内的包数」，1024 在 10% 以上丢包时
就会被突破，连接被直接断开。

实测（netns + netem，RTT 180ms，带宽 100 Mbps，详见 `docs/benchmark-2026-09.md` §3.5）：

| 条件 | sing-box hysteria2 | 上限 1024 + 2MB 窗口 | 上限 8192 + 8MB 窗口 |
|---|---|---|---|
| 下行丢包 10% / 上行 5% | 69–73 Mbps | 27–31 | 68–70 |
| 下行丢包 20% / 上行 10% | 50–57 | 20–23 | 53–61 |

上限 1024 时，8MB 窗口一遇丢包即断连（≈3 Mbps），所以单纯放大窗口不可行。

## 安全取舍

- 未认证的对端可以先完成 QUIC 握手，并在 Mirage 口令校验之前发送碎片化的流数据，因此上限放大会提高最坏情况下的
  defragment CPU 开销（8192 段，仍是有界的 O(n log n)）。
- 内存不受影响：缓存数据仍受接收窗口约束（单流 `quic_window_mb`，连接级为其 4 倍）。
- QUIC 传输是实验特性：release 二进制包含 QUIC 代码，但只有配置 `transport: "quic"` 的入站 / 出站才会监听或使用 QUIC。

## 升级 quinn-proto 时

1. 把新版本的 `src/`、`Cargo.toml`、许可证覆盖到本目录。
2. 重新应用上面这一处改动（`assembler.rs` 里的 `MAX_CHUNKS`）。
3. 同步根 `Cargo.toml` 中 `quinn-proto` 的版本约束，跑 `cargo test --features quic`。
4. 若上游已把该上限做成可配置项，删除本目录与 `[patch.crates-io]`，改为在 `TransportConfig` 里配置。
