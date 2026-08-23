# QUIC 传输设计：erasure-aware 自动 CC + FEC（吸收 queqiao）

> 状态：**设计草案**（未实现）。对应 roadmap「UDP mux → QUIC Datagram」epic。
> 参考：`/opt/reference/queqiao`（bojieli/李博杰，Go + apernet/quic-go）。分析见 brain
> `reference-projects-analysis`。最后更新 2026-08-23。

## 1. 动机（为什么值得做）

Mirage 现有传输：**fake-TLS-over-TCP**（主链路）+ **UDP mux**（透明 UDP，一隧道复用多流）。
两个真实痛点，正好是中美烂链路：

1. **Brutal 要手填速率。** `tuning.brutal_rate_mbps` 得人肉估带宽，估错就浪费或拥塞。
2. **TCP 有队头阻塞。** UDP mux 把多流塞进一条 TCP 隧道，一条流丢包连累同隧道其他流（brain
   `udp-capacity-findings` 已记）；TCP 本身在高丢包长 RTT 上也慢。

queqiao 在**同款中美路径**上实测（`docs/PATH-CHARACTER-20260813.md`）：**~42% 独立丢包**（与发送
速率无关，1 Mbit/s 和 12 Mbit/s 一样丢），loss-responsive CC 全崩：

| CC | 吞吐 (Mbit/s) |
|---|---|
| Reno/Cubic (默认) | 0.13 |
| BBR | 0.39 |
| BBR-TUIC | 1.36 |
| Brutal（人手填 25 Mbit/s） | 13.89 |

只有 Brutal 拿得到路径 —— **因为它无视丢包、按人手填的速率 pace**。queqiao 的 **ErasureSender**
不用人手填就到同一位置。这就是 Mirage 该吸收的核心。

## 2. 从 queqiao 吸收什么（按价值排序）

### 2.1 ErasureSender —— erasure-aware 自动定速 CC ⭐（最高价值）

源：`internal/congestion/erasure.go`。是"包在 BBR 外面的两处修正"：

- **修正一：信道丢包不当拥塞。** 测 **erasure floor** = 降低发送速率也不减少的那部分丢包（独立
  erasure）。只把**超出 floor 的部分**当拥塞信号喂给 BBR。floor 是**下包络**（队列丢包只会抬高
  某次观测，不会抬高信道底噪）；需 ≥100 个包定论前一律透传（未测路径行为 == 纯 BBR）。
- **修正二：pacing 除以到达率 (1-p)。** BBR 的带宽估计是**送达速率**，但 pacer 控的是**发送速率**。
  干净路径两者相等；erasure 信道上，发 S 送达 S(1-p)，成为下次估计，pace 成 S(1-p)，送达
  S(1-p)² …… 每轮走低直到归零（这就是上表 BBR 的 0.39）。**pacing 除以 (1-p)** 恢复 BBR 假设的
  性质，环路收敛到瓶颈而非零：startup 每轮按 gain 增长直到送达不再增长（恰好在 S 达到瓶颈时）。
- 上瓶颈后丢包不再无记忆（丢包串从 1.7 涨到 5.7），超 floor 的部分变正，BBR 照常退避。**既不
  无视拥塞，也不把信道 erasure 当拥塞。**
- 边界常量：`erasureMinArrival=0.15`（补偿封顶 ~7x，太低的路径不该硬推）、`erasureMinSamples=100`、
  `erasureEarlyMaxFloor=0.65`（bootstrap 期防小样本误判导致 >3x 暴涨）。

**对 Mirage 的意义**：替掉「Brutal 手填速率」→ **自动收敛瓶颈**。这是 QUIC 传输最大的用户价值。

### 2.2 选择性 FEC（Reed-Solomon）

源：`internal/fec/`（`gf.go` 伽罗华域 · `window.go` · `rate.go`）。长 RTT 丢包**无需往返**恢复
（一个来回在中美 = 数百 ms）。关键：**参数全测量不配置**（`rate.go`）：

- `Class`：**Bulk**（码率贴近容量，可等一个 block）vs **Interactive**（早出 repair，多付 parity）。
- block 长度受 **RoundTrip 上界约束**：一个 block 发得比重传到达还慢，就白搭了 —— 编码唯一的
  意义是"比重传快"。
- `TargetResidual`（可接受的"整 block 不可修需重传"概率）**故意非零**：压到零 parity 几何增长，
  而尾部**正是重传擅长的**。→ FEC 修主体，重传兜尾。

**对 Mirage**：Mirage **无 FEC**。仅适用于**数据报传输**（QUIC/UDP），TCP 上无意义（TCP 自己重传）。

### 2.3 共享瓶颈路径模型

源：`internal/pathmodel`。同一 client→gateway 的多条 lane **共享** delivery/loss/RTT/pacing/floor
状态。新开的 lane 从共享的"已补偿送达速率 + floor" **seed**（不重付 ramp —— 42% 丢包路径上 ramp
是最贵的）。独自决策会让聚合**过冲 lane 数倍**、把路径丢包从无记忆推成拥塞。

**对 Mirage**：UDP mux 现共享隧道但**不共享 CC 状态**；应共享（多流一个模型）。拓扑天然吻合：
queqiao 假设「多流 → client → 单一主瓶颈 → gateway」，**正是 Mirage client→server**。

### 2.4 多路复用重组 + 共享内存预算

源：`internal/multipath/reassembly.go`。QUIC lane 可乱序到达，应用流须严格有序重组；**共享内存
预算非阻塞** —— overload **只挂一条流**不死锁全部（暂停一条 lane 可能连带暂停补空缺所需的段）。

**对 Mirage**：UDP mux HoL + 内存安全的参考做法。

## 3. Mirage 集成架构（关键分歧点）

**queqiao 只做传输性能，混淆委托 sing-box**（`internal/extproxy/singbox.go` + 真 TLS PKI 证书认证
`internal/identity/tls.go`）。它**明确非匿名网络、无 DPI 规避**（`KNOWN-LIMITATIONS`：provider 看得到
目标与流量形态）。

→ **Mirage 的映射**：**反识别层仍是 Mirage 自己的**（fake-TLS + REALITY 式 + ClientHello 仿真），
只把 queqiao 的**传输性能内核**（erasure CC + FEC + 共享模型）搬进来。分层：

```
[Mirage fake-TLS/camouflage 认证握手]   ← 反识别, 不变 (Mirage 自有, 已领先参考项目)
        └── 承载 ──▶ [QUIC-datagram 传输]  ← erasure CC + FEC + 共享瓶颈 (吸收 queqiao)
                          └── 多路复用 ──▶ 应用 TCP/UDP 流
```

### 3.1 硬问题：QUIC 指纹 vs Mirage 的反识别

QUIC 自带 TLS 1.3 ClientHello + QUIC transport parameters，**有独立指纹**（uQUIC/uTLS 存在正为此）。
Mirage 现有反识别是 **TCP-fake-TLS**。三条路，需真机 + 威胁模型定：

1. **QUIC 走明面（如 Hysteria2）**：QUIC/H3 在公网已普遍，直接用 quinn 的 QUIC，接受其指纹。
   代价：与 Mirage 现有 TCP-fake-TLS 指纹策略不统一；QUIC 在某些网络被限速/封（UDP 443）。
2. **QUIC ClientHello 仿真**：uQUIC 式仿真真实浏览器 QUIC 指纹。工程量大，quinn 需改。
3. **QUIC-over-fake-TLS 不可行**：QUIC 要 UDP，Mirage fake-TLS 是 TCP 记录层，套不进。真正可比的是
   "把 erasure CC + FEC 用在 Mirage 现有 **UDP mux 数据报**上"（不引入 QUIC 的 TLS 握手），
   **自定义数据报传输**复用 Mirage fake-TLS 握手派生的密钥。← **可能是最契合 Mirage 的路**：
   要的是 queqiao 的**算法**（erasure CC/FEC/共享模型），不是 QUIC 协议本身。

> **倾向**：先不追 QUIC 协议，而是把 **erasure-aware CC + FEC + 共享瓶颈模型移植到 Mirage 自有的
> UDP 数据报 mux 上**（保留 Mirage fake-TLS 反识别、避免 QUIC 指纹新面）。"QUIC" 是路线图的名字，
> 真正的营养是**烂链路传输算法**，与是否用 QUIC 线协议正交。待真机与威胁模型复核后定。

## 4. 分阶段（大 epic，逐块真机验）

1. **P0 数据报传输骨架**：Mirage 自有 UDP 数据报 mux（复用 fake-TLS 握手密钥），带序号 + 有序重组
   （吸收 2.4 的共享内存预算、非阻塞、fail-one-flow）。
2. **P1 erasure-aware 自动 CC**：移植 2.1（erasure floor 测量 + 超出部分喂 CC + pacing 除 (1-p)）。
   **真机中美路径验**（对照现 Brutal：目标 = 免手填达到同吞吐）。这是最大价值块。
3. **P2 选择性 FEC**：移植 2.2（Reed-Solomon，Class bulk/interactive，block 受 RTT 上界，residual 非
   零留给重传）。真机烂链路验恢复率 vs 额外 parity 开销。
4. **P3 共享瓶颈模型**：2.3，多流共享 CC/floor，新 lane seed。
5. **P4 保护交互流**：queqiao 的 cross-flow scheduling（控制/新交互流优先于 bulk）。

## 5. 风险 / 边界

- **传输算法是用户态 CC** —— 与内核 TCP-Brutal 两套。QUIC/UDP 路径独立于 Mirage 现有 TCP 主链路，
  不替换、并存（TCP 仍是抗封锁主力，UDP 传输是"链路好时更快"选项）。
- **非 TCP-friendly 假设你自己的端到端段**（同 Brutal）：公网共享瓶颈上不合适。文档需注明。
- **erasure 模型不是"高丢包就套"**：队列溢出 vs 独立 erasure 要区分（erasure floor 测量正为此）。
- QUIC/UDP 在部分网络被限速/封（UDP 443）；作为 TCP 的补充而非替代。
- 大工程 + 用户态数据面重写，回归风险高；每块真机验（Mirage 无中美真机时无法本地证）。

## 6. 结论

queqiao ≈ Mirage「UDP mux → QUIC」epic 的**参考实现**，且解决 Mirage 最大痛点（Brutal 手填速率
→ 自动定速）。**最大价值 = erasure-aware 自动 CC（P1）**，其次 FEC（P2）。反识别层不变（Mirage
自有 fake-TLS 已领先）。倾向：吸收**算法**用在 Mirage 自有数据报 mux 上，不必绑 QUIC 线协议（避免
新指纹面）—— 但这点待真机 + 威胁模型定。移植时直接研读 `erasure.go` + `fec/rate.go`。
