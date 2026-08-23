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

### 3.2 实现路径决定 (2026-08-23, 用户拍板)

先前草案倾向"自研数据报、避开 QUIC 指纹面"。复核抗检测轴时**修正**: 那个理由漏了**掩护人群**维度——
GFW 抓两类流量靠不同机制:

- **标准 QUIC**: 有正指纹 (线格式 + Initial 明文 ClientHello/SNI 可读 + JA4-QUIC), 一眼归类; 但躲进
  全网浏览器 QUIC 的**巨大人群**, 封你连带误伤 Chrome。
- **自研随机 UDP**: 无正指纹, 但"高熵无结构无 SNI 的 UDP"正是全加密流量检测盯的信号, 且**零掩护人群**。

→ 结论: **做对了的标准 QUIC (浏览器仿真 ClientHello + 真 SNI fronting) 比自研随机 UDP 更难封**。
故走**真 QUIC (quinn/rustls, 纯 Rust, 保 16 目标交叉编译) + 后续指纹仿真 (path A: patch rustls)**。
反识别层的定位随之调整: **QUIC 路径的抗检测靠"仿真真浏览器 QUIC + fronting", 不是内层 fake-TLS**
(fake-TLS 仍是 TCP 主链路的抗检测)。

分步落地: **P0 先上裸 quinn 打通测性能 (Model Y, 不隐蔽) → 真机验 UDP443 在目标链路是否可用/更快 →
再投 P1 指纹仿真的重工** (若 UDP443 被封则整条路无意义, 先证再投)。这也解释为何 P0 用 Model Y (内层
仍套 fake-TLS): P0 抄近路复用现有协议零改动, P1 转 Model X (QUIC 即混淆, 内层瘦认证) 时再精简。

## 4. 分阶段（大 epic，逐块真机验）

1. **P0 传输骨架** ✅ **已实现** (未发版, `--features quic` 默认关)：走**真 QUIC (quinn)** 而非自研
   数据报 —— 决策见下「实现路径决定」。Model Y: QUIC 做底层字节管道, 上面照跑 Mirage fake-TLS+AEAD,
   运行时开关 `transport: "quic"` 两端同设, 与 TCP 主链路并存。见 `src/proxy/quic.rs` + `tests/test_quic_e2e.rs`。
2. **P1 erasure-aware 自动 CC**：移植 2.1（erasure floor 测量 + 超出部分喂 CC + pacing 除 (1-p)）。
   **真机中美路径验**（对照现 Brutal：目标 = 免手填达到同吞吐）。这是最大价值块。
3. **P3 erasure-aware CC** ✅ **首版已实现** (未发版)：`src/proxy/quic_cc.rs` `ErasureController` 包 quinn
   内置 BBR, 测 erasure floor + 吞纯 erasure 退避 + 窗口 1/(1-floor) 补偿 (2.1)。挂 quinn
   `TransportConfig::congestion_controller_factory`。**真机 A/B 见 §5.1: stock 28KB/s → erasure 2.1MB/s (~75-100x)**。
   首版仅做窗口层补偿, 未做 pacing 层 /(1-p) 与共享瓶颈模型, 后续细化。
4. **P2 选择性 FEC**：移植 2.2（Reed-Solomon，Class bulk/interactive，block 受 RTT 上界，residual 非
   零留给重传）。真机烂链路验恢复率 vs 额外 parity 开销。
5. **mux 架构** ✅ **已实现** (未发版)：一个共享 QUIC 连接承载多条 bi-stream (每条=一条隧道), 取代
   "一隧道一连接"。**服务端每客户端就一个连接 = 一个 CC = 天然共享瓶颈** (P4 想要而独立控制器做不到
   的), 连接级 receive_window 封顶聚合在途量。**真机治好 128MB 过冲崩溃** (WND128 从 ~0 变稳定 ~41MB/s,
   20 并发扩展平坦)。`QuicMux` + WarmPool 集成, 服务端零改动 (早已 accept_bi 多流)。见 §5.4。
5b. **P4 保护交互流**：queqiao cross-flow scheduling (控制/新交互流优先于 bulk) —— mux 之上做流优先级。
6. **P1 指纹仿真** (path A: patch rustls)：抗检测。真机已证 UDP 可达 + erasure CC 有价值后再投。

## 5. 风险 / 边界

- **传输算法是用户态 CC** —— 与内核 TCP-Brutal 两套。QUIC/UDP 路径独立于 Mirage 现有 TCP 主链路，
  不替换、并存（TCP 仍是抗封锁主力，UDP 传输是"链路好时更快"选项）。
- **非 TCP-friendly 假设你自己的端到端段**（同 Brutal）：公网共享瓶颈上不合适。文档需注明。
- **erasure 模型不是"高丢包就套"**：队列溢出 vs 独立 erasure 要区分（erasure floor 测量正为此）。
- QUIC/UDP 在部分网络被限速/封（UDP 443）；作为 TCP 的补充而非替代。
- 大工程 + 用户态数据面重写，回归风险高；每块真机验（Mirage 无中美真机时无法本地证）。

## 5.1 真机实测 (2026-08-23, china-us P0)

China 客户端 → US VPS, P0 二进制 (`--features quic`), QUIC(UDP) vs TCP 同密码 A/B。

- **路径**: RTT 157ms, **27% 丢包, mdev 1ms** —— RTT 极稳说明丢包非拥塞、是**独立 erasure**
  (正是本设计针对的路径)。
- **UDP 端口 China→US 未被封** (go/no-go 通过): QUIC 隧道功能通, 出口 IP 正确。
- **吞吐 (50MB, target=VPS 自身 http, 排除第三方抖动)**:

  | 传输 | 结果 |
  |---|---|
  | QUIC (P0, quinn 默认 CC) | **~20-25 KB/s** (120s 超时只下 2-3MB) |
  | TCP (默认 CC) | 1.6-2.9 MB/s |

  **P0 QUIC 比 TCP 慢约 100 倍** —— quinn 默认 loss-responsive CC 在 27% erasure 上环路自我归零
  (= §1 表里 BBR 0.39 Mbit/s 现象)。

- **P3 erasure CC 加入后同路径 A/B** (2026-08-23, 同一 27% 丢包路径):

  | CC | 50MB 下载吞吐 |
  |---|---|
  | stock quinn (P0) | ~28 KB/s |
  | **erasure (P3, ErasureController)** | **~2.1 MB/s (两跑稳定一致)** |
  | TCP 基线 | 0.5–2.9 MB/s (波动大) |

  **erasure CC ≈ 75-100x 提升, QUIC 追平 TCP 且更稳。** 首版仅窗口层补偿 (未做 pacing /(1-p)),
  已足以把 quinn 从崩溃拉回瓶颈。

- **结论**: P0 证"管道通 + UDP 可达"; P3 证 **erasure-aware CC 是 QUIC 有价值的前提且首版即有效**。
  后续: P1 指纹仿真 (抗检测) + P2 FEC + 补 pacing 层。

### 5.2 真机实测 (2026-08-23, US↔JP 干净高带宽路径)

US 服务端 ↔ JP 客户端, 500MB 下载。路径: **RTT 111ms, 0% 丢包, mdev 0.16ms** (干净, 对照 china-us 烂链路)。

| 场景 | QUIC | TCP |
|---|---|---|
| quinn 默认小窗口·单流 | 7.5–9 MB/s (**窗口卡死**) | 48 MB/s |
| 16MB 窗口·单流 | **37 MB/s** | 36–51 MB/s |
| 4 并发聚合 | **52 MB/s** | 50 MB/s |

- **根因**: quinn 默认流控窗口 (~1MB 级) 太小, 长肥管道 (111ms) 单流被窗口卡死 (窗口/RTT 天花板)。
  TCP 内核自动调窗填满管道。→ `transport_config` 显式放大 `stream_receive_window` 默认 16MB
  (`MIRAGE_QUIC_WND` 可调), 单流即追平 TCP; 4 并发聚合双双撞 **链路/CPU 上限 ~50MB/s (~400Mbps)**, 非隧道瓶颈。
- **erasure CC 在干净路径 floor≈0 自动退化纯 BBR, 不伤性能**。
- **两路径合看**: 烂链路 (china-us 27% 丢包) 靠 **erasure CC** (28KB/s→2.1MB/s); 干净长肥路径 (US↔JP)
  靠 **大流控窗口** (9→37MB/s)。两项都需要, QUIC 才在两种 regime 都不输 TCP。⚠️ 大窗口更吃内存。

- **高并发 (10 并发, US↔JP, 200MB×10)**: 聚合多轮 QUIC 54.9/92.6/52.8 (中位~55) vs TCP 42.8/43.5/18.4
  (中位~43) MB/s。**QUIC 10 并发扩展良好、中位 ≥ TCP 且更稳** (TCP 有 18.4 低谷; QUIC 低谷 52.8, 峰
  92.6≈740Mbps)。**非 CPU 瓶颈** (单核服务端 mirage 峰值 12%)、非窗口、非内存 (客户端 10 连接 VmRSS
  峰 130MB)。撞共享链路容量 + 自然方差。**注**: P0 是"一 Mirage 隧道=一 QUIC 连接" (10 并发=10 独立
  连接/CC/crypto); 未来 mux 版 (多流骑一 QUIC 连接) 可省 per-conn 开销 + 共享 CC (P4)。

### 5.3 真机调参 (2026-08-23, CN2→US 优化线路, 找最大吞吐)

第三台真机: 国内 CN2 优化线路客户端 → US 服务端。RTT 167ms, 丢包**测试期间 5%→20% 波动**
(中国晚高峰), 2 核。目标: sweep 参数找最大吞吐。

- **流控窗口是长肥路径 (167ms) 的主杠杆** —— 单流吞吐随窗口线性涨:

  | MIRAGE_QUIC_WND | 单流吞吐 |
  |---|---|
  | 16MB | 15.8 MB/s |
  | 32MB | 27.7 MB/s |
  | 64MB | **37.7 MB/s** |
  | 128MB | 单流尚可, 但**10 并发崩溃 (~0)** |

- **WND=64MB 是甜点**: 10 并发聚合稳定 **~48-52 MB/s**。**128MB 过大 → 10 流叠加在丢包路径上
  巨量过冲、瓶颈队列爆 → 崩溃** (印证需 P4 共享瓶颈模型协调多 lane)。
- **丢包越高, erasure + QUIC 优势越大** (同时段 10 并发交替):

  | 路径丢包 | QUIC (WND64+erasure) | TCP | 倍数 |
  |---|---|---|---|
  | ~5% (测试初) | ~30-50 MB/s | ~20-25 | ~2x |
  | ~20% (晚高峰) | **~47 MB/s** | ~6.6 | **~7-8x** |

  5% 时 erasure≈stock (quinn BBR 尚能扛中等丢包); 20% 时 erasure 关键 (对照 china-us 27% 的 75x)。

- **最大吞吐配方**: `MIRAGE_QUIC_WND=64` + **~10 并发** + erasure CC。再大窗口在并发+丢包下过冲反伤。
  默认 16MB 是安全值 (并发下不崩); 高 BDP 独占场景手动调到 64 榨单流。⚠️ 大窗口吃内存 (每连接)。

## 7. P1 抗审查 —— **重定向为 SNI 层** (据 USENIX Security 2025)

### 7.0 关键 reframe: GFW 查的是 SNI, 不是 ClientHello 指纹
USENIX Security 2025《揭示并绕过 GFW 基于 SNI 的 QUIC 封锁》: GFW (2024-04 起) **解密 QUIC Initial
读 SNI 按黑名单封**, **不**按 ClientHello 形状指纹 (JA4)。细节: 仅当 src_port>dst_port 才查; 良性 SNI
即过; >90% 1 秒内被封。**→ 原计划"fork rustls 做 JA4 字节仿真"防错了威胁; 有效规避在 SNI 层, 且大多
不需 fork。** (佐证: queqiao/Hysteria 也走 SNI 层, 不做 QUIC ClientHello 仿真。)

### 7.1 已做 (SNI 层, 不 fork)
- **良性 SNI (默认)**: QUIC ClientHello SNI 用 camouflage_host (良性域名) 非 server 真身。
- **ALPN `mirage-p0` → `h3`**: 去掉活靶子 ALPN。
- **源端口 ≤ dst (opt-in)**: 利用"仅 src>dst 才查"规则让 GFW 干脆不查。best-effort, dst≤1024 需 root。
- **pre-packet (opt-in)**: 握手前发随机 UDP 包 desync 四元组追踪。

### 7.1a 真机验证 (2026-08-23, CN2→US): SNI 层代码坐实
tshark 抓包**确认线上 QUIC Initial SNI = www.apple.com (良性) + ALPN = h3** —— ①② 代码坐实上线。
(初测时 QUIC 传输被切、TCP 满速, 一度误判"GFW 针对 QUIC"; **深挖后证实是 quinn 的 gap 上限 bug, 非
GFW —— 见 §5.5**。修掉窗口后 QUIC 正常传输, SNI 层规避与传输功能两回事、都不受 GFW 影响。)

### 7.2 评估后不做 / 阻塞

### 7.2 评估后不做 / 阻塞
- **ECH**: rustls 0.23 **无服务端 ECH**, 自建 server 解不了内层 ClientHello; 良性 SNI 已覆盖, 冗余。
- **Initial 分片 / SNI 切片**: 最鲁棒 (对齐 Chrome v124+/quic-go/Hysteria), 但 **quinn 公开 API 无分片
  控制** (ClientHello ~400B 装一个 Initial 包不会拆, initial_mtu/max_udp_payload 都强制不了), **需 fork
  quinn-proto 手动拆 CRYPTO 帧** —— 维护债。良性 SNI 已防当前威胁, 故**暂缓**; 若 GFW 硬化 SNI 封锁
  (超出黑名单, 如封未知 SNI / SNI-IP 不符) 再投。

### 7.3 残留: ClientHello 形状指纹 (JA4) —— 仍是独立 epic (低优先)
若 GFW **未来**改用 QUIC ClientHello 指纹 (像对其他协议那样), 才需下面的字节级仿真。当前 GFW 不这么做,
故**不为假想威胁先付 fork 代价**。真要做时的路 (均非小工程):

GFW (未来若) 匹配的 QUIC 指纹 = ①Initial 包结构 ②quic_transport_parameters 集合/顺序/值 ③**Initial 内的
TLS1.3 ClientHello (cipher/扩展顺序/GREASE/key_share)** ④SNI (需真 fronting)。第③项是主战场。

**阻塞: rustls 不暴露 ClientHello 扩展顺序/GREASE 控制** (uTLS 之所以存在正为此), 且 **Rust 生态
无成熟 uQUIC/uTLS 等价物**。故 quinn+rustls 出来的是"rustls 指纹", JA4-QUIC 可辨, 与真浏览器不同。

### 选项 (需选一条投入, 均非小工程)
| 路 | 做法 | 代价 |
|---|---|---|
| **A. patch rustls** (倾向) | fork/改 rustls 让其按目标 Chrome 精确排布 ClientHello 字节 + GREASE | 啃 rustls 内部, 多周; 但保纯 Rust + 16 目标交叉编译 |
| B. quiche/BoringSSL | 换 Cloudflare quiche (底层 BoringSSL=Chrome 的 TLS 栈), 指纹近似白送 | **炸纯 Rust 16 目标交叉编译** (C 依赖 × musl×8), 与项目定位冲突 |
| C. 贡献/等 Rust-uTLS | 推动社区做 Rust 版 uTLS, 再接入 | 不可控时程 |

### 配套 (P1 落地时一并)
- **服务端也要像被 front 的真站** (h3 响应 / 认证失败转发真站) —— 复用 TCP 侧已有的 REALITY 式逻辑。
- **JA4-QUIC harness**: 扩现有 JA4 对照工具到 QUIC, 拿真 Chrome QUIC 当基线校验字节级一致。
- SNI 指向真 fronting 站 (Initial 明文暴露 SNI)。

### 决策依据 (真机已证)
UDP 端口 China→US **未被封** (P0 三台真机), erasure CC + 大窗口在丢包/长肥路径**已证有价值** —— 
即"先证 UDP 可达 + 传输值得, 再投指纹重工"的 gate 已过。**P1 是让 QUIC 能扛主动检测/封锁的前提,
建议作为独立 epic 立项** (path A)。在它落地前, QUIC 传输只作"链路好且不担心指纹时更快"的 opt-in。

### 5.4 mux 架构真机验证 (2026-08-23, CN2→US)

把"一隧道一 QUIC 连接"改为"多流骑一共享连接"后, 同 CN2→US 路径:

| 场景 | pre-mux (独立连接) | mux (共享连接) |
|---|---|---|
| WND=64 10 并发 | ~50 MB/s | ~43 MB/s (单 CC 略保守) |
| **WND=128 10 并发** | **崩溃 ~0** (10×窗口过冲) | **~41 MB/s 稳定** ✅ |
| 20 并发 | (未测, 预期更崩) | ~41 MB/s 平坦扩展 |

- **根因治愈**: 服务端每客户端只见一个 QUIC 连接 → **一个 CC + 一个连接级 receive_window** 封顶所有流
  的聚合在途量, 不再是 N 条独立连接各自过冲。这正是 §7 里说"真共享瓶颈受 quinn Controller API 无 peer
  上下文所限、需 mux 才能干净实现"的兑现 —— **mux 用架构解决了 P4 独立控制器解决不了的问题**。
- 权衡: 单 CC 比 N 条独立连接抢带宽略保守 (WND64 43 vs 50); 一个连接是单点 (断则齐掉, 靠重拨+池
  stale/handler 重试恢复)。换来无过冲崩溃 + 高并发省 per-conn 开销 + 天然共享瓶颈。

### 5.5 ⚠️ quinn gap 上限 vs 重排序线路 (2026-08-24, 深挖"~1MB 切断")

**现象**: CN2→US 上 QUIC 传输恒被切在 ~1MB (TCP 同路径满速), 一度误判"GFW 针对 QUIC"。

**深挖 (client debug 日志)**: `quinn_proto: closing connection due to transport error: too many gaps in
stream buffer`。根因 = **quinn-proto 0.11.17 的 `MAX_CHUNKS=1024` 硬界** (乱序流重组的并发 chunk 上限,
正是 RUSTSEC-2026-0185 修复引入的界; 0.11.14 无界能下完但有内存漏洞)。

**机理**: 抓包显示 1MB≈833 包却触发 1024 gap = **接近每包乱序 → CN2 是重排序线路** (CN2 优化线路多用
多路径/负载均衡, 天然重排序)。并发乱序 chunk 数 ≈ 在途包数, 大窗口 (16MB=万级在途包) 必超 1024 → 关连接。
**非 GFW** —— TCP 无此界故满速; 之前 china-us 27% 丢包能下完是因为用的 0.11.14 (无界)。

**验证**: 同路径 `MIRAGE_QUIC_WND=2` (小窗口→在途少) **3×50MB 全下完, 零 gap 错误**; 4/8/16MB 均切。

**修复**:
1. **默认窗口 16→2MB** (真机确认: **4MB 在 CN2 仍切、2MB 稳** —— 即使 0% 丢包下 4MB 也切、2MB 完整
   下完 3×50MB @ ~11MB/s, 证实是重排序驱动非丢包)。面向中国重排序线路取安全默认; 干净长肥可调大 16-64。
2. **erasure CC 加 gap-safety 封顶** (`quic_cc.rs` GAP_SAFE_CHUNKS): 按测到的丢包率封顶 cwnd 使 gap < 界
   —— 但只治**丢包驱动**的 gap 且校准后才生效; 纯重排序 (gap≈在途包数, 与丢包率无关) 主要靠小窗口治。
3. ⚠️ **本质无免费午餐**: MAX_CHUNKS 硬界 = QUIC 在重排序路径上须小窗口 (限单流吞吐); 干净路径可大。
   这是 quinn 0.11.17 的已知局限, 不 fork quinn 无法根治。文档标明重排序线路调小窗口。

**教训**: 升级依赖 (为修 RUSTSEC) 可能引入行为回归; 且"传输被切"先排查自己的传输栈, 别急着归因 GFW。

## 6. 结论

queqiao ≈ Mirage「UDP mux → QUIC」epic 的**参考实现**，且解决 Mirage 最大痛点（Brutal 手填速率
→ 自动定速）。**最大价值 = erasure-aware 自动 CC（P1）**，其次 FEC（P2）。反识别层不变（Mirage
自有 fake-TLS 已领先）。倾向：吸收**算法**用在 Mirage 自有数据报 mux 上，不必绑 QUIC 线协议（避免
新指纹面）—— 但这点待真机 + 威胁模型定。移植时直接研读 `erasure.go` + `fec/rate.go`。
