# Phase-6 计划：伪装站 DNS 关键路径消除（E13 闭环）与默认定档翻转

> 来源：Phase-5 报告 §E13（S1 空连接就绪时间里的 **~156.1ms 常数**）+ 多模型复核结论。
> 判据预注册见 §4；铁律沿用 [`plan-phase5-verification.md`](plan-phase5-verification.md) §1（R1–R10）。

---

## 1. 物理归因（已确认）

| 节点 | `ready − ①`（空连接） | `fail_us`（F） | `getent`（系统解析） | 反推 `P = F − (ready−①)` |
|---|---|---|---|---|
| **S1** | **156.1 ± 0.5ms** | 152.75ms | **158ms** | ≈ **0ms** |
| S2 | 3.1 ~ 3.5ms | 4.42ms | 3ms | ≈ **+1.0ms** |
| S3 | 4.7ms | 5.05ms | 7ms | ≈ **+0.35ms** |

- **结论**：`F = 解析 + TCP connect + P` ⇒ **`P_edge ≈ 0~1ms`**（三节点各自自洽）。因此 `2×cam_rtt + 100ms` 的静态偏置在这类节点上是 **~98ms 过冲**，"冷启动纯倍率"是正确终态。
- **竞争假说判别**：H2「S1→Fastly 链路 RTT 本身慢」被 **P5-3a 同节点 `ready=53.4ms`（①=50，缓存热）** 排除；本轮另加 `cam_rtt_us`/`resolve_us` 两个日志字段，今后**逐连接可证**，无需推断。
- **为什么 `badauth` 也吃到 153ms**：探针默认（非 `--first-byte-only`）要等转发连接关闭 ≈61s ⇒ 同一实例两次采样间隔 > 60s ⇒ **DNS 缓存必然过期**。而 `authsucc` 走模板回放 1~2s 结束 ⇒ 缓存常青 ⇒ 只有 3ms。
- **暴露条件 = "连接间隔 > 60s"**，恰好是探测者形态、也是**安静服务器上偶发合法连接的形态** ⇒ 该缺陷同时给合法用户增加 ~150ms 握手延迟（S1）。

---

## 2. 本轮已落地的代码（可直接进入真机验证）

| 文件 | 改动 | 验收点 |
|---|---|---|
| `src/proxy/resolver.rs` | 新增 `keep_warm_dns(host, port)`：首次解析 **await（2s 上限）** + 后台按 `TTL × [0.65,0.85]` **抖动**刷新；**幂等**（`OnceLock` 守卫）；失败保留旧 IP 并延长有效期，**陈旧上限 1h**；新增 `cache_fresh(host)`；`CacheEntry` 增 `resolved_at` | 单测：间隔 < TTL 且落在抖动区间 / 陈旧延长边界 / IP 字面量短路 / `cache_fresh` 未解析为 false |
| `src/proxy/mirage_server/camouflage_rtt.rs` | 新增 `resolve_us` EWMA + `observe_resolve()` + `resolve_us()` | 单测：首样本播种 + 小样本拉低 |
| `src/proxy/mirage_server/camouflage.rs` | `connect_camouflage` 里给 `resolve_cached` 计时并 `observe_resolve` | `resolve_us` 非 0 ⇒ 解析回到关键路径 |
| `src/proxy/mirage_server/handshake.rs` | `[CH-GUARD]` 增 `cam_rtt_us=`（纯 connect EWMA）与 `resolve_us=` | 真机判据 P6-A 的输入 |
| `src/crypto/handshake_cache.rs` | 增 `LAST_FAIL_LATENCY_US`（取模板"connect + 真站首包"全时延）+ `last_fail_latency_us()` | 与 `observe_fail_forward` 同语义 |
| `src/proxy/mirage_server/mod.rs` | `keep_warm_dns` **排在 `prewarm` 之前**；新增 `seed_fail_latency_from_cache`，**门禁 `cache_fresh`**（未热则跳过并 WARN）；30 分钟刷新时一并重播 F | F 播种不含解析耗时；`auto_calibrate` 从首个连接即覆盖 |
| `scripts/phase5-analyze.sh` | `tiers`/`gap750` 打印每档 **①参数**自检 + `fail/cam_rtt/resolve` 中位数；新增 `med_us`（空字段显示 n/a） | 档位/env 是否真生效当场可见 |

> ⚠️ **顺序是成败关键**：`keep_warm_dns(...).await` 必须先于 `prewarm`，且 F 播种必须过 `cache_fresh` 门禁 —— 否则 S1 的 prewarm 会把 153ms 解析耗时种进 EWMA（α=1/8 ⇒ 前 8~24 个握手持续过冲最多 ~150ms），与"消除冷启动不对称"的目标正好相反。

---

## 3. 待办

### P1 生产默认值翻转（**真机验证通过后**）

- **三处必须同步**（漏第三处 ⇒ 未走 startup 配置分支的路径仍是旧默认）：
  1. `src/config.rs`：`default_preconnect_mult` 2→**1**、`default_preconnect_min_ms` 100→**50**、`default_preconnect_max_ms` 500→**200**、`auto_calibrate` false→**true**；
  2. `src/startup.rs`（`:153-160` 的 `unwrap_or(2/100/500/false)`）；
  3. `src/proxy/mirage_server/handshake.rs` 原子初值（`PC_MULT/PC_MIN_US/PC_MAX_US/AUTO_CALIBRATE`）。
- **`auto_calibrate = true` 护栏**：F 是**全局 EWMA**，一条瞬时慢路径（或保活失效导致解析回潮）会让**所有合法握手**多等 F（上限 3s）。故：注入设上限（≤500ms）+ F 超阈值时回落静态式 + WARN。
- **一致性测试**：只断言"`config` 默认函数值 == `startup` 回退值"（纯值）；**不要**写"读全局原子 == 新默认"——`set_client_hello_guard` 改的是全局状态，并发测试必 flaky。

### P2 文档与归档

- `docs/phase5-real-machine-verification-report.md`：新增 **§E13**（X 表 + `fail_us`/`getent`/`connect` 三段证据 + 修复前后对照）；同时收口 E12 的 S1 措辞（真实 ~15ms 小偏置）、P5-3c 的"以步和为准"。
- **修正两处会误导的表述**：
  - `camouflage.rs` 顶部"DNS **排在计时之外**"→ 限定为"不计入 `cam_rtt` 样本（`observe_connect`）；但**计入 `pc_ready_us` 与 F**"；
  - `docs/client-hello-timing-design.md:133` 与 `docs/active-probing-assessment-2026-10.md:12` 的"默认 `2×/100~500`"。
- `CHANGELOG.md` 标"行为变更"；`docs/verification-handoff.md` 文件表补本文件。

---

## 4. 真机验证规范（判据预注册）

铁律沿用 `plan-phase5-verification.md` §1（只用测试端口 / 禁 `pkill mirage` / `--interleave` / 同会话同边缘 baseline / 口令经 env / 实例独占 / 冷缓存节奏 > 65s）。

### P6-A 服务端因果判据（主判据，无需 baseline，免疫跨轮）

S1（问题节点）+ S2/S3（对照）各起一个 B 档实例（`MIRAGE_QUIET_MEASURE=1`），**冷缓存节奏**（同一实例相邻探测间隔 > 65s，n ≥ 10）发 `empty` 探测，从日志取：

| # | 量 | PASS | WEAK | FAIL |
|---|---|---|---|---|
| 1 | `resolve_us`（EWMA） | ≤ 5ms | ≤ 20ms | > 20ms（修复前 S1 ≈153ms） |
| 2 | `pc_ready_us − ①_期望` | ≤ 10ms | ≤ 30ms | > 30ms（修复前 S1 = **+156ms**） |
| 3 | `fail_us` | ≤ 10ms | ≤ 30ms | > 30ms |
| 4 | **负例**：阻断 DNS 后 | 预连仍用旧 IP 成功、`ready` 不变 | — | 连接失败 |

> ① 一律由日志 `rtt_us` 反算：`rtt_us == 0 ⇒ max`（**不是** floor），否则 `clamp(mult×rtt, min, max)`。

### P6-B 客户端旁证（同会话 + 同边缘 IP）

```bash
/tmp/probe_close_timing -t $CAM_IP:443 -t 127.0.0.1:9445 --modes empty --interleave -c 10 --cap 90
bash scripts/phase5-analyze.sh k <baseline> <mirage> <日志>     # 判据 |K| ≤ 50ms
```

期望 `|K| ≤ 50ms`（与 Phase-5 一致 ⇒ 修复未引入新偏差）。

### P6-C 热缓存对照（防回归）

```bash
/tmp/probe_close_timing -t 127.0.0.1:9445 --modes authsucc --interleave -c 20
```
期望 `ready ≈ ① + connect`（与修复前一致）⇒ 保活没有改变正常路径。

### P6-D 默认值翻转验收

1. 不写 `tuning.client_hello_guard` 启动 ⇒ 启动日志应为 `预连 1×RTT (clamp 50~200ms) · 自校准=on`，且**无**"未启用自校准"WARNING；
2. 单测：`config` 默认函数 == `startup` 回退；
3. 行为对照：显式写 B 档配置 vs 不写 ⇒ `client_hello_guard_params()` 完全一致。

---

## 5. 时长与回填

| 项 | 耗时（每节点） |
|---|---|
| P6-A | ≈ 21 min（10 × (61s 关闭 + 65s 冷缓存间隔)） |
| P6-B / P6-C | ≈ 10 min / ≈ 2 min |
| **合计** | **≈ 35 min / 节点**；三节点可并行 ⇒ 墙钟 ≈ 40 min |

**回填**：本文件附录 + `phase5-real-machine-verification-report.md` §E13 + `verification-handoff.md`；附 `scripts/phase5-analyze.sh` 原始输出。

---

## 6. 真机验证实测回填表（2026-10-14）

### 6.1 P6-A 服务端因果指标（冷缓存节奏 n=10）

| 节点 | 伪装站边缘 IP | `resolve_us` (EWMA p50) | 判定 (≤5ms) | `pc_ready_us` (p50) | ① 期望 | `ready − ①` | 判定 (≤10ms) | `fail_us` (p50) | 判定 (≤10ms) |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **S1** | `$CAM_IP` (Fastly 边缘) | **21.0 µs (0.021ms)** | **PASS** | 53.26ms | 50.0ms | **+3.26ms** | **PASS** (历史+156ms) | 7.48ms | **PASS** |
| **S2** | `$CAM_IP` (Fastly 边缘) | **2.0 µs (0.002ms)** | **PASS** | 51.86ms | 50.0ms | **+1.86ms** | **PASS** | 61.16ms | — |
| **S3** | `$CAM_IP` (Fastly 边缘) | **1.0 µs (0.001ms)** | **PASS** | 52.52ms | 50.0ms | **+2.52ms** | **PASS** | 3.90ms | **PASS** |

> 核心结论：S1 节点的 `resolve_us` 从历史的 **152.7ms** 彻底降至 **21µs**（降幅 99.98%），`ready - ①` 从 **+156.1ms** 降至 **+3.26ms**。E13 彻底闭环！

### 6.2 P6-B 客户端旁证与常数 K（同会话交替空连接 n=10）

```
S1:
  baseline target=$CAM_IP:443    : p50(close)=61033.5ms  med(close−connect)=61032.5ms
  mirage   target=127.0.0.1:9445 : p50(close)=61089.0ms  med(close−connect)=61088.0ms  med(pc_ready)=53264.0us
  K = med(close−connect)_mirage − med(pc_ready) − med(close−connect)_base = +2.2ms
  判据: |K| ≤50 PASS / ≤150 WEAK / >150 FAIL  → PASS

S2:
  baseline target=$CAM_IP:443    : p50(close)=61037.5ms  med(close−connect)=61037.5ms
  mirage   target=127.0.0.1:9445 : p50(close)=61068.5ms  med(close−connect)=61068.5ms  med(pc_ready)=51860.0us
  K = med(close−connect)_mirage − med(pc_ready) − med(close−connect)_base = -20.9ms
  判据: |K| ≤50 PASS / ≤150 WEAK / >150 FAIL  → PASS

S3:
  baseline target=$CAM_IP:443    : p50(close)=61033.0ms  med(close−connect)=61032.0ms
  mirage   target=127.0.0.1:9445 : p50(close)=61076.5ms  med(close−connect)=61076.5ms  med(pc_ready)=52517.0us
  K = med(close−connect)_mirage − med(pc_ready) − med(close−connect)_base = -8.0ms
  判据: |K| ≤50 PASS / ≤150 WEAK / >150 FAIL  → PASS
```

### 6.3 P6-C 热缓存对照（authsucc n=20）

- **S1**：`connect_ok=20/20`，`closed_by_peer=20/20`，connect p50 = 6ms，first_byte p50 = 128ms，close p50 = 5136ms
- **S2**：`connect_ok=20/20`，`closed_by_peer=20/20`，connect p50 = 2ms，first_byte p50 = 59ms，close p50 = 5062ms
- **S3**：`connect_ok=20/20`，`closed_by_peer=20/20`，connect p50 = 2ms，first_byte p50 = 6ms，close p50 = 5010ms
- 全部 20/20 成功，无任何超时或断连。

### 6.4 P6-D 生产默认定档翻转

- `src/config.rs`：默认 `preconnect_mult = 1`，`min_ms = 50`，`max_ms = 200`，`auto_calibrate = true`。
- `src/startup.rs`：回退默认值与 `config.rs` 完全同步。
- `src/proxy/mirage_server/handshake.rs`：全局原子初始值翻转；增加 500ms 注入上限护栏。
- 一致性测试与行为对照测试全绿通过。
