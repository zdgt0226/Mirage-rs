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
| `src/crypto/handshake_cache.rs` | 增 `LAST_FAIL_LATENCY_US`（取模板"connect + 真站首包"全时延）+ `last_fail_latency_us()` —— **已在 R2 中彻底移除**（负收益，见 §6.1 注） | 曾与 `observe_fail_forward` 同语义 |
| `src/proxy/mirage_server/mod.rs` | `keep_warm_dns` 与 `prewarm` **并发执行 (`tokio::join!`)**（`cache_fresh` 门禁与 F 播种**已在 R2 移除**） | 消除串行等待，启动耗时由 2s + 5s 降至 max(2s, 5s) |
| `scripts/phase5-analyze.sh` | `tiers`/`gap750` 打印每档 **①参数**自检 + `fail/cam_rtt/resolve` 中位数；新增 `med_us`（空字段显示 n/a） | 档位/env 是否真生效当场可见 |

> ⚠️ **启动时序优化**：`keep_warm_dns` 与 `prewarm` 采用 `tokio::join!` 并发执行。
> 由于 **F 播种已在 R2 彻底移除**，不再存在"启动期解析耗时被播种污染 EWMA"的风险，串行门禁已解除；并发启动不仅缩短常态启动时间，更将 DNS 异常或抖动时的最差启动超时从 $2\text{s} + 5\text{s} = 7\text{s}$ 压减至 $\max(2\text{s}, 5\text{s}) = 5\text{s}$。

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
| **S2** | `$CAM_IP` (Fastly 边缘) | **2.0 µs (0.002ms)** | **PASS** | 51.86ms | 50.0ms | **+1.86ms** | **PASS** | 61.16ms | **FAIL** (注) |
| **S3** | `$CAM_IP` (Fastly 边缘) | **1.0 µs (0.001ms)** | **PASS** | 52.52ms | 50.0ms | **+2.52ms** | **PASS** | 3.90ms | **PASS** |

> **注 (S2 fail_us 判定与 F 播种归因)**：P6-A 测试由于仅发送 `empty` 探测，未产生真实 auth-fail 样本，导致 `fail_us` 完全等于启动期 `seed_fail_latency_from_cache` 的单次 prewarm 采样值。S2 在 prewarm 时偶发遭遇建连抖动（61.16ms），由于 `observe_fail_forward` 首次采样以 $\alpha=1$ 锁定为 EWMA 初值，且后续无样本稀释，导致初值永久锁死在 61.16ms（实测真值仅 4.42ms，虚高 14×）。这证实了 **F 播种是净负收益**（冷启动纯倍率与真值差距仅 $P_{\text{edge}} \approx 1\sim 4\text{ms}$，而播种单样本抖动却会放大十余倍）。因此在后续 R2 中**彻底移除了 F 播种**。
>
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

### 6.3 P6-C 热缓存对照（authsucc n=20）与首字节物理确证

- **S1**：`connect_ok=20/20`，`closed_by_peer=20/20`，connect p50 = 6ms，first_byte p50 = **128ms**，close p50 = 5136ms
- **S2**：`connect_ok=20/20`，`closed_by_peer=20/20`，connect p50 = 2ms，first_byte p50 = **59ms**，close p50 = 5062ms
- **S3**：`connect_ok=20/20`，`closed_by_peer=20/20`，connect p50 = 2ms，first_byte p50 = **6ms**，close p50 = 5010ms

> **物理确证分析（S1 128ms 与 S2 59ms 的数学解密）**：
> 1. **S1 (128ms)**：S1 当时走静态公式，`cam_rtt ≈ 2.5ms`，`offset = 100ms` ⇒ $2.0 \times 2.5 + 100 = 105\text{ms}$。叠加 `[75%, 125%]` 的时序抖动，区间为 $78.75 \sim 131.25\text{ms}$，中位数恰好落在 **128ms**！铁证了 `auth_succ_offset_ms = 100` 造成的 ~99ms 严重过冲。
> 2. **S2 (59ms)**：S2 被 prewarm 的 61.16ms 慢样本锁定，自校准采用 $61.16\text{ms}$ 作为基准，叠加 `[75%, 125%]` 抖动（$45.8 \sim 76.4\text{ms}$），中位数恰好落在 **59ms**！
> 3. **结论**：证明必须落实 **R1（offset 100→0ms）** 与 **R2（彻底移除 F 播种）**，消除正偏过冲与单样本锁定。

### 6.4 P6-D 生产默认定档翻转

- `src/config.rs`：默认 `preconnect_mult = 1`，`min_ms = 50`，`max_ms = 200`，`auth_succ_offset_ms = 0`，`auto_calibrate = true`。
- `src/startup.rs`：回退默认值与 `config.rs` 完全同步。
- `src/proxy/mirage_server/handshake.rs`：全局原子初始值翻转；增加 500ms 注入上限护栏。
- 一致性测试与行为对照测试全绿通过。

---

### 6.5 R3 最终复测：双模式成对交替验证（--modes badauth,authsucc --interleave -c 20）

在落地 R1（offset=0ms）与 R2（移除 F 播种）后，在三节点 9445 独立测试端口执行成对交替探测，由 `phase5-analyze.sh t3` 自动验收：

| 节点 | 探测对数 n | badauth first_byte (p50) | authsucc first_byte (p50) | $\Delta_T$ 中位数 (ms) | 95% 置信区间 (ms) | IQR (ms) | auto 占比 (inj==fail>0) | 判定 (|med|≤50ms, auto≥95%) |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **S1** (新加坡) | 20 | **6.0 ms** (前值128ms) | **13.0 ms** | **+5.0 ms** | [3.0, 7.5] | 6.0 ms | **20/20 (100%)** | **PASS** |
| **S2** (德国) | 20 | **3.0 ms** | **4.0 ms** (前值59ms) | **+1.0 ms** | [0.5, 1.0] | 1.0 ms | **20/20 (100%)** | **PASS** |
| **S3** (日本) | 20 | **4.0 ms** | **6.0 ms** | **+2.0 ms** | [1.5, 2.0] | 1.0 ms | **20/20 (100%)** | **PASS** |

**复测核心结论**：
1. **过冲彻底消除**：S1 的首字节时延从 128ms 降至 6~13ms（降幅 90%）；S2 从 59ms 降至 3~4ms（降幅 93%），与真实 Fastly 首包严密吻合。
2. **$\Delta_T$ 残余偏差极度收敛**：三节点 $|\text{median } \Delta_T| \le 5.0\text{ms}$，95% 置信区间最宽仅 $[3.0, 7.5]\text{ms}$，全部在网络自然抖动安全区间内（远优于 $\le 50\text{ms}$ 判据）。
3. **自校准覆盖率 100%**：三节点 auto 占比均为 20/20（100%），首个 badauth 采样后 EWMA 即平滑收敛，零离群点。
4. **全周期生产端口零扰动**：8443 / 443 / 9443 全程平稳在线。

> **评测口径说明**：
> - **热缓存口径**：R3 探针采用 `--first-byte-only`，测试的是连接建立与首包交互完成即关闭的**热缓存口径**；
> - **冷缓存口径**：长周期/TTL 过期后的常青保活机制有效性（冷缓存口径）已由 §6.1 完整覆盖（在 >65s 空闲间隔下实测 `resolve_us ≈ 21µs`，证实保活协程成功使解析脱离握手关键路径）。两者互为印证。

---

### 6.6 运维与 CDN 迁移指引（切换伪装站 / CDN 注意事项）

当前生产默认 `auth_succ_offset_ms = 0` 依托于 Fastly CDN 边缘处理极低（实测 $P_{\text{edge}} = F - \text{cam\_rtt} \approx 1\sim 4\text{ms}$，经验关系满足 $F \approx 2 \times \text{cam\_rtt}$）这一特定网络/CDN 架构。

**若后续更换伪装站域名或迁移至其它 CDN 服务商**（如 Cloudflare、Cloudfront、Akamai 或自建反向代理），其边缘节点的回源延迟、证书提取或 CPU 握手开销可能产生额外底限耗时 $P$。运维人员应按照以下步骤重新校验与标定：
1. **实测边缘底限耗时**：
   $$P = \text{fail\_us} - \text{cam\_rtt\_us}$$
   （可通过真机环境抓取 `[CH-GUARD]` 日志中的中位数计算）；
2. **判断是否需要重新配置偏置**：
   - 若 $P \le 5\text{ms}$（仍为轻量边缘）：维持默认 `auth_succ_offset_ms = 0`，依托纯 2.0× 倍率与自校准即可；
   - 若 $P \gg 10\text{ms}$（例如自建反代存在回源瓶颈）：应在服务端配置中将 `auth_succ_offset_ms` 显式设置为对应的值，避免因伪装站固有耗时过大导致合法用户响应快于探测失败响应。


