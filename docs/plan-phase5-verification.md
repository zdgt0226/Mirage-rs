# Phase-5 复测规范（判据先定）

> **触发**：`docs/phase4-real-machine-verification-report.md` §8 勘误 **E8–E12**。
> **范围**：只复测 Phase-4 未自洽 / 未覆盖的 6 项；已确认项（②=1000ms、反向不对称免疫、合法性）只做最小回归（P5-5）。
> **判据已在开跑前固定**（§4）：**禁止"跑完再挑指标"**。某项事后发现判据写错 → 只能作废该项并如实记录，不得改判据。

---

## 1. 铁律（违反任一条 ⇒ 该轮结果作废）

| # | 规则 |
|---|---|
| **R1** | 只用测试端口 **9444 / 9445 / 9446 / 9447**。生产端口 **8443 / 443 / 9443 全程不动**；测前测后各存一份 `ss -ltnp` 存档对比。 |
| **R2** | **禁止** `pkill -9 mirage` / `pkill -f mirage`（会打死生产进程）。只 `kill $(cat /tmp/p5_<实例>.pid)`。 |
| **R3** | 所有探测必须加 `--interleave`。**禁止**默认并发路径（并发 ≠ 同轮成对，统计上不可用）。 |
| **R4** | **同轮同源**：baseline 与各档必须在**同一会话内交替探测**（同一 `--interleave` 命令的多个 `-t`）；禁止"每档单独跑一段"（这正是 Phase-4 的 E8）。 |
| **R5** | 口令只经 env `MIRAGE_PROBE_PASSWORD` 传入；**禁止** `--password`（会进 `ps`）。 |
| **R6** | 仓库/报告/截图不得出现真实 IP、口令、节点链接；回填只用 `S1/S2/S3`、`$CAM_IP`、`$PW` 等代号，示例用 RFC 5737 保留地址（如 `203.0.113.7`）。 |
| **R7** | 测试实例必须设 `MIRAGE_QUIET_MEASURE=1`（否则**没有** `[CH-GUARD]` 行，P5-1/P5-3/P5-4 全部无法判定）；`--cap ≥ 75`（真站空闲关闭 ≈61s，cap 过小会截断）。 |
| **R8** | 四个实例共用**同一份 config**，差异**只允许**来自 tier 环境变量；禁止改生产 config。 |
| **R9** | 每个测试实例**专供探针**（无其它流量），否则"按顺序配对"失效；配对前先 `grep -c` 校验行数 = n。 |
| **R10** | 探针与 baseline 都在**同一台节点本机**跑（`127.0.0.1` 与节点自身出站），避免把"客户端→节点"路径混进 Δ。 |

---

## 2. 前置门禁 P5-0（任一不过 ⇒ 停止，本轮结果无效）

```bash
cargo test --lib                                            # 期望: 525 passed / 0 failed / 3 ignored
cargo clippy --all-targets -- -D warnings                   # 期望: 0 warning
cargo clippy --all-targets --features quic -- -D warnings   # 期望: 0 warning
bash scripts/check-no-real-endpoints.sh                     # 期望: 0 命中
cargo build --release --example probe_close_timing          # 产出探针
git rev-parse --short HEAD                                  # 记录版本
```

版本须包含：`injection_base_us` 冷启动改纯倍率、`camouflage.rs` 边缘 IP 日志、`startup.rs` 降级 WARNING、example 的 clippy 修复。

---

## 3. 准备：四个测试实例（同 config，仅 tier env 不同）

| 实例 | 端口 | tier 环境变量 | 用途 |
|---|---|---|---|
| **A**（极限档） | 9444 | `MIRAGE_CH_PRECONNECT_MULT=1 MIN=50 MAX=150` | P5-3a/b |
| **B**（推荐档） | 9445 | `MIRAGE_CH_PRECONNECT_MULT=1 MIN=50 MAX=200` | P5-1 / P5-3a/b / P5-4 / P5-5 |
| **C**（默认档） | 9446 | `MIRAGE_CH_PRECONNECT_MULT=2 MIN=100 MAX=500` | P5-3a/b |
| **A′/B′/C′**（对照） | 9447 / 9448 / 9449 | `MIN=MAX=100` / `MIN=MAX=200` / `MIN=MAX=300`（mult 任意） | P5-3c（**① 被强制**，消除 RTT/clamp 不确定性） |

启动（每实例一份独立日志与 pid）：

```bash
MIRAGE_QUIET_MEASURE=1 MIRAGE_CH_AUTO_CALIBRATE=1 \
MIRAGE_CH_PRECONNECT_MULT=1 MIRAGE_CH_PRECONNECT_MIN_MS=50 MIRAGE_CH_PRECONNECT_MAX_MS=150 \
/tmp/mirage_new -c /tmp/p5_config.json > /tmp/p5_A.log 2>&1 &
echo $! > /tmp/p5_A.pid
```

**启动自检（必做）**：

```bash
grep "ClientHello 守卫" /tmp/p5_A.log                  # 生效参数
grep -c "未启用自校准" /tmp/p5_A.log                   # 必须为 0（非 0 ⇒ 忘了 MIRAGE_CH_AUTO_CALIBRATE=1）
grep "伪装站出站边缘" /tmp/p5_B.log | tail -1           # 记下 $CAM_IP（baseline 的目标，必须用 IP 不用域名）
```

> ⚠️ **为什么 baseline 要用 IP**：同源 baseline 若用域名解析，可能落到与转发连接**不同的 CDN 边缘** → Δ 混入"不同边缘的空闲超时差"（E12 的残差 `K` 的首要嫌疑）。用 `$CAM_IP` 把"同边缘"变成构造保证。

---

## 4. 判据总表（预注册）

| 项 | 判据 | PASS | WEAK | FAIL |
|---|---|---|---|---|
| **P5-1** 同连接常数 `K` | `K = [med(close−connect)_mirage − med(pc_ready)] − med(close−connect)_base` | ≤50ms | 50~150ms | >150ms |
| **P5-2** 边缘一致性 | 整轮 `伪装站出站边缘` 变更行数 | =0 | — | ≥1 |
| **P5-3a** ① 自洽 | 每档 `pc_fire_us ≈ clamp(mult×rtt_us, min, max)` 且 `≤ max+5ms` | 每档 ≥95% 样本 | 80~95% | <80% |
| **P5-3a** 硬门口径（E9） | `max_gap_us ≈ 750±100ms` 且 `ch_read_us ≥ 0.9×750ms` | 两项各 ≥95% | 80~95% | <80% |
| **P5-3a** 2b 率（E11） | `preconnect=2b` 占比（仅 `pc_ready_us < max_gap_us` 的样本计入） | ≥95%（Wilson 下界 ≥76%） | 80~95% | <80% |
| **P5-3b** 模型核对（E8，**核心**） | `(Δ_C−Δ_B) − (ready_C−ready_B)`；`Δ_X = p50(close_X) − p50(Z_base)` | ≤100ms | 100~200ms | >200ms |
| **P5-3b** 不劣性 | `Δ_B ≤ Δ_C + 50ms` 且 `\|Δ_B−Δ_A\| ≤ 100ms` | 成立 | — | 不成立 |
| **P5-3c** ① 敏感性（对照） | `(Δ_{C′}−Δ_{B′})` 应 ≈ `100ms`；`(Δ_{B′}−Δ_{A′})` 应 ≈ `100ms` | 各 ±100ms 内 | ±100~200ms | >200ms |
| **P5-4** 自校准 | auto 占比（`inj_us == fail_us > 0`）；`\|median Δ_T\|`（中位数 bootstrap 2000 次） | ≥95% 且 ≤50ms | 占比 90~95% | <90% 或 >50ms |
| **P5-5** 弱网回归 | `authsucc` + gap 550/750 的 `authed=1` 数 | 20/20 | — | <20/20 |

**统计口径**：`Δ` 用 p50（中位数）；率用 Wilson 95% 区间；成对差值用**中位数 bootstrap（2000 次）**而非正态近似的均值 CI（Phase-4 的 S1 出现 `[18.0, 638.5]` 这类虚胖区间，须以原始逐样本列表重算）。
**样本量**：**率类/配对类（P5-3a 的 2b 率、P5-4、P5-5）必须 n ≥ 20**；**空连接类（P5-1/P5-3b/P5-3c）允许 n = 10**（实测 close_ms 的 σ ≈ 15ms ⇒ 中位数 CI ≈ ±10ms，远小于 ±50~100ms 判据；时间充裕请用 n = 20，判据不变）。

---

## 5. 测试项

> **一键判决（只读分析器）**：`scripts/phase5-analyze.sh` 已把下表的算术与判据固化（中位数 / IQR / Wilson / 中位数 bootstrap 2000 次 / 固定随机种子可复现）。它**只读**日志，不碰测试环境；输出 PASS/WEAK/FAIL 与逐样本值，直接粘入 §6：
>
> ```bash
> bash scripts/phase5-analyze.sh k      <baseline探针> <mirage探针> <mirage日志>   # P5-1
> bash scripts/phase5-analyze.sh tiers  <探针(4 target)> <日志A> <日志B> <日志C>    # P5-3b
> bash scripts/phase5-analyze.sh gap750 <探针(authsucc,gap750)> <日志A> <日志B> <日志C>  # P5-3a
> bash scripts/phase5-analyze.sh t3     <探针(badauth,authsucc)> <日志>           # P5-4
> bash scripts/phase5-analyze.sh count  <日志> 'authed=1' 20                     # P5-5
> ```
>
> 入参口令**不含**：分析器只读文件；服务端日志必须含启动行 `ClientHello 守卫: ...`（用于反算 ① 的 mult/min/max）。

### P5-1 同连接模型核对 —— 判定 E12 的常数 `K` 是否存在（最高优先）

**目的**：把 `close ≈ B_srv + ① + cam_idle` 里的未识别常数 `K = cam_idle_fwd − cam_idle_base` 直接测出来。

```bash
# ① baseline：本机直连"转发实际落到的那个边缘 IP"
/tmp/probe_close_timing -t $CAM_IP:443        --modes empty --interleave -c 10 --cap 90 > /tmp/p5_SX_base.txt
# ② Mirage B 档（本机探自身）
/tmp/probe_close_timing -t 127.0.0.1:9445     --modes empty --interleave -c 10 --cap 90 > /tmp/p5_SX_mirage.txt
# ③ 服务端每条连接的①/就绪时刻（顺序配对）
grep "outcome=fallback" /tmp/p5_B.log | grep -o "pc_fire_us=[0-9]* pc_ready_us=[0-9]*" > /tmp/p5_SX_ready.txt
```

**计算**（工具输出的 `samples:` 行是**排序后**打印的，且 `close_ms` / `connect_ms` 各自独立排序 ⇒ **不做逐样本配对**，用中位数分项口径）：

```
med_base   = median(close_ms − connect_ms)      # baseline
med_mirage = median(close_ms − connect_ms)      # Mirage B 档
ready_ms   = median(pc_ready_us) / 1000         # 服务端日志（同轮、同实例）
K          = (med_mirage − ready_ms) − med_base
判据: |K| ≤ 50ms（PASS） / ≤150ms（WEAK） / >150ms（FAIL）
参考(非判据): IQR(close−connect) 两组对比 —— 排序配对会人为压低离散度, 仅作方向性参考
```

**记录**：n、两组的 `med(close−connect)` 与 `med(pc_ready)`、`K`、逐样本 `close−connect`、`$CAM_IP`、`rtt_us` 中位数。
**FAIL 时的下一步**：查 P5-2（边缘是否一致）→ 查"真站关闭后服务端是否仍持有 probe socket"（`ss -tnp` 在 60~70s 区间抽样）。

### P5-2 边缘 IP 一致性

```bash
grep -c "伪装站出站边缘" /tmp/p5_B.log        # 运行前后计数差必须为 0（=无变更）
getent ahosts <cam 域名> | head -3            # 记录节点自身解析结果（仅供参考）
```

**判据**：运行期间**无变更行**（其余 PASS 前提是 baseline 已用 `$CAM_IP` 构造同边缘）。
**额外记录**：节点默认解析是否包含 `$CAM_IP`；不含 ⇒ 服务端解析路径与节点默认解析器不同（本身即一个"不同边缘"风险点）。

### P5-3a `authsucc` + `--gap-ms 750`（E11 复测 + E9 口径核对）

```bash
/tmp/probe_close_timing -t 127.0.0.1:9444 -t 127.0.0.1:9445 -t 127.0.0.1:9446 \
  --modes authsucc --interleave -c 20 --gap-ms 750 --split-at 40 > /tmp/p5_SX_gap750.txt
```

**判据**（每档独立判定）：
1. `pc_fire_us ≈ clamp(mult × rtt_us, min, max)`，误差 ≤ ±10ms 且 ≤ `max + 5ms`（≥95% 样本）。
   ⚠️ `preconnect_delay` 对 **`rtt_us == 0` 取上限 `max`**（仅 `Some(非0)` 才 clamp）—— 所以**必须用日志里的 `rtt_us` 反算期望值**，不要假设 ① 落在 floor。
   ⚠️ `preconnect=2a`（建连前 abort）样本的 `pc_ready_us = 0`，其 `pc_fire_us` 可能不是"定时器唤醒时刻"⇒ 该样本只用于①校验，`ready` 类校验跳过。
2. **E9 口径核对**：`max_gap_us ≈ 750ms ± 100ms`；**`ch_read_us ≥ 0.9 × 750ms`**。两者各 ≥95% 样本满足。
   （Phase-4 §3.2 表里 gap=750ms 的 `ch_read_us` = 350~457ms 与 `total_us` 的定义矛盾，故该列存疑；此处以**原始日志字段**为准。）
3. **2b 率**：`preconnect=2b` 占比 ≥95%，**只把 `pc_ready_us < max_gap_us` 的样本计入分母**；出现 `ready > gap` 的样本说明该档 ① 过大，须单列。
4. 记录每档 `preconnect` 分布（`0/1/2a/2b`）与 `rtt_us` 中位数。

### P5-3b 三档同会话交替 `empty`（**E8 核心判据**）

```bash
/tmp/probe_close_timing -t $CAM_IP:443 -t 127.0.0.1:9444 -t 127.0.0.1:9445 -t 127.0.0.1:9446 \
  --modes empty --interleave -c 10 --cap 90 > /tmp/p5_SX_tiers.txt
```

第 1 个 target 被工具当作基线，自动打印各档 Δ（p50）。再取每档日志的 `pc_ready_us` 中位数：

```
模型核对: |(Δ_C − Δ_B) − (ready_C − ready_B)| ≤ 100ms        # 核心
不劣性  : Δ_B ≤ Δ_C + 50ms  且  |Δ_B − Δ_A| ≤ 100ms
```

**含义**：Δ 的档位差**必须**与预连就绪时刻的档位差一致；Phase-4 的 `(Δ_C−Δ_B) = 344ms` vs `(ready_C−ready_B) ≈ 50ms` ⇒ 若复现即为 **FAIL**（说明档位间还有与 ① 无关的项）。

> **为什么用 `ready` 而不是配置值**：`preconnect_delay` 的取值由**实际 `rtt_us`** 决定，而内核 `tcpi_rtt == 0` / 非 Linux 时会回落成 **`max`（上限）**而非 floor。用配置值反推会搭错。进一步：Phase-4 的 Δ 无论如何都不能用"单一 RTT"解释 ——
> `Δ_C−Δ_B = 363ms` 要求 `①_C−①_B ≈ 300ms`（需 `R ≥ 250ms`），而 `Δ_B−Δ_A = 8ms` 要求 `①_B−①_A ≈ 0`（需 `R ≤ 50ms`），**二者不可能同时成立** ⇒ 三档必然跑在不同条件下（或 Δ 列混了不同样本）。这正是必须**同会话交替 + 逐行记 `rtt_us`** 的理由。
**同时记录**：三档 `rtt_us` / `pc_fire_us` / `pc_ready_us` 的中位数与 IQR（用于解释本机 `rtt_us` 是否触发了 `max` 分支）。

### P5-3c 对照：① 被强制相等档差（确定性模型证明）

```bash
/tmp/probe_close_timing -t $CAM_IP:443 -t 127.0.0.1:9447 -t 127.0.0.1:9448 -t 127.0.0.1:9449 \
  --modes empty --interleave -c 10 --cap 90 > /tmp/p5_SX_ctrl.txt
```

三个实例 `MIN = MAX = 100 / 200 / 300` ⇒ ① **确定等于** 100 / 200 / 300ms（与 RTT 无关）。
**判据**：`(Δ_{300} − Δ_{200}) ≈ 100ms` 且 `(Δ_{200} − Δ_{100}) ≈ 100ms`（各 ±100ms 内）。
**意义**：这是**唯一不依赖 RTT/clamp 行为的模型证明**；若通过而 P5-3b 不通过，则差异来自"档位配置在真实 RTT 下的行为"而非测量假象。

### P5-4 T3′ 自校准复算（E12 的 S1 区间）

```bash
# 预热 ≥10 轮使 F 收敛（冷启动为纯倍率，见 CHANGELOG 2026-10-11）
/tmp/probe_close_timing -t 127.0.0.1:9445 --modes badauth,authsucc --interleave -c 20 > /tmp/p5_SX_t3.txt
grep -E "outcome=(Fallback|AuthFail|AuthSucc)" /tmp/p5_B.log | grep -o "fail_us=[0-9]* inj_us=[0-9]*" > /tmp/p5_SX_fus.txt
```

**判据**：
1. **auto 占比 ≥95%**：`inj_us == fail_us > 0` 的条数 / 总条数。
2. `median Δ_T`（`authsucc − badauth` 首字节，工具已打印逐样本列表）满足 `|median| ≤ 50ms`。
3. **CI 用中位数 bootstrap（2000 次重采样）**，并**列出离群样本**（> median + 5×IQR 的原始值）；不得再出现 Phase-4 那种"中位数系 CI 却宽 620ms"的不一致（除非离群样本可解释）。

### P5-5 弱网回归（最小回归，Phase-4 T4′ 不重跑全量）

```bash
for g in 550 750; do
  /tmp/probe_close_timing -t 127.0.0.1:9445 --modes authsucc --interleave -c 20 --gap-ms $g --split-at 40 \
    > /tmp/p5_SX_gap$g.txt
done
```

**判据**：日志中 `authed=1` 计数 = 20/20（无 `Fallback`/`Close` 误杀）。

### P5-6 收尾

```bash
kill $(cat /tmp/p5_*.pid)                     # 禁止 pkill
ss -ltnp | grep -E ":(9444|9445|9446|9447|9448|9449)"   # 应为空
ss -ltnp | grep -E ":(8443|443|9443)"                   # 生产仍在（与测前存档一致）
rm -f /tmp/p5_* /tmp/mirage_new
bash scripts/check-no-real-endpoints.sh
```

---

## 6. 结果回填模板与实测记录（2026-10-12 / Commit `a0f39a1` / S1、S2、S3）

完整真机报告详见 [`docs/phase5-real-machine-verification-report.md`](phase5-real-machine-verification-report.md)。

| 项 | 判据 | 实测 (S1 / S2 / S3) | 判定 |
|---|---|---|:---:|
| **P5-0 门禁** | 525/0/0 · clippy 0 · gate 0 | 525 pass / 0 fail / clippy 0 warn / gate 0 hit | **PASS** |
| **P5-1 K** | $\|K\| \le 50\text{ms}$（同连接中位数口径） | S1: -36.1ms / S2: +2.9ms / S3: +20.8ms | **PASS** |
| **P5-2 边缘** | 变更行数 = 0 | S1: 0 行 / S2: 0 行 / S3: 0 行（全程单 IP 锁定） | **PASS** |
| **P5-3a ① 自洽** | $\ge 95\%$ | 三节点各档 fire_us 落于 floor 下限，全量 60/60 (100.0%) | **PASS** |
| **P5-3a E9** | max_gap≈750±100 且 ch_read≥675, 各≥95% | 全节点 ch_read_us≈751ms, max_gap≈751ms (60/60, 100.0%) | **PASS** |
| **P5-3a 2b** | $\ge 95\%$ (Wilson $\ge 76\%$) | A/B/C 三档均为 20/20 (100.0%, Wilson下界 83.9%) | **PASS** |
| **P5-3b 模型** | $\|(\Delta_C-\Delta_B)-(ready_C-ready_B)\| \le 100\text{ms}$ | S1: -18.3ms / S2: -7.6ms / S3: -9.5ms | **PASS** |
| **P5-3b 不劣** | $\Delta_B \le \Delta_C+50$ 且 $\|\Delta_B-\Delta_A\| \le 100$ | S1: PASS / S2: PASS / S3: PASS | **PASS** |
| **P5-3c 对照** | 各 $\approx 100\text{ms} \pm 100\text{ms}$ | S1: 67.0 / 131.0ms; S2: 90.5 / 115.5ms; S3: 86.0 / 105.5ms | **PASS** |
| **P5-4 自校准** | auto $\ge 95\%$ 且 $\|\text{median} \Delta_T\| \le 50\text{ms}$ | auto 100%(60/60) · S1: -15.5ms CI=[-29.5,-3.0] / S2: +1.0ms / S3: +1.0ms (离群=0) | **PASS** |
| **P5-5 回归** | 20/20 (550/750ms) | gap 550ms: 20/20 PASS; gap 750ms: 20/20 PASS (误杀率 0.0%) | **PASS** |
| **P5-6 清理** | 端口释放且生产端口活跃 | 9444~9449 全解绑，8443 / 443 / 9443 持续正常运行 | **PASS** |

---

## 7. 时长预算与并行

| 项 | 单项耗时（每节点） |
|---|---|
| P5-1 | 2 × (10 × ~61s) ≈ 20 min |
| P5-3b / P5-3c | 各 ≈ 40 min（4 target × 10 轮 × ~61s） |
| P5-3a / P5-4 / P5-5 | 各 ≈ 2~4 min（认证路径不等待 61s 关闭） |
| **合计** | **≈ 1.7 h / 节点**（n=10；改 n=20 约 3.5 h） |

三个节点**相互独立、可并行**（每节点只探自己的 `127.0.0.1`）⇒ 墙钟 ≈ 2 h。开跑前先确认 R1 的 `ss` 存档。

---

## 8. 陷阱清单

1. **忘 `MIRAGE_QUIET_MEASURE=1`** → 没有 `[CH-GUARD]` 行，P5-1/P5-3/P5-4 无法判定（§3 自检）。
2. **`--cap < 75`** → 在真站关闭（≈61s）前被截断，Δ 全错。
3. **baseline 用域名而非 `$CAM_IP`** → 可能不同边缘，`K` 白测（§3）。
4. **不加 `--interleave`** → 工具走并发路径，样本非成对（R3）。
5. **把三档分批跑**（各跑一段） → 直接复现 E8，结果作废（R4）。
6. **`rtt_us == 0` 误判**：内核 `tcpi_rtt` 为 0 或**非 Linux** 时，`tcp_info_rtt` 返回 `None` ⇒ `preconnect_delay` 回落成 **`max`（上限）**，**不是** floor（实测判据一律用日志 `rtt_us` 反算，§P5-3a）。Phase-4 的 T2′ `fire` 值（C=101/B=51）说明**当时** `rtt_us` 非 0（命中了 floor）。
7. **`2a` 样本的 `pc_fire_us`** 可能不是唤醒时刻，勿用于"① 是否等于期望"以外的推断。
8. **`/tmp` 会被系统清理** → 每步产物立即落盘到本机 `/tmp` 并**及时拷回**，不要留到最后。
9. **长复合命令丢输出**（本机已知问题） → 分步执行、每步 `> 文件` 落盘。
10. **`--password` 会进 `ps`** → 只用 `MIRAGE_PROBE_PASSWORD`（R5）。
11. **误 `pkill mirage`** → 打死生产（R2）。
12. **顺序配对失效**：测试实例若被其它流量（含健康检查、监控探针）命中，`grep -c` 行数会 ≠ n ⇒ 该轮作废（R9）。
