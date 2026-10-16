# Phase-3 实机验证计划（① 收紧 / 反向不对称 / 自校准验收）

> **状态**: ✅ **全部实机验证通过已完成 (2026-10-09)**  
> **实测完整报告**: 详见 [`docs/phase3-real-machine-verification-report.md`](phase3-real-machine-verification-report.md)  
> **测试拓扑**: S1 (新加坡)、S2 (德国)、S3 (日本东京) 三节点异构网络  
> **执行方**：实机操作者。**本文件为历史指挥方案与基线**：给命令、给判据、给记录表；不含真实地址与口令。
> 地址/口令一律用占位符或环境变量：`$S1` `$S2` `$S3` `$CAM_REAL`（真站域名）`$CAM_IP`（伪装站解析 IP）`$PW`（测试口令）。
> 参数化的理由：`scripts/check-no-real-endpoints.sh` 是硬门禁，且 argv 会暴露口令。
>
> 上游数据见 `docs/real-machine-verification.md`（A1/A2/A3）与操作者报告；本计划的**判据全部预注册**，
> 禁止"跑完再挑指标"。所有"通过/不通过"必须用同轮、同口径、成对采样得出。

---

## 0. 背景：为什么还要做这三件事

Phase-2 的严格同口径成对数据（`Δ = T_succ − T_fail = offset − P`）给出：

| 节点 | Δmean | 95% CI | 配对 σ | 反推 P |
|---|---|---|---|---|
| S2 | −9.5ms | [−31.2, +12.2] ∋ 0 | 49.4ms | **109.5ms** |
| S1 | −106.2ms | [−115.0, −97.5] ∌ 0 | 20.0ms | **206.2ms** |

⇒ 让两台都达标的 offset 可行区间 **S1 [186,226] 与 S2 [61,159] 不相交** → **静态公式结构上不可能同时满足**；
且 `P` 属"服务器→其 CDN 边缘"的路径属性（会随 anycast 选边漂移）。因此**必须由服务端自校准 F**。
本计划验证：① 的收紧收益/代价、自校准是否真的把两台都压进 CI 覆盖 0、以及一处**尚未修的反向不对称**。

---

## 1. P0 前置（**不满足则不要开跑**）

| # | 前置项 | 为什么必须 |
|---|---|---|
| P0.1 | `[CH-GUARD]` 度量行**新增** `fail_us=`（自校准 EWMA 的 F）与 `inj_us=`（本次注入基准，未含 jitter） | 否则 T3 只能在客户端侧看 Δ，**无法验证自校准本身** |
| P0.2 | `auto_calibrate` 由 env-only 改为 config（`tuning.client_hello_guard.auto_calibrate`，默认 `false`）+ 启动日志；env 仍可覆盖；`check` 不报非法值 | 与其它 5 个参数"config 一次设定 + env 覆盖"保持一致；也消除每握手 `env::var` 的热路径开销 |
| P0.3 | 被测代码**先 commit**，把 hash 写进结果表 | 上次报告只能写"工作区未提交版本"，不可复现 |
| P0.4 | （可选但建议）探针支持从**环境变量**读口令（`--password` 会进 `ps`） | 口令卫生 |
| P0.5 | 每组参数启动服务端时，**把启动日志里的 `ClientHello 守卫:` 整行存档** | 防"以为设了其实没设"的配置漂移 |

**共享环境要求**：全部在测试端口 `9443`；生产服务（`8443` / `443`）全程不动；
服务端全程带 `MIRAGE_CH_MEASURE=1`（否则 T1 的 2a/2b 统计与 T4 的误杀判据都看不到）。

**参考基线（用来识别配置漂移，不是判据）**：S1 `badauth` P50≈455ms / `authsucc`≈350ms；S2 272 / 250；
`cam_rtt` ≈ 125ms(S1) / 75ms(S2)；`P` ≈ 206ms(S1) / 110ms(S2)。若新一轮偏离一倍以上，先查配置而非下结论。

---

## 1.1 P0.1 详细改法：度量行加 `fail_us=` 与 `inj_us=`

> **行号基准**：下文所有 `:NNN` 均以 **commit `c1d8a07`** 为准。若期间代码已变动，请按函数名/字符串重新定位（行号会漂）。

**目的**：把"自校准是否生效"变成**服务端可证**（T3 判据 3 与 T3.3 冷启动子项都依赖它）。
当前 `[CH-GUARD]` 有 `rtt_us`（cam 建连 EWMA）但**没有** F 的 EWMA（`fail_us`），也无法区分某条连接注入的是 auto 值还是静态兜底。

**涉及的既有代码（以 `c1d8a07` 为准）**：
- `src/proxy/mirage_server/handshake.rs:419` `fn log_ch_guard(outcome, authed, bytes, timing, judge, client_rtt, preconnect)` —— 现签名 7 参。
- 4 个调用点：`:750`（读异常回落）、`:764`（Close）、`:820`（完整 CH 认证失败）、`:838`（认证成功）。
- 注入块在**认证成功日志之后**（约 `:895~:912`），所以 `inj_us` 目前不可能出现在 `:838` 那条日志里 —— **必须把"算注入基准"上移**。

### 改动步骤

**① 新增纯函数（放在 `auth_succ_delay_us` 之后，`:348` 附近）**：

```rust
/// 选 auth-succ 注入基准: auto 且已有 F 样本→用 F(EWMA); 否则回落静态公式;
/// cam 不可达(cam_rtt_us==0)→0(不注入, 避免反向不对称)。抽纯函数以便单测。
pub(crate) fn injection_base_us(
    auto_calibrate: bool, fail_us: u64, mult_x10: u32, offset_us: u64, cam_rtt_us: u64,
) -> u64 {
    if auto_calibrate && fail_us > 0 { return fail_us; }
    auth_succ_delay_us(mult_x10, offset_us, cam_rtt_us)
}
```

**② `log_ch_guard` 加两个入参**：`cam: &CamouflageRtt`（函数内取 `fail_us`）与 `inj_us: u64`：

```rust
fn log_ch_guard(outcome: &str, authed: Option<bool>, bytes: &[u8], timing: &ReadTiming,
                judge: Duration, client_rtt: Option<Duration>, preconnect: &'static str,
                cam: &CamouflageRtt, inj_us: u64) {
```

日志格式串**末尾追加两个字段**（便于 grep/awk）：

```text
[CH-GUARD] outcome=… ch_read_us=… bytes=… max_gap_us=… pre_tls=… authed=… \
           judge_us=… preconnect=… rtt_us=… fail_us=<cam.fail_latency_us()> inj_us=<inj_us>
```

**③ 4 个调用点补齐**：
- `:750` / `:764`（未到注入阶段）→ `inj_us = 0`；
- `:820`（完整 CH 认证失败）→ `inj_us = 0`（该路径不注入），`cam = cam_rtt`；
- `:838`（认证成功）→ **先把注入基准算出来**再传：

```rust
// 从 :895 上移到 drop(pre) 之后、log_ch_guard 之前
let mult_x10 = AUTH_MULT_X10.load(Ordering::Relaxed);
let offset_us = AUTH_OFFSET_US.load(Ordering::Relaxed);
let inj_us = injection_base_us(AUTO_CALIBRATE.load(Ordering::Relaxed),
                              cam_rtt.fail_latency_us(), mult_x10, offset_us, cam_rtt.rtt_us());
log_ch_guard("complete", Some(true), &client_hello, &timing, judge, client_rtt,
             preconnect_status(was_armed, false, was_connected), cam_rtt, inj_us);
// 原处的 sleep 保留（用它算 jitter），并把原处的 base 计算删掉，避免两份逻辑
if inj_us > 0 {
    let jitter_num = 75 + fastrand::u64(0..=50);
    tokio::time::sleep(Duration::from_micros(inj_us.saturating_mul(jitter_num) / 100)).await;
}
```

**④ 单测（`handshake.rs` 的 `mod tests`）**：

```rust
#[test]
fn injection_base_selection() {
    // auto 有样本 → 用 F
    assert_eq!(injection_base_us(true, 460_000, 20, 100_000, 180_000), 460_000);
    // auto 开但无样本 → 静态兜底
    assert_eq!(injection_base_us(true, 0, 20, 100_000, 180_000), 460_000);
    // auto 关 → 静态
    assert_eq!(injection_base_us(false, 460_000, 20, 100_000, 180_000), 460_000);
    // cam 不可达 → 0
    assert_eq!(injection_base_us(true, 460_000, 20, 100_000, 0), 0);
}
```

**验收**：`cargo test --lib proxy::mirage_server::handshake` 全绿；跑一次 `authsucc` 后
`[CH-GUARD]` 能同时看到 `rtt_us= fail_us= inj_us=` 三个值，且 `auto` 关时 `inj_us == 2×rtt_us+100000`（±1 个抖动无关的基准）。

---

## 1.2 P0.2 详细改法：`auto_calibrate` 由 env-only 提升为 config

> **行号基准**：同 §1.1（commit `c1d8a07`）。

**为什么**：当前它在注入处**每握手**执行 `std::env::var("MIRAGE_CH_AUTO_CALIBRATE")`（加锁+分配，热路径），
且与其它 5 个参数的"config 一次设定 + env 覆盖 + 启动日志 + `check` 可见"约定不一致。

### 改动步骤（5 个文件，按依赖顺序）

**① `src/config.rs`** —— `ClientHelloGuardConfig`（约 `:1290`）新增字段：

```rust
    /// 自校准: 用实测的 auth-fail 全程耗时 F 的 EWMA 作为 auth-succ 注入基准（取代静态
    /// `mult×cam_RTT + offset`）。**默认 false**：需先在目标节点积累 F 样本（≥20 次成功转发）再开，
    /// 否则会走静态兜底（行为与不开等价）。见 docs/client-hello-timing-design.md §4.5。
    #[serde(default)]
    pub auto_calibrate: bool,
```

- 结构体文档注释的 env 列表追加 `MIRAGE_CH_AUTO_CALIBRATE`。
- `semantic_issues()` 里加**一条提示（非错误）**：`auto_calibrate == true` 时提示
  "static offset 仅作冷启动兜底；请确认已积累 F 样本"。
- 测试 `client_hello_guard_params_validated`（约 `:2429`）：断言**默认 false**、显式 `"auto_calibrate": true` 能解析到位（防字段漂移）。

**② `src/proxy/mirage_server/handshake.rs`**：

- 静态量（与 `AUTH_MULT_X10` 同处，约 `:277`）：
  ```rust
  static AUTO_CALIBRATE: AtomicBool = AtomicBool::new(false);
  ```
- env 解析辅助（与 `env_u32` 同处）：`fn env_bool(name: &str) -> Option<bool>`（认 `1/true/on` 与 `0/false/off`）。
- `set_client_hello_guard(...)`（约 `:283`）**加第 8 个参数** `auto_calibrate: bool`，并
  `AUTO_CALIBRATE.store(env_bool("MIRAGE_CH_AUTO_CALIBRATE").unwrap_or(auto_calibrate), Relaxed);`
- `client_hello_guard_params()`（约 `:356`）元组 **7 → 8**（追加 auto）。
- 注入处删掉内联 `std::env::var(...)`，改用 `AUTO_CALIBRATE.load(Relaxed)`（见 §1.1 步骤③）。

**③ `src/proxy/mirage_server/mod.rs`**：`pub use handshake::{client_hello_guard_params, set_client_hello_guard};` 不变（签名变化会自动跟随）。

**④ `src/startup.rs`**（约 `:152~:170`）：

```rust
let auto = q.map(|q| q.auto_calibrate).unwrap_or(false);
set_client_hello_guard(mult, pc_min, pc_max, judge, hard, auth_mult, auth_off, auto);
let (m, lo, hi, j, h, am, ao, ac) = client_hello_guard_params();
info!("ClientHello 守卫: … auth-succ 注入 {}.{}×cam_RTT+{}ms · 自校准={} (MIRAGE_CH_* 可覆盖)",
      am/10, am%10, ao, if ac { "on" } else { "off" });
```

- 并在日志里补一句：**"guard 参数为启动一次设定，改后需重启"**（热改不生效，属已知约定）。

**⑤ 文档**：`docs/client-hello-timing-design.md` §4.5 与 §8 的配置样例补上 `auto_calibrate`，
并说明"auto 开启时 offset 仅作冷启动兜底"；`CHANGELOG.md` 记一条。

**验收**：`cargo test --lib config::` 与 `cargo test --lib proxy::mirage_server` 全绿；
`cargo clippy --all-targets -- -D warnings` 0 warning；用 `check` 验一份带 `auto_calibrate: true` 的配置能通过；
启动日志出现 `自校准=on`。

---

## 1.3 P0.3–P0.5 细化 + 未落地时的降级方案

### P0.3 commit 与 provenance

```bash
git add -A && git commit -m "feat(anti-probing): phase-3 前置（fail_us/inj_us 度量、auto_calibrate 入 config）"
git rev-parse --short HEAD          # ← 记进结果表 A 的 commit 列
```
- 建议同时打 tag（如 `phase3-test`）便于两台机器比对本二进制；构建命令与 `md5sum` 一并记入结果文件。
- 测试**只能**用这个 commit 构建的二进制；中途改代码必须重新 commit + 重跑已做过的组。

### P0.4 口令卫生（可选但建议）

- 现状：`examples/probe_close_timing.rs` 用 `--password <pwd>`（会进 `ps` 被同机用户看到）。
- 改法：参数解析处优先读 `std::env::var("MIRAGE_PROBE_PASSWORD")`，`--password` 仅作显式覆盖；`USAGE` 里加一行"建议用 `MIRAGE_PROBE_PASSWORD` 传入"。
- 若不改：测试机上确认无其它登录用户，且测试结束即清历史（`history -c` / 用 `HISTCONTROL=ignorespace` + 前置空格）。

### P0.5 配置漂移防护

```bash
grep 'ClientHello 守卫' $SRV_LOG | tail -1 >> $RESULT_DIR/run_meta.txt
md5sum $(which mirage_new) >> $RESULT_DIR/run_meta.txt   # 或 target/.../release/mirage
env | grep '^MIRAGE_CH_' | sort >> $RESULT_DIR/run_meta.txt
```
- **每组参数**（T1 的 A/B/C、T3 的 auto 开/关）都必须存一份 `run_meta.txt`。

### 降级方案（若 P0.1/P0.2 本轮来不及落地）

| 受影响项 | 降级后能做到 | 做不到（必须在报告里标注"未验证"） |
|---|---|---|
| T3 判据 1–2（客户端侧 Δ 与 CI） | ✅ 仍可判（`badauth` vs `authsucc` 同口径成对） | — |
| T3 判据 3（`fail_us` 与服务端可见量交叉核对） | — | ❌ 无 `fail_us` 字段 |
| T3.3 冷启动子项（区分 auto/静态兜底） | 只能看客户端侧 Δ | ❌ 无法确认"该条连接注入的是哪一路" |
| T1 的 2b 率 | ✅ 不受影响（`preconnect=` 已有 2a/2b） | — |
| P0.2 的好处（热路径 `env::var`、`check` 可见、启动日志） | — | ❌ 缺失（但**不影响**测试结论，只影响工程性） |

> 建议：**P0.1 必做**（否则 T3 只能证一半）；P0.2 可稍后（它不改行为，只在 auto 模式下影响读取方式），
> 但若本轮要用 `MIRAGE_CH_AUTO_CALIBRATE=1`，建议一并做完，以免每握手的 `env::var` 给 T3 引入额外噪声。

---

## 2. T1 — ① 预连触发收紧：收益与代价（优先级 1）

**问题**：把 ① 由 `2×RTT` 收到 `1×RTT` 能否把 `empty` 偏差从 ~650ms 降到 ~350ms？代价（弱网下每次延迟握手多 1 条上游连接）有多大？
**为什么现在做**：Phase-2 §3 只在**干净链路**（`ch_read_us` ≤ 1966µs）测到 20/20 全 `2a`，并**没有**给出收紧后的 `empty Δ`；而同一份报告的 gap 扫描在 `gap=450ms` 时已出现 `2b` —— 说明延迟一出现，预连就会真连。

### 2.1 组别（逐组：改 env → 重启 → 存档启动日志 → 测 → 记录）

| 组 | `MIRAGE_CH_PRECONNECT_MULT` | `_MIN_MS` | `_MAX_MS` |
|---|---|---|---|
| A（默认） | 2 | 100 | 500 |
| B（收紧） | 1 | 50 | 300 |
| C（极紧，可选） | 1 | 30 | 150 |

### 2.2 采集

```bash
# 2.2.1 empty 关闭偏差（同轮、真站作第 1 个 target；约 60~70s/组）
probe_close_timing -t $CAM_REAL:443 -t $S1:9443 -t $S2:9443 \
  --modes empty --count 5 --cap 90 --sni $CAM_REAL

# 2.2.2 干净链路 2b 率（预期≈0）
probe_close_timing -t $S1:9443 -t $S2:9443 --modes authsucc \
  --count 20 --first-byte-only --password "$PW" --sni $CAM_REAL

# 2.2.3 延迟注入下的 2b 率（关键新增：直接量"延迟 → 真连"的转化）
for g in 100 200 300; do
  probe_close_timing -t $S1:9443 -t $S2:9443 --modes authsucc \
    --count 20 --gap-ms $g --split-at 40 --first-byte-only --password "$PW" --sni $CAM_REAL
  # 统计服务端 [CH-GUARD] 的 preconnect 分布 (0/1/2a/2b)
done
```

统计方法（每组）：

```bash
grep -o 'preconnect=[^ ]*' $SRV_LOG | sort | uniq -c          # 2a/2b/0/1 分布
grep -o 'ch_read_us=[0-9]*' $SRV_LOG | ...                    # P50/P95
grep 'outcome=fallback' $SRV_LOG | grep -c 'bytes=0'          # 该组是否有误杀迹象
```

### 2.3 判据（预注册）

**采纳 B（或 C）当且仅当三条同时成立**：

1. `empty` 的 **Δp50 相对 A 组下降 ≥ 150ms 且仍为正**（为正=不早于真站）；
2. `--gap-ms 200` 下的 **2b 率 ≤ 20%**（即"延迟一档的握手"里多数不产生真连）；若 > 20% → 保持 A，或取折中 `MULT=1 MIN=100 MAX=300`；
3. `--gap-ms {100,200,300}` 三档 **误杀数 = 0**（`outcome=fallback && bytes>0 && pre_tls=1`）。

> 说明：2b 本身不是错误（认证成功即关），但它会以"每次延迟握手 1 条上游连接"的形式抬高对本地上游的连接频率。
> 判据 2 的意义是把它与旧预热池的 `~0.38 conn/s` 历史包袱做量化对比，而不是凭感觉。

---

## 3. T2 — "伪装站不可达"的反向不对称（优先级 2，属**未修缺口**的判定）

**问题**：`cam_rtt` 一旦置位永不复位、`fail_latency_us` 只由**成功**转发更新。于是"曾连通 → 现不可达"时：
auth-fail 走合成模板回落（真实 F ≈ 0），而 auth-succ 仍注入旧值 → **auth-succ 反而更慢**（反向侧信道）。
现有 `cam_rtt == 0 → 不注入` 只覆盖"从未连通"，不覆盖"曾连通后不可达"。

### 3.1 步骤（在 $S1 测试实例上，单机可控，互不影响生产）

```bash
# 1) 正常启动测试实例（cam 可达），等 prewarm 完成
# 2) 让 cam_rtt / fail_us 有值：跑 5 次 badauth
probe_close_timing -t $S1:9443 --modes badauth --count 5 --first-byte-only --sni $CAM_REAL
#    从 [CH-GUARD] 记下 rtt_us= / fail_us=

# 3) 【不重启服务端】让到伪装站的连接快速失败（模拟 CDN 拒绝）
trap 'iptables -D OUTPUT -p tcp -d $CAM_IP --dport 443 -j REJECT 2>/dev/null;
      iptables -D OUTPUT -p tcp -d $CAM_IP --dport 443 -j DROP   2>/dev/null' EXIT
iptables -I OUTPUT -p tcp -d $CAM_IP --dport 443 -j REJECT --reject-with tcp-reset

# 4) 立刻做同口径成对 A2
probe_close_timing -t $S1:9443 --modes badauth,authsucc --interleave \
  --count 20 --first-byte-only --password "$PW" --sni $CAM_REAL

# 5) case 2b：换成 -j DROP 重复 3)~4)
```

### 3.2 判据（预注册）

| case | 预期（行为正确） | 判定 |
|---|---|---|
| **REJECT**（快失败） | auth-fail ≈（合成模板写入），auth-succ ≈ 注入值 → **Δmean ≈ 0** | Δmean > **+50ms** 且 CI 不含 0 → **缺口成立**，需要修 |
| **DROP**（黑洞，forward 阻塞到 5s 预算） | 记录 auth-fail **绝对首字节时延**（预期 ≈ 5s + 模板） | 仅记录，用于评估"黑洞下认证失败路径停 5 秒"这一**既有**可观测量是否需要收敛 |

**若 REJECT 判定缺口成立**，采用以下修法之一（由实现方决定，T3 前必须落地，否则 T3 结论会被它污染）：
- **(a) 在合成模板回落路径也采样 F**（其值≈0，语义正是"auth-fail 的实际代价"）→ auto 模式下注入自然塌到 0；
- **(b) 转发失败时衰减/复位 `cam_rtt` 与 `fail_latency_us`**；
- **(c) 注入前门控"最近 N 次转发是否成功"**。

---

## 4. T3 — 自校准正式验收（优先级 3，核心）

**问题**：`auto_calibrate=1` 后，S1/S2 是否**各自**都把 Δ 压进 95% CI 覆盖 0？

### 4.1 步骤

```bash
# 服务端：MIRAGE_CH_AUTO_CALIBRATE=1（或 config auto_calibrate=true）+ MIRAGE_CH_MEASURE=1
# 1) 预热：让 F 的 EWMA 收敛（≥20 次成功转发）
probe_close_timing -t $S1:9443 -t $S2:9443 --modes badauth --count 20 --first-byte-only --sni $CAM_REAL
#    确认 [CH-GUARD] 的 fail_us= 已稳定（并与 cam_rtt 同量级、且 ≈ 静态公式的 2×cam_rtt+P）

# 2) 成对同口径采样（两台同轮，消除时段漂移）
probe_close_timing -t $S1:9443 -t $S2:9443 --modes badauth,authsucc --interleave \
  --count 20 --first-byte-only --password "$PW" --sni $CAM_REAL
```

#### 4.1.1 服务端侧取证（**依赖 P0.1 的 `fail_us=` / `inj_us=`**）

```bash
# (a) F 的 EWMA 是否已收敛、且 auto 是否真的生效
#     预热前后各取一次（同一进程内持续更新）
grep -o 'fail_us=[0-9]*' $SRV_LOG | tail -30 | awk -F= '{print $2}' \
  | awk '{a[NR]=$1} END{printf "n=%d first=%d last=%d min=%d max=%d\n", NR, a[1], a[NR], a[1], a[NR]}'

# (b) 每条连接的注入基准：auto 生效时 inj_us 应≈fail_us（静态度量下应≈2×rtt_us+100000）
grep 'CH-GUARD' $SRV_LOG | grep 'outcome=complete' | grep 'authed=1' | tail -20 \
  | sed -E 's/.*rtt_us=([0-9]+) fail_us=([0-9]+) inj_us=([0-9]+).*/rtt=\1 fail=\2 inj=\3/'

# (c) 交叉核对: 服务端 F 应与客户端可见量同量级
#     RTT_cs ≈ 探针输出里的 connect_ms(≈1×RTT);  则 F_est ≈ badauth_P50 − RTT_cs
#     与 fail_us 比 — 两者同量级(差 ≤ 30%)即认为一致
```

**交叉核对成立的条件**（写进报告）：`fail_us` 与 `F_est` 差 ≤ 30%；且 auto 开启后
`inj_us` 的 P50 ≈ `fail_us` 的 P50（而非静态式）。

### 4.2 判据（预注册）

1. **S1 与 S2 各自的 95% CI 都覆盖 0** → 通过；
2. 且 `|Δmean| < 配对 σ`（1σ）；
3. 且 `fail_us` 与服务端独立可见量一致（`badauth` P50 减去客户端↔服务端 RTT，同量级即可）。

### 4.3 冷启动子项（同轮做，成本极低）

重启测试实例后**立刻**跑 5 对 `badauth,authsucc`：
- 预期：静态公式兜底，`|Δ|` 不出现 >100ms 的系统偏移；
- 若出现 → 说明冷启动兜底不足（因为 `cam_rtt` 由 prewarm 播种、但 `fail_us` 需要一次成功转发才有值），需记录并评估。

---

## 5. T4 — 回归复测（**任何参数变更后必跑**）

```bash
# 5.1 A1 三形态关闭时间（真站基线 + 两台测试实例，同轮）
probe_close_timing -t $CAM_REAL:443 -t $S1:9443 -t $S2:9443 \
  --modes empty,partial --count 5 --cap 90 --sni $CAM_REAL
#    判据: |Δp50| ≤ 1~2s 且 Δ 为正

# 5.2 judge 关键点 gap 扫描（只两点，n=5）——防"改 ① 顺手动了 ② "
for g in 550 750; do
  probe_close_timing -t $S1:9443 --modes authsucc \
    --count 5 --gap-ms $g --split-at 40 --first-byte-only --password "$PW" --sni $CAM_REAL
done
#    判据: 误杀数 = 0 (不得出现 outcome=fallback && bytes>0 && pre_tls=1)

# 5.3 零成本门禁
cargo test --lib
cargo clippy --all-targets -- -D warnings
cargo clippy --all-targets --features quic -- -D warnings
bash scripts/check-no-real-endpoints.sh
```

---

## 6. 记录表（把结果贴回 `docs/real-machine-verification.md`，**用代号不用真地址**）

**表 A：Δ 与判据**

| 日期 | commit | 测试 | 节点 | 组别/参数 | n | Δmean | 95% CI | 配对 σ | 判据 | 结论 |
|---|---|---|---|---|---|---|---|---|---|---|
| | | T1 empty | S1/S2 | A(2x) | 5 | | | | | |
| | | T1 empty | S1/S2 | B(1x) | 5 | | | | | |
| | | T3 A2 | S1 | auto | 20 | | | | CI∋0 ? | |
| | | T3 A2 | S2 | auto | 20 | | | | CI∋0 ? | |

**表 B：① 的代价（preconnect 分布）**

| 组别 | 条件 | preconnect=0 | 1 | 2a | **2b** | 2b 率 | ch_read_us P50/P95 |
|---|---|---|---|---|---|---|---|
| A | 干净 | | | | | | |
| B | 干净 | | | | | | |
| A | gap=200 | | | | | | |
| B | gap=200 | | | | | | |

**表 C：T2 反向不对称**

| case | 注入前 rtt_us / fail_us | Δmean | 95% CI | auth-fail 绝对首字节 | 结论 |
|---|---|---|---|---|---|
| REJECT | | | | | 缺口成立? |
| DROP | | | | | （记录） |

**表 D：T3 服务端侧取证（依赖 P0.1）**

| 节点 | auto | 预热后 `fail_us` | `inj_us` P50 | `F_est`(badauth P50 − RTT_cs) | 差异 | auto 是否生效 |
|---|---|---|---|---|---|---|
| S1 | off | | | | | — |
| S1 | **on** | | | | | |
| S2 | off | | | | | — |
| S2 | **on** | | | | | |

**表 E：T3 冷启动（重启后立刻 5 对）**

| 节点 | 重启后第 1 对 Δ | 第 5 对 Δ | `fail_us` 何时非 0 | 是否存在 >100ms 系统偏移 |
|---|---|---|---|---|
| S1 | | | 第 N 条成功转发 | |
| S2 | | | | |

---

## 7. 安全 / 清理 / 卫生不变量（每组都适用）

1. **只碰 `9443`**；生产 `8443` / `443` 全程 `active`；`pkill` 必须精确匹配（`pkill -f 'mirage .*9443'` 之类），**禁止** `pkill -9 mirage`（会打掉生产）。
2. **`iptables` / `tc` 必须 trap 清理**（模板见 §3.1），并在每组结束核对 `iptables -S OUTPUT`。
3. **口令与地址**：只经 env / `0600` 文件传入；不进 argv（如可）、不进仓库、不进结果表中的真值（用 `$S1` 代号）。
4. **一次只跑一组参数**；不同组不并行（会互相污染 `[CH-GUARD]` 统计）。
5. **统计纪律**：成对交替（`--interleave`）、同轮、`n≥20`；容差用**配对差的标准差**（不是单边 σ）；先定判据再跑，**不做"再看一眼多跑几次"**。
6. 收尾：删 `/tmp` 产物、终止测试进程、`git status` 干净、门禁跑过。

---

## 8. 执行顺序与门（决策树）

```text
P0 前置（度量字段 / auto_calibrate 入 config / commit / 口令卫生）
  └─ T1 ① 收紧 ── gate: 三判据是否满足 → 采纳 B/C 或保持 A（或折中）
        └─ T2 不可达反向不对称 ── gate: REJECT 下 |Δ|>50ms?
              ├─ 是 → 先修（a/b/c 之一）→ 再进 T3
              └─ 否 → 直接进 T3
                    └─ T3 自校准验收 ── gate: S1/S2 CI 均∋0?
                          ├─ 是 → T4 回归 → 收尾 + 结果回填
                          └─ 否 → 记录 fail_us 与 Δ 的对应关系，回到"采样口径/衰减"排查
```

**预计窗口**：T1 ≈ 3 组 × (empty 70s + 3 档 gap 各 ~20s) ≈ 10 分钟；T2 ≈ 10 分钟；T3 ≈ 15 分钟；T4 ≈ 5 分钟。可在一个晚高峰窗口内完成。
