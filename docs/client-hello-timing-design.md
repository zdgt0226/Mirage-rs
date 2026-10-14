# ClientHello 计时与判定设计（对齐 / 容错分离）

> 状态：**已实施**（2026-10-06 起，取代 `docs/active-probing-assessment-2026-10.md` §4 P1 的"方案 A"）。
> 本文回答三件事：**为什么现在的做法长这样**、**它怎么同时满足对齐与容错**、**它还有哪些残余风险**。
> 验收项见 `docs/real-machine-verification.md` A1–A3；协作流程见 `docs/verification-handoff.md`。

---

## 1. 问题

伪装站（`camouflage_host`）的空闲超时**从它自己 accept 那条连接时开始计**。因此"什么时候建立到伪装站的连接"直接决定了探测者看到的关闭时间。

第一版（延迟预连）只做对了一半：

- **对齐**：改为"判定要转发的此刻即时建连"，池龄 ≈ 0 → T2（空连接）关闭时间偏差从提前 8–14s 收敛到亚秒级。✅
- **容错**：把判定依据从"5s 总时限"改成"**最后一次收到数据后静默 ≈ `clamp(2×RTT, 100ms, 500ms)`**"。❌ 这个窗口的论据是错的：
  1. **假设"ClientHello 分段、段间隔 ≈ 1 RTT"是错的**：真实 Chromium ClientHello 约 **1786B**（含后量子 key_share，见 `tests/test_tls_fingerprint.rs::chromium_size_matches_real`），超过 MSS 1460 → 拆 2 段；但在初始拥塞窗口（IW10）下两段**背靠背发出，间隔 ≈ 0**（客户端还开了 `TCP_NODELAY`）。
  2. **真正出现间隔的只有丢包**，而那时发送端**已无数据可发**，只能等 TLP（≈2×SRTT）或 RTO（Linux 最小 200ms）。低延迟客户端的窗口下限只有 100ms → **扛不住 200ms 的 RTO**。于是丢第 2 段 → 服务端读到半截 → 判异常转真站；丢第 1 段 → 乱序段滞留内核、应用读到 0 字节 → 当空连接转走。**两种都会把合法客户端杀掉**（可用性问题，非泄密；但静默、偶发、极难排查）。
  3. 附带的方法论缺陷：标定度量只记录"读完整"的样本，被误杀的合法客户端**根本不会出现在数据里** → 用它的 P99 去定窗口，**永远看不到窗口太小**（幸存者偏差）。

另外旧做法还有两处工程问题（见 §5）：RTT 样本仅来自"发生转发时"（冷启动为 0 → 时序对齐失效），以及**伪装站地址在转发关键路径上做 DNS 解析**（还混进了 RTT 样本、绕过了 `tuning.dns_tcp_resolver`）。

**根因是一个参数管了两件事**：窗口既要"让真站尽早开始计时"（越小越好），又要"给合法客户端留够重传时间"（越大越好）。二者冲突，所以必须拆开。

---

## 2. 设计：三个时钟

| 时钟 | 名称 | 取值 | 作用 | 谁受影响 |
|---|---|---|---|---|
| ① 对齐 | `preconnect_delay` | `clamp(preconnect_mult × RTT, preconnect_min_ms, preconnect_max_ms)`，默认 `2 / 100ms / 500ms` | 从 accept 起算，超过它 ClientHello 仍未读完整 → **在后台推测性地连一条伪装站连接**（不阻塞读取） | 决定 T2/T3 的**对齐**（真站计时起点 ≈ 探测者连上 + ①） |
| ② 容错 | `judge_silence_ms` | 默认 **1000ms**（每收到数据就重置） | 连续静默超过它 → 判定为探测，转真站 | 决定丢包容忍度（要 > RTO 退避）与 T3 的**残余偏差** |
| ③ 兜底 | `hard_deadline_ms` | 默认 5000ms（绝对上限） | 防"每 `judge_silence`−ε 滴一个字节"的 slowloris | 未认证连接的最长占用 |

**关键点：① 早、② 宽。** 因为它们不再互相迁就：

- **合法客户端**（含丢包重传）：CH 在 ① 之内到齐 → **预连根本没触发**（定时器任务被 abort），零额外开销；丢包时静默 ≤ RTO 退避（200→400→800ms）< ② = 1s → 读到完整 → 认证成功 → **不再被误杀**（修复 P1 的两个形态）。
- **空连接探测**：0 字节 → ① 后预连建立 → 真站**此刻**开始空闲计时；② 到点后用这条连接转发 0 字节 → 探测者看到的关闭 = ① + 真站超时 → **偏差 ≈ ①（几十~几百 ms）**（修复 T2）。
- **半截 ClientHello 探测**：同上，但转发发生在 ②。**若真站在收到数据时重置空闲计时，残余偏差 ≈ ②（1s）** —— 这一点**必须靠 A1 实测确认**（见 §6 残余风险）。
- **滴发探测**：每次数据到达都重置 ②，最长拖到 ③ = 5s（有界）。

---

## 3. 预连的预算（**不能绕过既有反射守卫**）

预连是"由未认证输入触发的出向连接"，必须自带上限，否则一次空连接扫描就能让 VPS 对伪装站狂开连接（正是旧预热池被诟病的那个问题，且这次可被攻击者放大）。

- **独立的预连预算**：全局在途 ≤ `PRECONNECT_MAX_INFLIGHT`（128，信号量 `try_acquire`）+ 全局发起速率 ≤ 30/s（1 秒窗口）。
- **不与反射守卫混用**：`GLOBAL_UNAUTH` / `UNAUTH_RATE` / `UNAUTH_CONNS` 仍在**转发时**计数（那才是真正的反射）。用它们给预连计数会**惩罚触发预连的合法慢客户端**（它们随后认证成功、并非反射）。
- **预算不足时的降级**：不arm预连，②到点时退回"按需即时建连"（仍受反射守卫约束）。**只损失对齐，不影响可用性**。

---

## 4. RTT 来源与 DNS

- **样本要纯**：`observe_connect` 只测**TCP connect** 的耗时（`Instant` 包住 `connect`），解析放在计时之外。
- **DNS 出关键路径**：伪装站地址经 `proxy::resolver::resolve_first`（**60s 缓存** + 尊重 `tuning.dns_tcp_resolver`），再连 IP。不再用 `TcpStream::connect(host:443)` 每次走 `getaddrinfo`（无 nscd 时不缓存）。
  - 这同时修掉一个**部署级 bug**：出向 UDP 被封的 VPS 上，原来每次转发都要先等一次 DNS；现在只在缓存过期或连接失败时重解析。
- **冷启动播种**：启动时 `handshake_cache::prewarm` 本来就会连一次伪装站 —— 把它的 connect 耗时喂给 EWMA 作初值，避免"刚重启后合法用户秒回、最早几次探测却慢 2×RTT"的 T5 侧信道。
- **过时防护**：`prewarm` 的测量顺带在每次模板刷新（30 分钟）时重播一次，避免少见探测的机器上初值长期不动。

---

## 4.5 auth-succ 时序注入：**倍率 + 固定偏置**（实测定档）

注入量的作用：让本地模板回放（auth-succ）的首字节时延，与转发真站（auth-fail）的耗时一致，从而消除 T1/T5 的"合法用户秒回、探针慢回"侧信道。

**实测（S1/S2，n=20，见 `real-machine-verification.md` A2.1/A2.2）**：

- 只注入 `2 × cam_RTT`（旧实现）时，auth-succ 比 auth-fail **快 118~125 ms**（Δp50）。
- 根因：auth-fail 的实际耗时是 `2 × cam_RTT + P`，其中 **`P` 是伪装站/CDN 对 ClientHello 的固有处理底限**
  （证书检索 / CPU 处理 / CDN 回源），**与 RTT 无关**，量级 ~100ms。
- 因此**纯倍率调节方向错误**：增大倍率在小 RTT 链路补不足、在大 RTT 链路过冲（实测 2.5× → S1 Δp50
  反而从 −224ms 变成 −397ms）。
- 参数矩阵实测（4 组 × n=20）：`2.0× + 100ms` 最优（S2 均值差收敛到 **−36ms**，S1 Δp50 −224 → −113ms）。

**公式**（`handshake.rs::auth_succ_delay_us`，启动时由 config/env 定档）：

```text
注入 = (auth_succ_mult_x10 / 10 × cam_RTT + auth_succ_offset_ms) × jitter(75%~125%)
默认  auth_succ_mult_x10 = 20 (2.0×)   auth_succ_offset_ms = 100
```

- **偏置不可省**：它是与 RTT 无关的常量部分（CDN 处理底限），倍率改不了它。
- **附带修了冷启动**：由于偏置本身非 0，**即使尚无 RTT 样本也会注入偏置**（旧实现 `rtt == 0` 则完全不注入）。
- **换伪装站需重校**：`P` 是按 Fastly 测的；换 Cloudflare/Akamai 等应重跑 A2 并按结果调 `auth_succ_offset_ms`。
  更彻底的后续方向见 §6.2 第 4 条（自校准）。

---

## 5. 可观测性（让"误杀"可计数）

修掉幸存者偏差：**判定为异常（Fallback）的样本也要记**，并带上判别丢包误杀所需的字段。

`read_client_hello` 额外返回 `ReadTiming { total_us, max_internal_gap_us, bytes }`，其中 **`max_internal_gap_us` 只统计"两次数据到达之间"的最大间隔，不含末尾那段触发判定的静默**。于是：

| 形态 | `max_internal_gap` | 判读 |
|---|---|---|
| 探测（一次发 40B 后停） | 0（只有一次到达） | 不是丢包误杀 |
| 合法客户端 + 丢第 2 段 | ≈ RTO（≥200ms） | **疑似误杀** |
| 合法客户端 + 丢第 1 段 | ≈ RTO（首字节前无数据，用总时长近似） | **疑似误杀** |

度量行（`MIRAGE_CH_MEASURE=1`）：

```text
[CH-GUARD] outcome=complete|fallback|close ch_read_us=<us> bytes=<n> max_gap_us=<us> pre_tls=<0|1> \
           authed=<0|1> judge_us=<us> preconnect=<0|1|2> rtt_us=<us>
```

- `pre_tls=1` 表示已收到的字节以 `0x16`（TLS 记录）开头。
- 判据：`outcome=fallback && pre_tls=1 && max_gap_us ≥ 150000` ≈ **丢包误杀**；该计数在修好后应保持为 0。
- 未开度量时：首次出现打一次 WARN（附完整解释），之后降 debug（**免被滴发探测刷日志**）。

---

## 6. 实测结论与残余风险

### 6.1 已由真机实测确认 / 修正（S1 新加坡 + S2 德国，2026-10-08）

三项探测形态的残余偏差模型（真站 `speedtest.net`/Fastly，S1/S2 为被测实例）：

| 形态 | 模型 | 实测（相对真站的 Δp50） |
|---|---|---|
| `empty` | `Δ ≈ ① + cam_RTT` | S1 **+682ms** / S2 **+630ms** ✅ |
| `partial` 40B | `Δ ≈ ② + cam_RTT` | S1 **+1398ms** / S2 **+1358ms** ✅（≤2s） |
| `badauth` | 关闭时间不可比（都撞 90s 上限）→ 真正的判别面是**首字节**（A2） | +249~+593ms（cap 截断，参考值） |

1. **真站的计时语义已判定**：Fastly 在收到数据后会**重置**自己的空闲计时 → 半截场景的残余偏差**确实等于 ②**（不是 ①）。
   A3 的三档实测给出线性关系：`Δ_partial ≈ ② + cam_RTT`（②=500 → +746ms；1000 → +1191ms；1500 → +1554ms）。
   → **② 的选择变成了算术**：验收门是 |Δ| ≤ 1~2s，则 ② ≤ 1s − cam_RTT。默认 1000ms 在 S1/S2（cam_RTT≈180ms）下给出 ~1.2~1.4s，仍过门但已接近半程。
2. **① 不必再覆盖"合法 CH 到达时间"**：A3 画像显示合法客户端 `ch_read_us` 仅 **23~236µs**（P50 ≈ 70µs）——
   ClientHello 与握手 ACK **捎带到达**，服务端 accept 时它已在缓冲里。故 ① 里的 `× RTT` 项对合法客户端并非必要；
   ① 越小则 `empty` 偏差越小。生产默认已翻转为 Tier B（`1×RTT`、clamp 50~200ms，配合 `keep_warm_dns` 与 `auto_calibrate = true`），三节点实测 empty 偏差已收敛至 ~50ms 量级，且常数项残差彻底消失（E13 闭环）。
3. **预连对合法客户端确实零开销**：A3 画像中合法客户端全部为 `preconnect=2`（armed 但在延迟内读完 → 任务 abort），
   伪装站侧无对应连接；也确认了"除启动 prewarm 外无后台持续性连接"。
4. **旧实现在真实探测面前是灾难级的**：生产版 v0.12.1 / v0.5.0-alpha.5 的 `empty`/`partial` 均在约 **5.8s** 关闭，
   比真站早 **~55s**（不是之前评估的 8~14s——那是另一代实现）。这反向确认了本方案的诊断与收益。
5. **（Phase-3）② 的取值已被实测锤实**：`judge_silence_ms = 1000` 在 550ms / 750ms 弱网重传间隔下
   **18/18 零误杀**；而 `500ms` 档在 gap ≥ 550ms 时 **0/5 全部误杀** ⇒ **`500ms` 档已实测证伪**，
   不再作为"可选高隐蔽档"候选（取代了 §6.2 旧第 1 条的"待 netm 验证"）。
6. **（Phase-3）反向不对称已免疫**：`CamouflageRtt::observe_connect_failure()` 在建连失败时归零 `cam_rtt`
   与 F，配合 `injection_base_us` 的 `cam_rtt_us == 0 → 0` 守卫；S3 强制建连拒绝下实测 `inj_us = 0`、
   Δmean **+1.7ms**（95% CI [−28.2, +31.6] ∋ 0）⇒ §6.2 旧第 4 条的"自校准待评估"已落地并验收（见下）。
7. **（Phase-3）自校准已实现并验收（机制层）**：`tuning.client_hello_guard.auto_calibrate`（默认 `false`）
   + env `MIRAGE_CH_AUTO_CALIBRATE`；`[CH-GUARD]` 增 `fail_us=` / `inj_us=`，实测 `fail_us == inj_us`（µs 级）。
   注意：**`T0` 取在 `connect_camouflage` 之前**，故 F 含一次建连（`F = 2×cam_rtt + P`），与"注入目标 =
   auth-fail 全程"自洽。

> **⚠️ Phase-3 发现的测量局限（影响"Δ 类指标"的用法）**：
> `Δ = ① + cam_rtt + (cam_idle − baseline_idle)` —— 当 baseline 是"**客户端→真站**"而转发路径是"**VPS→真站**"时，
> 两者可能落在不同 CDN 边缘、空闲超时不同，Δ 里会混入这个差异（S3 实测 Δ 为**负**即此因，达数百 ms）。
> **结论：评估 ① 的收益前必须先让 baseline 同源**（见 `docs/plan-phase4-verification.md` P0.7/T1′）。

### 6.2 未解决 / 需继续跟进

1. ~~**`judge_silence_ms = 500` 的"紧凑档"缺乏丢包容错证据**~~ → **已实测证伪（Phase-3）**：
   gap ≥ 550ms（真实 RTO 退避区间）时 500ms 档 **0/5 全部误杀**；1000ms 档在 550/750ms 下 18/18 零误杀。
   ⇒ **结论：`500ms` 不作为候选档，生产默认保持 1000ms**。
2. **预连的状态机复杂度**：每条"未在 ① 内完成 CH"的连接多一条到伪装站的生命周期；关连接会在伪装站侧留下
   "accept 后无数据即关"的短连接（旧池同类行为更强，但非零）。
3. **预连预算只做全局粒度**：单个恶意 IP 可占满全局额度，导致他人"对齐"降级（可用性不受影响）。未做 per-IP，属有意简化。
4. ~~**注入量仍是"估算 + 定档"，不是自校准**~~ → **已实现并验收（Phase-3）**：见 §6.1 第 6、7 条。
   `auto_calibrate` 默认仍为 `false`（静态公式兜底），因其客户端侧验收的置信区间仍偏宽（σ_paired 400~700ms）、
   且需要先排除"静态兜底样本混入"的干扰（见 `docs/plan-phase4-verification.md` T3′）。
5. **`badauth` 的关闭时间未被真正观测**：五个目标全部撞 90s 采集上限。若关心"完整 CH 认证失败"后的长连接行为差异，
   需把 `--cap` 提到真站握手超时之上（并查阅真站自己的握手超时值）。
6. **合法的"滴发"与探测无法从形态上区分**：②/③ 只把代价压到有界（≤ ③ 的一条连接占用）。

---

## 7. 为什么不用评估文档 §4 的"方案 A（accept 即预连）"

| | 方案 A | 本设计 |
|---|---|---|
| 预连时机 | **每条**入站连接 accept 即连（含占多数的合法客户端） | 仅当 CH 未在 ① 内读完整（≈ 探测/异常/慢客户端） |
| 对伪装站的连接量 | ≈ 入站连接数（合法流量占多数 → 数量级放大，且与有无探测无关） | 与"异常流量"相关；合法快客户端 **0 条** |
| 合法客户端额外开销 | 每条都多一次建连+关闭 | 无（定时器被 abort） |
| 对齐效果 | 偏差 ≈ 1 个 cam RTT | 偏差 ≈ ①（同为数十~数百 ms） |
| 与"旧池被诟病"的关系 | 只是把"常驻"换成"每连接一次"，量级仍大 | 只在需要时才连 |

方案 A 的对齐上限并不比本设计好（都是"到伪装站的一个 RTT"量级），而代价是**把到伪装站的连接量放大到接近入站连接数**——这与我们取消预热的理由直接冲突。故采用本设计。

---

## 8. 配置

```json
"tuning": {
  "client_hello_guard": {
    "preconnect_mult": 2,          // ① = clamp(preconnect_mult × RTT, preconnect_min_ms, preconnect_max_ms)
    "preconnect_min_ms": 100,
    "preconnect_max_ms": 500,
    "judge_silence_ms": 1000,      // ② 必须 > TCP 重传退避 (RTO≥200ms, 退避可达 800ms+)
    "hard_deadline_ms": 5000,      // ③ slowloris 总兜底
    "auth_succ_mult_x10": 20,      // auth-succ 注入 = (20/10 × cam_RTT + offset) × jitter → 2.0×
    "auth_succ_offset_ms": 100,    // 伪装站/CDN 处理底限 P (实测定档, 与 RTT 无关)
                                   //   **仅 auto_calibrate=false 时生效**
    "auto_calibrate": false        // true: 用实测 F(EWMA) 取代静态公式;
                                   //   冷启动(尚无 F 样本)用纯倍率, 不加 offset
  }
}
```

环境变量（启动读一次；真机 A/B 用）：`MIRAGE_CH_PRECONNECT_MULT` / `_MIN_MS` / `_MAX_MS` / `MIRAGE_CH_JUDGE_MS` / `MIRAGE_CH_HARD_MS` / `MIRAGE_CH_AUTH_MULT_X10` / `MIRAGE_CH_AUTH_OFFSET_MS` / `MIRAGE_CH_MEASURE=1`。（旧名 `MIRAGE_DELAY_MULT_TENTHS` / `MIRAGE_DELAY_OFFSET_MS` 仍兼容。）

校验（`check` 即拦）：`mult > 0`、`0 < preconnect_min_ms ≤ preconnect_max_ms`、`judge_silence_ms ≥ 200`、`hard_deadline_ms ≥ judge_silence_ms`、`auth_succ_mult_x10 ∈ 1..=100`、`auth_succ_offset_ms ≤ 2000`。

---

## 9. 实施与验证

实施顺序（每步独立可验）：

1. **计时分离 + 预连 + 可观测性**：`handshake.rs`（三时钟 / `Preconnect` / `ReadTiming` / 度量）、`camouflage.rs`（接预连 socket）、`config.rs` + `startup.rs`（新配置）、`mod.rs`（接线）。
2. **DNS 出关键路径 + RTT 样本变纯**：`camouflage.rs` 走 `resolver::resolve_first` + 计时只包 connect。
3. **冷启动播种 + 周期性刷新**：`handshake_cache::prewarm` 回传 connect 耗时 → EWMA。
4. **收尾**：重试循环语义与注释对齐、EWMA 改 CAS、测试裕量、文档同步。

零成本验证（每次改完都跑）：

```bash
cargo test --lib proxy::mirage_server && cargo test --lib config::
cargo clippy --all-targets -- -D warnings && bash scripts/check-no-real-endpoints.sh
```

真机验证（`docs/real-machine-verification.md`）：**A1**（三种形态关闭时间对齐，重点看"提前"方向）、**A2**（auth-succ vs auth-fail 首字节时延差）、**A3**（用 §5 的度量定 ① / ② 取值；先确认 `max_gap_us ≥ 150000 且 pre_tls=1` 的计数为 0）。

### 9.1 实机验证进展（截至 2026-10-10）

| 阶段 | 文件 | 结论 |
|---|---|---|
| Phase-1/2 | `docs/real-machine-verification.md` A1–A3 | 关闭时间对齐达标；`P` 非全局常量（两节点 CI 不相交）⇒ 需要自校准 |
| Phase-3（三节点） | `docs/phase3-real-machine-verification-report.md` | ② 保持 1000ms（500ms 证伪）；反向不对称免疫验收；自校准机制验收（`fail_us == inj_us`） |
| **Phase-4（已执行）** | `docs/phase4-real-machine-verification-report.md` | 同源 baseline 确立（三节点 idle 61.0~61.2s，极差 146ms）；`2b` 归因定案（gap ≥ 750ms 时 95~100%，**Phase-3 的 `2b=0` 被推翻**）；自校准逐条复核 auto 占比 100%、Δp50 11.5~39ms；定档 Tier B（理由=机制上界+不劣性，见报告 §4.3/§8） |
| **Phase-5（待办）** | 报告 §8.1 | Tier A S1 行复测；`Δ ≈ pc_ready_us` 同连接对齐核对；baseline/转发的解析 IP 一致性 |
