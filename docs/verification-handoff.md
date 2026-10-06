# 验证与测试交接指南（面向协作模型 / 协作者）

> **本文档的读者是接手的 AI 模型或协作者**，不是最终用户。目标：让接手方在**不重新通读全仓**的前提下，
> 准确判断"这次改动对不对""哪些能自动验、哪些必须真机验""结果怎么回填"。
>
> 配套文档：
> - `CLAUDE.md` —— 编码行为守则（最小改动 / 外科手术式 / 先想后写 / 端点护栏）。**动手前先读**。
> - `docs/real-machine-verification.md` —— 所有需真机 / netns 的验证项（**本文只做索引与判据**）。
> - `docs/threat-model.md` —— 抗审查验收基准 T1–T7（改动是否触碰红线的判据来源）。
> - `docs/active-probing-assessment-2026-10.md` —— 本次改动（延迟预连）的动因与实测数据。
> - `CHANGELOG.md` `[Unreleased]` —— 本次及近期改动的权威清单。
> - `graft/` —— 代码上下文图（`graft ask "<问题>" --source`）。**找代码先问 graft，再 grep。**

状态图例（两个文档通用）：⬜ 未开始 · 🔄 进行中 · ✅ 已完成（注明版本+日期）· ❌ 未通过（注明证据）· ⏸️ 暂缓

---

## 0. 30 秒背景

**本次改动 = 用「延迟预连」取代伪装站的「预热连接池」+ ClientHello 读取改为静默间隔语义。**

- **为什么**：旧池后台常驻 8 条预连到伪装站，探测者（空连接 / 半截 ClientHello）看到的关闭时间比真站
  **提前 8~14 秒**，可区分（T2/T3）。根因是"池中连接的已存在时长"被真站的 idle-timeout 继承。
- **怎么改**：转发路径改为"**判定要转发的此刻即时建连**"；读取改为"**最后一次收到数据后静默
  `quiet_timeout` 即判异常**"，窗口随客户端 RTT 自适应（可配）。
- **改动的权威清单**：`CHANGELOG.md` → `### feat(anti-probing): 延迟预连取代伪装站预热连接池 ...`

**接手方第一件事**：跑 §1 的零成本门禁（约 3~5 分钟，无需真机）。全绿才进入 §3 的真机项。

---

## 1. 零成本验证（无需真机，**必跑**）

```bash
cd <repo 根>

# ① 端点 / 密钥门禁 (CI 硬门禁; 见 CLAUDE.md §5)
bash scripts/check-no-real-endpoints.sh

# ② 构建 + eBPF feature 编译 (② 需 clang/llvm/libbpf-dev/linux-headers)
cargo build
cargo check --features ebpf

# ③ clippy 门禁 (CI 为 -D warnings, 新 warning 即红)
cargo clippy --all-targets -- -D warnings

# ④ 全量测试 (含 tests/ 下的 integration)
cargo test

# ⑤ QUIC feature (实验特性, 但 CI 也跑)
cargo clippy --all-targets --features quic -- -D warnings
cargo test --features quic --lib
cargo test --features quic --test test_quic_e2e

# ⑥ crypto 相对吞吐哨兵 (仅显式跑; 需 AES-NI 机器)
cargo test --release aes_chacha_throughput_ratio_sentinel -- --ignored --nocapture
```

**预期（判定通过）**

| # | 预期 |
|---|---|
| ① | 退出码 0，输出无 `[-]`（有则说明有真实地址/密钥被硬编码 —— 见 §6 红线） |
| ② | 编译成功 |
| ③⑤ | 0 warning（`-D warnings` 下退出码 0） |
| ④ | lib 测试 **516 passed; 0 failed; 3 ignored**（数字会随改动增长；重点是 `0 failed`） |
| ⑤ | quic lib 测试与 e2e 全绿 |
| ⑥ | AES-256-GCM / ChaCha20 比值 ≥ 1.3（有 AES-NI 时） |

> 环境缺 clang/llvm 时，② 与 CI 的 `ebpf-verify` job 无法本地复现 —— 在报告里注明"未跑"，
> **不要**把它当成"通过"。

---

## 2. 本次改动的不变量 ↔ 锁定它的测试

> 接手方若发现某条不变量**没有**对应测试，或测试断言与描述不符，**这是一个发现**（写进报告）。

| # | 不变量 | 代码位置 | 锁定测试（`cargo test <名>`） |
|---|---|---|---|
| I1 | 转发路径**无后台预连**：触发前 0 连接，触发后恰好 1 条 | `camouflage.rs::run_camouflage_forward` | `camouflage::tests::forward_connects_on_demand_not_before` |
| I2 | `CamouflageRtt` 无后台任务；EWMA 首样本即初值、平滑、毛刺截断 | `camouflage_rtt.rs` | `camouflage_rtt::tests::{no_sample_returns_zero,first_sample_seeds_ewma,ewma_smooths_and_stays_positive,spike_is_capped}` |
| I3 | ClientHello 读取为**静默间隔**：数据持续到达不触发；静默即 Fallback | `handshake.rs::read_client_hello` | `handshake::tests::test_read_client_hello_interval_data_not_treated_as_quiet` |
| I4 | `hard_deadline` 兜底 slowloris（滴发间隔 < 静默窗口也强制回落） | 同上 | `handshake::tests::test_read_client_hello_drip_feed_hits_hard_deadline` |
| I5 | 半截 / 0 字节超时 → Fallback **且携带已读全部字节** | 同上 | `test_read_client_hello_partial_body_timeout_fallback` / `test_read_client_hello_zero_bytes_timeout_fallback` |
| I6 | 只读首个 record，不吞管道化后续字节 | 同上 | `test_read_client_hello_does_not_overread_past_record` |
| I7 | 窗口 = `clamp(mult×RTT, min, max)`；未知 RTT → `max`；min/max 反转自动纠正 | `handshake.rs::quiet_window` | `handshake::tests::quiet_window_adapts_to_rtt` |
| I8 | 窗口参数可配（config），非法值被 `check` 拦下 | `config.rs::ClientHelloQuietConfig` | `config::validation_tests::client_hello_quiet_params_validated` |
| I9 | 转发目标头 `[2B len][host:port]` 与**服务端真解析函数**一致 | `handshake.rs::tunnel_target_header`（DNS 侧） | `dns::server::tests::tunnel_target_header_matches_server_parse` |

**未被单测覆盖、必须真机验的**（见 §3）：

- **I10** auth-succ 注入量为 `2 × cam_RTT`（`handshake.rs` 注入处）—— 纯时序，单测无法判定对错。
- **I11** 三种探测形态的**绝对关闭时间**与真站对齐（≤1~2s）。
- **I12** `T_quiet` 的 `min_ms`/`max_ms` 取值是否覆盖真实链路的 P99。

---

## 3. 需真机 / netns 的验证（**不在本文重复步骤**）

逐项步骤、命令、判据、采集工具全部在 **`docs/real-machine-verification.md`**。接手方按表执行：

| 项 | 内容 | 与本次改动的关系 |
|---|---|---|
| **A1** | T2/T3 关闭时间端到端对齐（真站 vs Mirage） | ⭐ 本次改动的核心验收 |
| **A2** | auth-succ 与 auth-fail 首字节时延差 | ⭐ 核对注入量 `2×cam_RTT` |
| **A3** | `T_quiet` 参数标定（合法 ClientHello 到达分布 → 定 min/max） | ⭐ 决定默认值是否合理 |
| B1–B3 | 探测面（SNI/IP 对照 / 生产升级 / 伪装站就近） | 相邻（同属抗主动探测面） |
| C1–C4 | 内核 / eBPF（TCP listener、LPM、ICMP） | 无关 |
| D1–D3 | 传输 / 性能（UDP mux、QUIC） | 无关 |
| E1–E2 | 泄漏测试补全（WG DNS、T1 转发） | 相邻（E2 与 A2 互补） |
| F1–F2 | 工程 / 供应链 | 无关 |

**采集工具（已提供，勿重复造轮子）**

```bash
# A1/A2: 探测关闭时间与首字节时延分布 (三形态: empty / partial / badauth)
cargo run --release --example probe_close_timing -- \
  -t 203.0.113.10:443 -t 198.51.100.20:443 --count 5 --sni www.example.com
#   ⚠️ 上面是 RFC 5737 占位地址, 仅示意; 真机参数由操作者经命令行传入, 严禁写进仓库 (见 §6)

# A3: 服务端 opt-in 度量 (输出 [QUIET-MEASURE] 行; 量完取消该 env 重启)
MIRAGE_QUIET_MEASURE=1 <server 启动命令>
```

**若接手方只能做零成本验证**：把 §3 标 ⭐ 的三项标为"未跑（需真机）"，**不要**判为通过。

---

## 4. 判据总表（通过 / 不通过）

| 判据 | 通过 | 不通过（给证据） |
|---|---|---|
| §1 门禁 | 全部退出码 0 且测试 `0 failed` | 任一红 → 定位到具体测试/行 |
| I1 无后台预连 | 触发前连接数 0 | 触发前 >0 → 预热池残留（回归） |
| I3/I4 静默语义 | 分段到达 → Complete；滴发 → hard 兜底 | 分段到达被判 Fallback → 误伤合法客户端 |
| I7 窗口 | `clamp` 语义 + 反转纠正正确 | 越界/未纠正 |
| A1 关闭时间 | `empty`/`partial` 的 \|Δp50\| ≤ 1~2s | **Δ 为负（提前）** = 池龄残留，重点排查 |
| A2 首字节 | auth-succ 与 auth-fail 中位数差 ≤ 个位数 ms | 明显单向偏离 → 调 `2×` 系数 |
| A3 标定 | `max_ms` ≥ 实测 P99（不误伤） | P99 > `max_ms` → 有合法客户端会被误转发 |
| T1–T7 | 无红线违规 | 触碰红线 → 见 `docs/threat-model.md` |

---

## 5. 结果回填（**协作契约**）

### 5.1 回填到哪里

1. **零成本门禁结果** → 追加到本文件 §7「验证记录表」（一行）。
2. **真机项** → 更新 `docs/real-machine-verification.md` 对应项的**状态图例**（⬜ → ✅/❌），
   并在该项下补「实测值 + 日期 + 版本」。
3. **发现了新问题** → 不要静默修；先写清「现象 / 复现命令 / 影响面 / 猜测根因」，
   再按 `CLAUDE.md` 的"最小改动"原则修，并补一条单测或场景测试锁定。

### 5.2 报告模板（贴到 PR 描述 / 回复里）

```markdown
## 验证报告

- 版本/commit：<mirage-rs vX.Y.Z / commit>
- 环境：<kernel 版本 / 是否 root / 有无 clang / 有无 AES-NI>

### 零成本门禁
- [ ] check-no-real-endpoints.sh → 退出码 <0/非0>
- [ ] cargo clippy --all-targets -- -D warnings → <0 warning / N>
- [ ] cargo test → <N passed, M failed, K ignored>
- [ ] cargo clippy/test --features quic → <...>

### 不变量抽查（§2）
| # | 结论 | 证据（命令 + 关键输出） |
|---|---|---|
| I3 | 符合 / 不符 | `cargo test test_read_client_hello_interval...` → ok |

### 真机项（§3）
| 项 | 状态 | 实测值 | 判据 | 结论 |
|---|---|---|---|---|
| A1 | ⬜/✅/❌ | 真站 close p50=… Mirage close p50=… Δ=… | ≤1~2s | … |

### 发现 / 未跑项
- 未跑：<项>（原因：<无真机 / 无 clang / …>）
- 发现：<现象 + 复现 + 影响面>
```

### 5.3 验证记录表（零成本门禁，逐次追加）

| 日期 | 版本/commit | 执行者 | check-endpoints | clippy(default) | cargo test | clippy(quic) | 备注 |
|---|---|---|---|---|---|---|---|
| 2026-10-06 | v0.15.2 + 延迟预连 | 初始实现方 | ✅ 0 | ✅ 0 | ✅ 516/0/3 | ✅ 0 | tools + 度量同批 |
| 2026-10-06 | v0.15.2 / ec4a4c5 + 工作区 (随本提交) | Antigravity AI | ✅ 0 | ✅ 0 | ✅ 516/0/3 | ✅ 0 | 零成本门禁全绿 + I1~I9全过 |

---

## 6. 红线与陷阱（**违反即打回**）

### 6.1 仓库级硬约束

1. **端点护栏（CI 硬门禁）**：源码 / 文档 / 测试中**禁止**出现真实服务器地址、节点链接、口令、密钥。
   - 占位一律用 RFC 5737 / 3849（`203.0.113.x`、`198.51.100.x`、`192.0.2.x`、`2001:db8::/32`）
     或保留域名（`example.com` / `.test` / `localhost`）。
   - 需要真实参数的测试/工具：**只能经环境变量或命令行传入**，缺失时明确提示并以非零码退出。
   - 若确需新增公网地址白名单，**必须**同步更新 `scripts/endpoint-allowlist.txt` 并注明用途与理由。
2. **协议冻结常量不许"顺手修正"**：
   - `crypto/aead.rs` 的 HKDF info `b"pyrealiy-session"`（历史拼写错误，改了=两端密钥不兼容）。
   - `crypto/cipher.rs` 的 `hkdf_suffix()`（ChaCha20 后缀必须为空，否则破坏向后兼容）。
   - `proxy/mirage_server/control.rs` 的分派哨兵（`0x00` UDP / `MUX_SENTINEL=0x01` / `[2B len][host:port]` TCP）。
   - 这些地方改动需**两端同步 + 协议版本 bump**，且必须有 e2e 覆盖。
3. **不要动与本次任务无关的代码**（格式化、重命名、清理"死代码"）。发现的无关问题**写进报告**，
   不顺手改（`CLAUDE.md` §3）。

### 6.2 本次改动特有的陷阱

| 陷阱 | 后果 | 正确做法 |
|---|---|---|
| 把 `quiet_timeout_for` 的"未知 RTT → `max`"改回硬编码 300ms | 与可配语义不一致 | 保持 §2 I7 的测试断言 |
| 只改发端/只改配置而不跑 §1 ④ | 破坏 I8 的 check 拦截 | 改 config 字段后必跑 `config::validation_tests` |
| 把 `2 × cam_RTT` 改回 `1 ×` 而不核对 A2 | T1/T5 时序侧信道回归 | 改系数必须在报告里附 A2 数据 |
| 为"省几毫秒"重新引入常驻预热池 | T2/T3 侧信道回归（本改动的初衷） | 若要小池，只允许**按需**建连；常驻池需重新评估并附 A1 数据 |
| 用 `--count 1` 跑一次就下结论 | 单样本噪声淹没结论 | 跨轮重复取中位数（文档 A1 已写明） |

### 6.3 工具链提示

- 改了代码后若项目启用了 `graft` 索引：跑 `graft build` 刷新（确定性、无需 API key）。
- 新增 example 后确认 `cargo clippy --all-targets` 仍 0 warning（CI 覆盖 examples）。
- 新增配置字段后：`config.rs` 的 `install_sh_config_templates_fields_take_effect` 类测试用于**防字段漂移**，
  若新字段属于模板必填，同步更新断言。

---

## 7. 速查索引

### 7.1 本次改动涉及的文件

| 文件 | 角色 |
|---|---|
| `src/proxy/mirage_server/camouflage.rs` | 转发路径（去池 → 即时建连，重试 1 次 → 合成模板） |
| `src/proxy/mirage_server/camouflage_rtt.rs` | RTT EWMA 估计器（**新增**，取代 `camouflage_pool.rs`） |
| `src/proxy/mirage_server/handshake.rs` | `read_client_hello`（静默语义）/ `quiet_window` / `set_quiet_window` / auth-succ 注入 / `[QUIET-MEASURE]` 度量 |
| `src/proxy/mirage_server/mod.rs` | 模块接线 + `set_quiet_window` re-export |
| `src/config.rs` | `TuningConfig::client_hello_quiet` + 语义校验 |
| `src/startup.rs` | 启动时应用窗口参数（含 env 覆盖） |
| `examples/probe_close_timing.rs` | A1/A2 采集工具（**新增**） |
| `docs/real-machine-verification.md` | 真机验证任务列表（**新增**） |
| `docs/active-probing-assessment-2026-10.md` | 动因 + P1 实施状态 |

### 7.2 常用命令

```bash
# 只看本次改动相关的测试
cargo test --lib proxy::mirage_server
cargo test --lib config::validation_tests

# 单跑一条
cargo test --lib <测试名>

# 真机探测 (参数由操作者传入, 不写进仓库)
cargo run --release --example probe_close_timing -- -t <真站>:443 -t <Mirage>:443 --count 5

# A3 度量
MIRAGE_QUIET_MEASURE=1 <server>

# 配置校验闸门 (改配置/规则后)
<binary> check -c <config.json> && systemctl restart mirage-rs
```

### 7.3 关键概念一句话

| 概念 | 一句话 |
|---|---|
| `quiet_timeout` | "最后一次收到数据后静默多久即判异常"；默认 `clamp(2×RTT, 100ms, 500ms)` |
| `hard_deadline` | 5s 总时限，防"滴发"slowloris |
| 延迟预连 | 判定要转发的**那一刻**才建连（池龄 ≈ 0），而非后台常驻预连 |
| `cam_RTT` | 服务器 → 伪装站的 RTT（EWMA），用于 auth-succ 时序对齐 |
| T2/T3 | 真站 idle 超时对齐（空连接 / 半截）；本次改动的主验收目标 |
| `[QUIET-MEASURE]` | A3 标定用的服务端度量行（env 门控，默认关） |

---

## 8. 交接清单（接手方勾选）

- [ ] 读 `CLAUDE.md`（编码守则 + 端点护栏）
- [ ] 读 `CHANGELOG.md` `[Unreleased]`（本次改动权威清单）
- [ ] 读本文件 §0–§2（背景 + 不变量）
- [ ] 跑 §1 零成本门禁，结果回填 §5.3
- [ ] 抽查 §2 至少 3 条不变量（含 I3/I4/I7 之一），确认测试真能锁住描述
- [ ] 判定能否做 §3 真机项：能 → 按 `docs/real-machine-verification.md` 执行并回填；
      不能 → 明确标注"未跑（需真机）"
- [ ] 按 §5.2 模板产出验证报告
- [ ] 若发现问题：先报告，再按最小改动修 + 补测试
