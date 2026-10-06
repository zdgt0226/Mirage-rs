# 实机验证任务列表

> 汇总**所有需要真机 / 真实网络 / netns 环境才能完成的验证项** —— 单测覆盖不到的时序、内核、
> 真实链路行为。每项给出**来源、验证内容、判据**。完成一项就把状态从 ⬜ 改为 ✅ 并注明版本与日期。
>
> **接手方的入口**：先读 [`docs/verification-handoff.md`](verification-handoff.md)（零成本门禁 →
> 不变量抽查 → 再进本文的真机项 → 结果回填格式）。本文只列"跑什么、怎么算过"。
>
> 文中服务器 / 客户端均以代号表示（S1/S2、C1/C2），不含任何真实地址。
> CI 里的 `ebpf-verify`（netns）与 `tests/`（进程内场景测试）能跑的**不**列在这里。

状态图例：⬜ 未开始 · 🔄 进行中 · ✅ 已完成 · ⏸️ 暂缓（有意的，非遗漏）

---

## A. 延迟预连（2026-10，本次改动，优先级最高）

改动见 `CHANGELOG.md` [Unreleased] 与 `docs/active-probing-assessment-2026-10.md` 文首"实施状态"。

### A1. T2/T3 关闭时间端到端对齐（真站 vs Mirage）⬜

- **来源**：`docs/active-probing-assessment-2026-10.md` §3/§4 P1。
- **背景**：旧预热池把"连接已存在时长"传导给真站 idle-timeout，探测者看到的关闭时间比真站提前
  8~14s（实测 46.6~56.0s vs 60.3~64.0s）。延迟预连改为"判定要转发时即时建连"，**预期**偏差收敛到
  「静默窗口 + 服务器→伪装站 RTT」（亚秒级）。
- **步骤**：对**真站**端口与 **Mirage 服务端**端口分别发三种探测，测"从连上到收到 FIN"的时间：
  1. 空连接（连上不发数据）；
  2. 半截 ClientHello（发 40 字节就停）；
  3. 完整但认证失败的 ClientHello（token 错误）。
  每个形态各 ≥5 次，记录中位数与离散度。
- **采集工具**（已提供，无需手工掐表）：
  ```bash
  cargo run --release --example probe_close_timing -- \
    -t <真站>:443 -t <Mirage服务端>:443 --count 5 --sni <真站域名>
  ```
  **第 1 个 `-t` 给真站作基线**（工具会对比第 2..n 个与第 1 个的 Δp50）。
  逐条记录 `connect_ms` / `first_byte_after_connect_ms` / `close_ms` 并输出 P50/P95/P99。
  目标机无 Rust 工具链时，可本机 `cargo build --release --example probe_close_timing`
  后把 `target/release/examples/probe_close_timing` 拷过去。
- **判据**：`empty` / `partial` 下 |Mirage 关闭时间 − 真站关闭时间| ≤ 1~2s（看 Δp50）。
  **重点关注"提前"方向** —— Δ 为负（提前）即池龄残留的回归信号。
- **备注**：进程内单测已覆盖机制（按需建连、静默语义、自适应窗口），此步只验绝对时序。

### A2. auth-succ 与 auth-fail 首字节时延差（T1/T5）⬜

- **来源**：本次改动把 auth-succ 的时序注入由 `1 × cam_RTT` 翻倍到 `2 × cam_RTT`
  （因 auth-fail 现为即时建连 = 建连 RTT + 转发 RTT）。此为**分析值**，需实测核对。
- **步骤**：
  1. 测 **auth-succ**（合法凭据）从"服务端收完 ClientHello"到"首字节发出"的时延；
  2. 测 **auth-fail**（完整但认证失败的 ClientHello）同口径时延；
  3. 各 ≥20 次，比较两者的中位数与分布（不是单次）。
- **采集工具**（同口径，建议同机、同轮、交错采）：
  - auth-fail 侧：`probe_close_timing -t <Mirage服务端>:443 --modes badauth --count 20`
    看 `first_byte_after_connect_ms`（已减去 TCP 建连段）；
  - auth-succ 侧：`mirage-rs test -c config.json --tag <mirage出站>` 报告的 `handshake_ms`
    （同为"建连后 → 认证确认"）。
- **判据**：两者中位数差落在**跨境抖动噪声范围内**（量级 ≤ 个位数 ms），即探测者无法用首字节
  时延稳定分类。若 auth-succ 明显更快 → 注入量偏小（把 `handshake.rs` 里的 `2 ×` 系数调大）；
  明显更慢 → 偏小调小。
- **备注**：改的是 `handshake.rs` 的 `2 × cam_RTT` 系数，与 `MIRAGE_QUIET_*` 无关。

### A3. `T_quiet` 参数标定（`clamp(mult×RTT, min, max)`）⬜

- **来源**：`tuning.client_hello_quiet`（本次新增，默认 `2 / 100ms / 500ms`）。
- **步骤**：
  1. 在晚高峰跨境链路上采集**合法 ClientHello 从探测者/客户端连上到完整送达**的时间分布
     （P50 / P95 / P99）；
  2. 用 `MIRAGE_QUIET_MULT` / `MIRAGE_QUIET_MIN_MS` / `MIRAGE_QUIET_MAX_MS` 环境变量 A/B
     调参（无需改 config、无需重编）；观察 A1 的关闭偏差与"是否有合法客户端被误转发到真站"。
- **采集（服务端 opt-in 度量）**：服务端设 `MIRAGE_QUIET_MEASURE=1` 重启，每个"读完整
  ClientHello"的连接会输出一行：
  ```text
  [QUIET-MEASURE] ch_read_us=<us> bytes=<n> authed=<0|1> quiet_us=<us> rtt_us=<us>
  ```
  跑一段真实流量后统计**合法客户端**（`authed=1`）的分布：
  ```bash
  journalctl -u mirage-rs-server --since "1 hour ago" | grep QUIET-MEASURE | grep 'authed=1' \
    | sed -E 's/.*ch_read_us=([0-9]+).*/\1/' | sort -n \
    | awk '{a[NR]=$1} END{printf "n=%d p50=%d p95=%d p99=%d max=%d (us)\n", NR, a[int(NR*0.5)], a[int(NR*0.95)], a[int(NR*0.99)], a[NR]}'
  ```
- **判据**：`max_ms` 覆盖 P99（不误伤），同时 `min_ms` 尽量小（探测偏差小）。`authed=1` 的
  `rtt_us` 还可用来校 `mult`（`ch_read_us / rtt_us`）。
- **备注**：调参定档后把结论写回 `tuning.client_hello_quiet` 的文档注释或此处。
  度量开关默认关，量完记得取消 `MIRAGE_QUIET_MEASURE` 重启（避免日志量）。

---

## B. 主动探测面（评估 §4 的 P2/P4/P5）

### B1. P2 —— SNI 与 IP 一致性对照实验 ⬜

- **来源**：`docs/active-probing-assessment-2026-10.md` §4 P2。
- **内容**：两台条件相同的服务端，一台伪装 `speedtest.net`（Fastly CDN，IP 归属不符），一台用
  **同 ASN / 同网段**的真实 TLS 站点，若干晚高峰持续观测**被主动探测次数**。
- **判据**：若"同 ASN 伪装"显著降低被探测/被封锁率 → 让 `install.sh` 的 SNI/IP 一致性搜索默认启用。

### B2. P4 —— 生产服务器升级到 v0.15.x ⬜

- **来源**：§4 P4。
- **现状**：生产服务器分别为 v0.12.1 与 v0.5.0-alpha.5，仍带 §5.3 中已被 v0.15 修复的识别面
  （空连接 / 明文 HTTP / 随机字节探测的回应与真站不一致；ServerHello key_share 跨连接重复）。
- **判据**：两侧版本一致后，重跑 §5.3 的探测对照（非 TLS 探测回应与真站一致）。
- **注意**：v0.15 是**协议断代**，升级需客户端（含 Android App）同步更换。

### B3. P5 —— 伪装站就近 + `RTT_MAX_US` 收紧 ⬜

- **来源**：§4 P5。
- **内容**：选离 VPS 近的伪装站（T1 多出的时间 ≈ 服务器→伪装站 RTT）；视情况收紧
  `camouflage_rtt.rs` 的 `RTT_MAX_US`（现 1s）。
- **判据**：A1 的 T1 首字节时延差与 auth-succ 注入量同步变小。

---

## C. 内核 / eBPF 数据面

### C1. TCP listener 分水岭 —— 真机复核 ✅（netns 三段拓扑，2026-10-06）

- **来源**：`docs/deploy-smoke-test.md` §6。netns 已通过（`examples/verify_tc_divert_tcp.sh`），真机复核。
- **判据**：代理 TCP 时反查目标 == 原始目的；`[TPROXY].*TCP` 出现，且不是被 MASQUERADE 转发。
- **实测**（v0.15.2-4-gcf2bb8d，本机 J4105 / kernel 6.1；netns：LAN 设备 — 网关 (mirage client 透明模式, tc_divert + sk_lookup, 8332 段 direct_cidr) — 出口侧 (mirage server + 目标站)，网关 WAN 口 MASQUERADE）：
  - 裸-IP 走代理（文档地址 `203.0.113.80:8080`）：日志 `[TPROXY] TCP … → 203.0.113.80:8080 → [203.0.113.80:8080]` + `[ROUTE] → [proxy]` + `[TUNNEL] 建立`；目标站看到的对端是服务端本机地址，**不是**网关 WAN 地址 → 未被 MASQUERADE 转发。
  - fake-IP 走代理（LAN 经网关 DNS 解析得 `198.18.0.x`）：`[TPROXY] TCP … → 198.18.0.2:8080 → [域名:8080]`，经隧道到达目标。
  - 对照：geoip cn 内地址走直连快路径，目标看到对端 = 网关 WAN 地址（MASQUERADE），无 `[TPROXY]` 日志，符合预期。
  - 局限：netns 模拟，非实体 LAN 设备 / 实体网卡。

### C2. LPM 是否成为 CPU 热点（决定要不要加 flow cache）✅ 不加（netns，2026-10-06）

- **来源**：`docs/deploy-smoke-test.md` §7。
- **内容**：LAN 设备从国内 CDN 持续高速下载（走 `direct_cidr` 直连路径）压满带宽，采样 tc 软中断里
  LPM 查找占比。
- **判据**：若 LPM 占比 <0.1% 核 → **不加** flow cache（避免无失效缓存的泄漏风险）。
- **实测**（同 C1 拓扑，LAN→geoip cn 目标 iperf3 直连上行，`perf record -a -g` 10s，两轮）：
  | 场景 | 吞吐 | gl0 收包 | `trie_lookup_elem` | `tc_divert` 程序 | 对照：内核 `fib_table_lookup` |
  |---|---|---|---|---|---|
  | veth 默认 TSO（大段） | 5.1 Gbps | 1.2 万 pps | 0.05% | 0.08% | — |
  | 关 TSO/GSO/GRO（MTU 包） | 1.44 Gbps | **12 万 pps**（> 千兆线速 8.1 万） | **0.77%** | 0.42~0.48% | 2.3~2.4% |
  - 百分比为 4 核全部采样的占比，折合约 3% 单核；LPM 查找比每包都要做的内核路由查找还便宜。**结论：不是热点，不加 flow cache。**
  - `%soft` 单核最高 42~64%、全核 21~23%，但该值包含同机 iperf 收发两端与 veth 转发的全部软中断，不能归因到 LPM，不按 §7 的 `%soft` 档判定。

### C3. ICMP 假 IP 反射（第一步）✅（netns，2026-10-06）

- **来源**：`brain/pages/icmp-fakeip-reflect.md`；`brain/roadmap.md`。
- **内容**：`bpf_redirect` 回弹 + tc ingress 语义本地难复现，需真机确认（校验和已复算）。
- **判据**：LAN 设备 ping 被代理域名得到来自 fake-IP 的 ICMP 回显，且不泄漏真实目标。
- **实测**（同 C1 拓扑）：LAN `ping -c3 198.18.0.2` → 3/3 回显，RTT 0.07ms（网关本地反射）；网关 LAN 口抓包见 echo request/reply 成对，**WAN 口同时段 ICMP 抓包为空** → 不泄漏。启动日志 `fake-IP ICMP 反射=198.18.0.0/15`。

### C4. ICMP 真隧道（第二步）⏸️ 暂缓

- **来源**：`brain/pages/icmp-fakeip-reflect.md`。
- **理由**：捕获路径三条（AF_PACKET/TUN/无）均待真机且边际价值低，保留第一步本地反射即可。

---

## D. 传输 / 性能

### D1. UDP mux 带机量 bench ✅ 突破 pool_size（netns + 实链路，2026-10-06；上限未到 4096）

- **来源**：`brain/pages/udp-capacity-findings.md`。
- **内容**：真机 bench 验证 mux 后并发 UDP 流**突破 `pool_size` 硬伤**（此前真机实测两端
  0.5→0.9 部署并发拐点 20→450）。
- **判据**：mux 开启下并发流上限由 `MAX_FLOWS`（4096）而非 `pool_size` 决定。
- **实测**（`scripts/bench_udp_capacity.py`，网关 `pool_size=4`，每流 10 包/秒、64B，拐点 = flow_ok 跌破 95%）：
  | 环境 | `udp_mux=false` | `udp_mux=true` |
  |---|---|---|
  | netns（网关、服务端、echo、压测全在本机 4 核） | 拐点 < 100 | 800 全过，1000 时 71%（拐点 ≈ 1000）；每流 2 包/秒时拐点 ≈ 2000 |
  | 实链路（本机 netns 网关 → S1，RTT ≈ 175ms，echo 在服务端本机） | 拐点 ≈ 60 | 1000 时 flow_ok 100%（丢包 37%），拐点 ≈ 1400 |
  - **pool_size 墙已破**：mux 关时几十条即崩，mux 开 1000+。
  - **但上限不是 4096**：拐点随每流包率移动（10 包/秒 ≈1000，2 包/秒 ≈2000），属吞吐型而非流表数量墙。网关 netns `UdpRcvbufErrors` 累计约 1 万（服务端约 2400）→ **主要丢在网关透明 UDP socket 的接收缓冲**（单 socket 用户态排空速度），过拐点后断崖式跌到约 7%。
  - 后续可选：网关透明 UDP socket 增大 `SO_RCVBUF` / 多 socket 分担，再复测（本次未改代码）。

### D2. QUIC 定速在干净链路上不超发 ✅（netns + 实链路，2026-10-06）

- **来源**：`docs/quic-transport-design.md` §5.8 末；`docs/benchmark-2026-09.md`。
- **内容**：定速公式在**无丢包**时补偿应为 1（不超发），此前仅公式推导，未实机验证。
- **判据**：无丢包链路上实测速率 ≈ 设定速率（不超发）。
- **实测**（`transport: quic` + `brutal_rate_mbps`，50MB 下载 ×3）：
  | 链路 | 设定 | goodput | 线上平均（含间隙） | netem 丢弃 |
  |---|---|---|---|---|
  | netns 200Mbit / RTT 40ms / 0 丢包 | 30 | 28.6~28.7 | — | 0 |
  | 同上 | 60 | 50.7~51.4 | 53.3~53.5 | 0 |
  | 同上 | 120 | 113.3~113.9 | — | 0 |
  | netns 100Mbit / RTT 180ms / 0 丢包 | 30 / 60 / 90 | 28.6 / 50.5 / 83.2 | 30.1 / 52.9 / 86.9 | 0 |
  | 实链路 本机 → S1 | 20 / 40 | 18.3~18.6 / 28.2~36.5 | — | — |
  - **全部 ≤ 设定值，无超发**，瓶颈队列零丢弃。
  - 附带发现：设定 60 时稳定只到约 85%（51 / 60），30、90、120 为 93~96%；不影响本项判据，原因未查。

### D3. QUIC 反识别面 ⬜

- **来源**：`docs/quic-transport-design.md` §96、§478。
- **内容**：QUIC 路线的伪装取舍（SNI 封锁 / 首包特征 / 与 TCP-fake-TLS 的关系）需真机 +
  威胁模型共同定。
- **判据**：产出"QUIC 是否作为默认传输之一"的结论（含 `quic_obfs` 混淆有效性）。

---

## E. 抗审查泄漏测试补全（`docs/threat-model.md` §7）

### E1. T2 —— WG 上游隧道内 DNS 解析不漏到本地 ⬜

- **来源**：`docs/threat-model.md` §7；`brain/roadmap.md`。
- **内容**：需 netns 环境验证"走 WG 隧道的域名解析确实经隧道内 DNS，未漏到本地 UDP:53"。
- **判据**：隧道内 DNS 被使用；本地解析器无对应查询。

### E2. T1 —— 认证失败转发伪装站 ⬜

- **来源**：`docs/threat-model.md` §7（标注"部分"）；`brain/roadmap.md`（probe.rs 部分）。
- **内容**：把"认证失败 → 转发伪装站（会话密钥解不开其 TLS）"提成完整的场景测试。
- **判据**：探针收到的是真站的 TLS 响应，且 Mirage 侧无专属可观测差异（与 A2 互补）。

---

## F. 工程 / 供应链（非真机，但同属"需实跑验证"）

### F1. `install.sh` 二进制签名（cosign keyless）⬜

- **来源**：`brain/roadmap.md`（审计 #13）。
- **内容**：cosign keyless（Sigstore OIDC）签 `SHA256SUMS` + bundle 挂 Release，**需 CI 实跑**
  才能确认对错。
- **判据**：`cosign verify-blob` 能验过；文档步骤可复现。

### F2. orphan 过滤器验证器接回 CI ⏸️

- **来源**：`brain/pages/orphan-filter-blackhole.md`（审计 #10）。
- **理由**：需 ≥6.1 自托管 runner（GH runner 5.15 跑不了跨进程 `sk_assign`）。已记录，等条件具备。

---

## 变更记录

| 日期 | 变更 |
|---|---|
| 2026-10-06 | 建档。汇总 A1–A3（延迟预连）、B1–B3、C1–C4、D1–D3、E1–E2、F1–F2。 |
| 2026-10-06 | A1/A2 提供采集工具 `examples/probe_close_timing.rs`；A3 提供服务端 opt-in 度量 (`MIRAGE_QUIET_MEASURE=1`)。 |
| 2026-10-06 | C1/C2/C3、D1/D2 实测回填（v0.15.2-4-gcf2bb8d，netns 三段网关拓扑 + 实链路 S1）。C4 维持暂缓。 |
