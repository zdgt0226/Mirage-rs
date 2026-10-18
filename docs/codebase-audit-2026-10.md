# 全库审计（2026-10）—— 纰漏与设计完善

> 范围：`src/` 97 个文件 / ≈48k 行（含 `Mirage-rs` 服务端、DNS、eBPF、API、CLI）。
> 方法：自动化扫描（panic/unsafe/锁+await/未超时 IO/资源上限/`let _ =`）→ 逐点读码确认 → 只保留**可指到行**的问题。
> 不变量：端点护栏 0 命中；协议冻结常量（`b"pyrealiy-session"`、`hkdf_suffix()`、`control.rs` 分派哨兵）不动。

---

## 1. 已修复（本轮）

### A1（高，抗探测）预连每秒限速把"对齐"降级成"不对齐"

- **位置**：`handshake.rs`（原 `PRECONNECT_RATE_PER_SEC = 30` + `try_acquire` 失败即 `disabled()`）
- **问题**：预算不足时**放弃预连**，空/半截探测于是退化为"判定时（②≈1000ms）才建连"。真站空闲计时起点从 ≈①（50~200ms）推到 ≈②（1000ms）⇒ 探测者看到的关闭偏差从 ~50ms 变成 **~1000ms**，即 **更容易被区分**。
- **关键论证**：该限速**不减少**对伪装站的总连接数 —— 被限速的探测在判定时仍会按需建连一次，只是晚了 1s。因此它没有任何负载收益，只有对齐损失。（且 >30 conn/s 的攻击者可以**故意**把节点推进这个更易识别的模式。）
- **修复**：删除每秒限速；只保留在途上限 `PRECONNECT_MAX_INFLIGHT=128`，并把"拿不到名额"改为**有界等待** `≤ PRECONNECT_TAKE_WAIT(800ms)`（名额由先完成的预连释放）⇒ 过载时是"部分对齐"而非"完全不对齐"。新增降级计数 + 每 500 次采样告警（可观测）。

### A2（中，DNS 完整性）上游响应只校验 txid+QR，未校验 question 段

- **位置**：`dns/server.rs::udp_query` / `tcp_query_one`
- **问题**：只比对 16-bit txid 与 QR 位。虽然每条查询用独立临时端口（源端口随机，实质提高了难度），但**question 比对是免费的**；一旦被接受，响应还会进 `DnsCache` **缓存一整个 TTL** ⇒ 放大为持久投毒（Kaminsky 型）。
- **修复**：新增 `response_matches()`：`txid + QR + QDCOUNT==1 + question(名/型/类) 逐字节、ASCII 大小写无关` 全等；UDP 与 TCP 两条路径都用它。附 8 条断言的单测（含"txid 对但 qname 不同必须拒""0x20 大小写随机不破匹配""截断响应拒"）。

### A3（中低，竞态）`shutdown()` 用的 raw fd 会与半句柄 drop 竞争 —— **已撤回**

- **状态**：已撤回。推演前提不成立：只有第一个 `swap(-1)` 的任务会调用 shutdown，此时它自己持有的半句柄仍存活，第二个任务看到 -1 直接跳过，故不存在 fd 复用窗口。原写法安全；dup 写法反而引入 dup 无 CLOEXEC、future 取消时 fd 泄漏令底层 socket 无法真正关闭、EMFILE 时静默失效等风险。

### A4（中，反指纹）握手模板：陈旧无告警 + 部分刷新导致多样性塌缩

- **位置**：`crypto/handshake_cache.rs::spawn_refresh_task`
- **问题**：① 刷新失败**静默保留旧模板**——若伪装站已轮换证书/密钥，回放的 ServerHello 与真站当前状态不一致（可区分），且无任何告警；② 部分成功时 `*cache = templates` **整体替换**：5 路 fetch 只回 1 条时，全部客户端会收到**同一个** ServerHello（被动侧可识别）。
- **修复**：`install_templates()` —— 设定 `BATCH=5` 与池上限 `MAX_TEMPLATES=10`；新模板数达到 BATCH（整批成功）则整体替换，部分成功则新在前旧在后拼接并截断淘汰最旧（保多样性 + WARN）；新增 `LAST_OK_SECS`，在 prewarm 与首连按需填充时补写，初值 0 防御不告警，超过 `STALE_WARN_SECS`（6h，即连续失败 12 次）周期性 WARN 提示可能已轮换。

### A5（高，可用性）TCP accept 层无全局并发上限

- **位置**：`mirage_server/mod.rs` accept 循环
- **问题**：每个已接受连接直接 `tokio::spawn`。保护只覆盖“**未认证转发**”（`UNAUTH_CONNS` 100/IP、`UNAUTH_RATE`、`GLOBAL_UNAUTH` 5000），而**认证前窗口**仅受 `hard_deadline`（5s）约束 ⇒ flood 可持有 `速率 × 5s` 个任务与 socket，把任务表/内存打满；且 QUIC 侧有 `rt_limiter`、**TCP 侧没有**（不对称）。
- **修复**：新增进程级 `Semaphore`（`tuning.max_connections`，默认 **8192**，env `MIRAGE_MAX_CONNS` 可覆盖，`0`=默认；夹到 `[16, 1e6]`）。accept 即 `try_acquire_owned`，拿不到就**直接关闭连接**并计数（每 500 次采样 WARN，提示调大上限或排查 flood）；名额持到连接结束（含握手失败与转发全程）。配置若 `<16` 由 `check` 报错（正常浏览器就有 6~8 并发，会议/下载器更多）。
- **语义**：作用域=**全进程**（多个 `mirage_server` 入站共享）；**重启生效**（信号量在首次 accept 时按配置创建）。
- **补强（复审后）**：全局上限单独存在时，单一来源约 `上限/5` 条连接每秒即可占满全部名额（认证前窗口 ≤5s），把 “内存被打满” 变成 “可用性被打满”。故 accept 时先过**来源 IP 子上限** `max(16, min(1024, 全局/4))`（IPv6 归一 /64，IPv4-mapped 先还原为 v4），再取全局名额；`rate_limit_key` 同步修正 IPv4-mapped 塌桶问题。`MIRAGE_MAX_CONNS` 非法值 WARN，启动日志打印夹取后的生效值。
- **未覆盖**：QUIC 入站仍用自身的 `rt_limiter`（按 stream 计），未共享此上限 —— 若要统一，把 permit 传给 `start_quic_server` 即可（后续项）。

### A6（中，DNS 正确性）缓存 key 缺 DO/CD 维度 + 越界下发大响应

- **位置**：`dns/server.rs::DnsCache`
- **问题**：key 只有 `(domain, qtype)` ⇒ ① `DO=1`（要 DNSSEC 签名）的客户端可能命中 `DO=0` 建立的条目（无 RRSIG）⇒ 客户端视作“无签名”/校验降级；② `CD=1`（表示“我自己校验”）的条目含上游**未验证**数据，给 `CD=0` 的客户端就是**绕过校验**；③ 条目大小按“当时那个客户端”的 EDNS 缓冲决定，`4096` 的条目可能下发给只声明 `512` 的客户端（无 EDNS/旧 resolver）⇒ 越过协议上限。附带：响应大小取决于**别的客户端**的 flags，本身构成可观测差异。
- **修复**：
  1. 缓存与单飞 key 含 UDP 缓冲档位, TC=1 响应不缓存：key 增加第 5 维 `udp_bucket`（`<=512 → 0`, `<=1232 → 1`, 否则 `2`），`put` 遇 `TC=1` 响应直接 return 不入缓存。
  2. key 包含 `(domain, qtype, DO, CD, bucket)`；新增 `edns_info()`（边界安全的 OPT 解析：`CLASS`=声明的 UDP payload，`TTL` bit15 = DO；`CD` 取 header byte3 的 `0x10`；无 OPT → `DO=0, 512`；畸形/截断安全回退）。
  3. 命中时若 `response.len() > client.max_udp` ⇒ **当作 miss**（让调用方现查一次，拿适合该客户端大小的响应）。
- **为何不用 `TC=1` 截断**：本 DNS 服务**只监听 UDP**（无 TCP:53），置 `TC` 会让客户端改走 TCP 后直接失败。故采用“宁多一次上游查询，不越界下发”。若后续补上 TCP DNS 监听，可改成标准截断 + `TC=1`。
- **代价**：key 空间增加，命中率略降；但只在同一域名被“不同 DNSSEC 意图”或不同缓冲档位的客户端访问时发生，正确性优先。

### A7（中，上游放大）DNS 查询无 single-flight

- **位置**：`dns/server.rs::direct_query` / `DnsForwarder::dns_over_tunnel`
- **问题**：N 个并发 miss 打 N 次上游；而 `udp_query` 每轮还向**所有**上游各发一份 ⇒ 放大 N×M。隧道路径更贵：**每次 miss 从 `WarmPool` 取一条隧道**，同名并发 miss 就是成倍的隧道消耗（冷启动 / 热点域名最明显）。
- **修复**：新增通用 `singleflight()`（`OnceCell` + 表，初始化完成即摘除；leader 被 cancel 时下一个等待者接替，不会卡死），缓存与单飞 key 含 UDP 缓冲档位, TC=1 响应不缓存，两处接入：
  1. `direct_query`：key = `(域名, qtype, DO, CD, bucket, 上游集合指纹)`；
  2. `dns_over_tunnel`：key = `(域名, qtype, DO, CD, bucket, 隧道 host, port, pool)`，补充出口 WarmPool 节点标识防跨出口串答案。
- **两个易错点（已处理）**：
  - 等待者拿到的是**别人 query 的**响应字节 ⇒ 必须用 `patch_for_query()` 把 tx_id + question 段换成自己的（与缓存命中同一套逻辑，顺手抽成公共函数），否则客户端因 tx_id 不匹配丢包。
  - key **必须含上游集合与出站节点**：同一域名经 CN 解析器与境外解析器或不同出站节点会给出不同答案（分流/就近调度的前提），合并就是错答案。
- **效果**：同 key 并发 miss 的上游查询数 / 隧道消耗从 N 降为 1（单测：5 并发 → 上游计数 = 1，且各自拿回自己的 tx_id；不同上游集合 → 各查 1 次、不合并；不同 bucket → 不合并）。

### A8（中低，可观测性）DNS 回包/上游发包失败无声

- **位置**：`dns/server.rs`（`run_loop` 回包、`udp_query` 上游发包）
- **问题**：两处原本是 `let _ = ...send_to(...)`。典型故障是**回程路由/防火墙丢弃 UDP**，现象是“DNS 时好时坏、页面偶发打不开”，但日志里**一行记录都没有**，只能靠抓包定位。
- **修复**：两处改为 `if let Err(e)` → 计数 + **采样告警**（每 500 次打一条，带累计值与对端地址及排查提示）。全库其余 `let _ =` 按性质归类为“有意忽略”（drop/close/关闭已死连接、fire-and-forget 通知），**不再逐个改动** —— 盲目加日志反而淹没真正信号。

---

## 2. 待决策（已定位，未改）

按影响排序。这些都需要**产品/运维口径**（配置面或语义变更），故先出方案。

| # | 严重度 | 问题 | 证据 | 建议 |
|---|---|---|---|---|
| ~~**B1**~~ | ~~高（可用性）~~ | **已修复，见 §1 A5** | — | — |
| ~~**B2**~~ | ~~中（正确性）~~ | **已修复，见 §1 A6** | — | — |
| ~~**B3**~~ | ~~中（放大）~~ | **已修复，见 §1 A7** | — | — |
| ~~**B4**~~ | ~~中低（可观测性）~~ | **已修复（最小面），见 §1 A8**：只给 DNS 回包/上游发包加计数与采样告警；其余 `let _ =` 归类为有意忽略 | — | — |
| **B5** | 低 | 凭据重载去重比较用 `==`（`mod.rs` 的 `o.password == new.password`）——非恒定时间、长度不等早退。**不在鉴权判定路径**（鉴权用 `hello_auth` 的 `ct_eq`），影响很小。 | `mod.rs` 凭据去重 | **已知待办，不改**：改动收益近零（对手需已能改配置），会在热重载路径引入无意义的哈希开销。 |
| **B6** | 低（性能） | 每连接 `spawn` + 每连接新建缓冲区，无池化。 | `handshake.rs` / `tcp_relay.rs` | **已知待办，不改**：A5 的连接上限已兜住内存上界；池化会与 `copy_bidirectional`/`split()` 的所有权模型冲突，回归风险 > 收益。 |

### 2.1 已验证**不是**缺陷（避免重复排查）

- **SSRF/元数据防护**：`net_util::egress_allowed` 在 **TCP 中继、UDP 中继、解析器**三处均生效，且在**解析后的 IP** 上判定（抗 DNS rebinding）；对 IPv4-mapped IPv6、`169.254.169.254`、`100.100.100.200`、Azure WireServer 等有专项测试。
- **看板 API**：token 恒定时间比较、按 IP 失败限流（窗口+锁定+容量上限）、DNS rebinding Host 校验、变更方法 CSRF 同源校验、`?token=` 仅限根路径与 SSE 且在文档中标注取舍。
- **AEAD/密钥**：`nonce == u64::MAX` 显式拒绝复用；cipher 切换时 (key, nonce) 整体变化；SS 客户端 salt 每条连接随机、SS-2022 校验服务端 salt 回显。
- **QUIC**：`quic_pin` **fail-closed**（未配或格式非法直接拒绝建连），SPKI 指纹校验。
- **panic 面**：`handshake.rs` 全文件仅 1 处 `expect()`（`authenticated ⇒ matched_idx`，有不变式说明）；大量 `unwrap` 集中在测试与启动期配置解析。

---

## 3. 设计层面的两点建议（非缺陷）

1. **"过载时的行为"应作为一等设计输入**：本轮 A1 揭示的规律是——*限流若只改变时序而不改变总量，就可能在安全属性上产生反效果*。建议后续所有"预算/限流"评审都加一问：**它改变的是总量还是时序？** 若只是时序，必须检查该时序是否被安全属性依赖（本例：关闭时间对齐）。
2. **可观测性优先于继续调参**：`[CH-GUARD]` 的 10 个字段已让 Phase-3→6 的争议全部靠数据收敛。同样的投入应补到 DNS（`upstream_fail_total`、`cache_hit/miss{do}`）与 accept（`accept_total`、`conn_rejected{reason}`）上——B1/B3/B4 的"沉默"正是缺这几个计数器。

---

## 4. 门禁

```
cargo test --lib                                  563 passed / 0 failed / 3 ignored
cargo test --features quic --lib                  593 passed / 0 failed / 3 ignored
cargo clippy --all-targets -- -D warnings          0 warning（含 --features quic）
bash scripts/check-no-real-endpoints.sh            0 命中
```

新增单测：`dns::server::tests::response_matches_requires_question_equality`（8 条断言）、
`edns_info_parses_do_and_bufsize`、`cache_separates_do_and_cd`、
`cache_rejects_entry_larger_than_client_budget`、`cache_skips_truncated_tc_response`、
`cache_isolates_512_and_4096_clients`、`direct_query_singleflight_coalesces_concurrent_misses`、
`singleflight_does_not_merge_different_upstream_sets`、`singleflight_does_not_merge_different_buckets`、
`crypto::handshake_cache::tests::test_merge_templates_*`（覆盖整批替换/部分合并截断/连续部分刷新/整批收缩）、
`mirage_server::conn_cap_tests::max_conns_normalization`。

---

## 5. 复跑核对清单（零成本，改完就跑）

```bash
cargo test --lib                                            # 563 passed / 0 failed / 3 ignored
cargo test --features quic --lib                            # 593 passed / 0 failed / 3 ignored
cargo clippy --all-targets -- -D warnings                   # 0
cargo clippy --all-targets --features quic -- -D warnings   # 0
bash scripts/check-no-real-endpoints.sh                     # 0 命中
```

改动对应到可观察行为的快速自检：

| 改动 | 怎么看到它在工作 |
|---|---|
| A1 预连有界等待 | 压测 >128 并发空连接时出现 `预连预算耗尽` WARN；不再出现“关闭时间突然跳到 ~1s”的台阶 |
| A2 question 校验 | 单测即可（伪造 txid 匹配但 qname 不同的响应必须被拒） |
| A3 dup fd | `ss -tnp` 下频繁开关连接不再出现“误 shutdown 其他连接”的 ECONNRESET |
| A4 模板多样性 | 伪装站不可达 6h 后出现“HandshakeCache 已 Ns 未更新” WARN；部分刷新时出现“已与旧集合并” |
| A5 连接上限 | 启动日志 `服务端并发连接上限: 8192`；打满时 `连接数达上限 ... 累计拒绝` |
| A6 缓存 DO/CD | `dig +dnssec` 与普通 `dig` 交替请求同域名，互不串味（不再出现 DO 客户端拿到无 RRSIG 的答案） |
| A7 单飞 | 并发 `dig` 同一域名，上游抓包只看到**一次**查询（隧道场景只消耗一条隧道） |
| A8 回包失败告警 | 人为封掉回程 UDP，出现 `DNS 回包失败 ... 累计 N` |
