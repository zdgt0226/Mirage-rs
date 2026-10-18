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

### A3（中低，竞态）`shutdown()` 用的 raw fd 会与半句柄 drop 竞争

- **位置**：`mirage_server/tcp_relay.rs`（`upstream.into_split()` 之后仍保存 `upstream.as_raw_fd()`）
- **问题**：读写半句柄先后 drop，fd 被关闭后可能被新 socket 复用；此时对端分支的 `libc::shutdown(fd)` 会打到**无关连接**上（或 EBADF）。
- **修复**：`dup()` 一份专用 fd 存进 `AtomicI32`，由第一个 `swap(-1)` 的 task 负责 `shutdown + close`；`dup` 失败保持 `-1`（闭包整体 no-op，安全降级）。

### A4（中，反指纹）握手模板：陈旧无告警 + 部分刷新导致多样性塌缩

- **位置**：`crypto/handshake_cache.rs::spawn_refresh_task`
- **问题**：① 刷新失败**静默保留旧模板**——若伪装站已轮换证书/密钥，回放的 ServerHello 与真站当前状态不一致（可区分），且无任何告警；② 部分成功时 `*cache = templates` **整体替换**：5 路 fetch 只回 1 条时，全部客户端会收到**同一个** ServerHello（被动侧可识别）。
- **修复**：`install_templates()` —— 新集更小则**与旧集合并**（保多样性 + WARN）；新增 `LAST_OK_SECS`，超过 `STALE_WARN_SECS`（6h，即连续失败 12 次）周期性 WARN 提示可能已轮换。

---

## 2. 待决策（已定位，未改）

按影响排序。这些都需要**产品/运维口径**（配置面或语义变更），故先出方案。

| # | 严重度 | 问题 | 证据 | 建议 |
|---|---|---|---|---|
| **B1** | 高（可用性） | **TCP accept 层无全局并发/接入速率上限**。每个已接受连接直接 `tokio::spawn`；保护只覆盖"**未认证转发**"（`UNAUTH_CONNS` 100/IP、`UNAUTH_RATE`、`GLOBAL_UNAUTH` 5000）。认证前窗口仅受 `hard_deadline` 5s 约束 ⇒ flood 可持有 `速率 × 5s` 的任务与 socket。QUIC 侧有 `rt_limiter.try_acquire_stream`，**TCP 侧没有**（不对称）。 | `mod.rs` accept 循环；`rt_limiter` 仅见于 QUIC 分支 | accept 前加全局 `Semaphore`（默认 10k、可配）+ 每 IP 接入速率；超限直接 RST 并计数。顺带把"未认证并发"从"转发时计数"提前到"accept 时预占"，避免 pre-judge 段无界。 |
| **B2** | 中（正确性） | **DNS 缓存 key 只含 (domain, qtype)**，未含 DO/CD 位与客户端 EDNS 缓冲大小。DO=1 的客户端可能命中 DO=0 建立的缓存（无 RRSIG、`AD` 位不对）⇒ DNSSEC 校验失败/降级；非 EDNS 客户端可能收到 >512B 的缓存响应（协议越界）。附带：响应大小取决于**别的客户端**的 flags ⇒ 可观测差异。 | `DnsCache::put/get` 仅 `(String, u16)` 作 key | key 加 DO 位（可选加 CD）；发送前按客户端 `bufsize` 截断并置 `TC=1`。 |
| **B3** | 中（放大） | **同名查询无 single-flight**：N 个并发 miss 会打 N 次上游（`udp_query` 还向**所有**上游各发一份）。冷启动/热点域名下对上游放大明显。 | `udp_query` 每轮 `for up in upstreams { send_to }` | in-flight 合并：按 (domain,qtype,DO) 记 `Notify`/broadcast，后到者等首个结果。 |
| **B4** | 中低（可观测性） | **`let _ =` 忽略关键路径错误 126 处**，其中含 DNS 回包 `send_to`、上游转发等；失败无计数、无日志 ⇒ 静默降级（例：回包 socket `ENETUNREACH`、上游 `EMSGSIZE`）。 | `grep -c 'let _ = ' src/proxy src/crypto src/api` = 126 | 对"发包/转发/写盘"三类加失败计数 + 采样 WARN；纯清理型（drop/close）保持忽略。 |
| **B5** | 低 | 凭据热重载去重比较用 `==`（`mod.rs:150/158`，`o.password == new.password`）——非恒定时间、且长度不等早退。**不在鉴权判定路径**（鉴权用 `hello_auth` 的 `ct_eq`），影响很小。 | `mod.rs:150,158` | 若追求一致，改为对定长摘要（如 SHA-256）做 `ct_eq`。 |
| **B6** | 低（性能） | 每连接 `spawn` + 每连接新建缓冲区（`Vec`/`Vec::with_capacity`），无池化。高并发下分配压力与 RSS 抖动。 | `handshake.rs`/`tcp_relay.rs`/`dns` | 与 B1 一并做：连接数上限 + `BytesMut` 复用（按 stream 分配，注意 `copy_bidirectional` 用不到）。 |

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
cargo test --lib                                  550 passed / 0 failed / 3 ignored
cargo clippy --all-targets -- -D warnings          0 warning（含 --features quic）
bash scripts/check-no-real-endpoints.sh            0 命中
```

新增单测：`dns::server::tests::response_matches_requires_question_equality`（8 条断言）。
