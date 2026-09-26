# QUIC 腿服务端证书固定 (SPKI Pinning) 设计

> 状态：**定稿，已决策**（2026-09-27 用户确认 §9 三项全部按推荐执行：链接本轮不加 pin / pin 必填 fail-closed / 默认 `quic_key.pem` + SAN 沿用 `localhost`）
> 决策：用户选定 **方案 (a) SPKI 指纹固定** ——「有一定的安全性即可，并不需要为了安全性牺牲太多」。
> 范围：仅 QUIC 传输腿（实验特性 `--features quic`，默认关，release 二进制不含），可不兼容地改；不影响 TCP fake-TLS 主协议。

---

## 1. 要解决的问题

QUIC 腿现为 Model X lean：每条流 `[token 32B][2B target_len][target][data…]` **裸转发、无内层 AEAD**
（`src/proxy/mirage_server/mod.rs::handle_quic_stream_lean`），机密性与完整性全靠外层 QUIC-TLS。但外层 TLS 不认证服务端：

- 服务端证书 `src/proxy/quic.rs:225` 用 `rcgen::generate_simple_self_signed(["localhost"])` **每次启动临时生成**；
- 客户端 `src/proxy/quic.rs:211` 用 `NoVerify`（`:311`）**接受任意证书**。

→ 主动中间人可终止客户端的 QUIC-TLS，明文拿到 token、target 与全部数据，再用这个**新鲜** token 以自己的连接连服务端转发、
篡改。token 机制挡不住（它证明的是"客户端知道口令"，不是"服务端是真的"）。`docs/threat-model.md` T6 已标注本问题。

## 2. 审计发现（写方案前核实的代码事实）

| # | 事实 | 影响 |
|---|---|---|
| A1 | **`NoVerify` 连握手签名都直接放行**：`verify_tls13_signature` / `verify_tls12_signature` 均返回 `Ok`（`quic.rs:329-345`） | 若只把 `verify_server_cert` 改成比对指纹、签名仍不验，MITM 直接出示**公开的**被固定证书即可通过（无需私钥），固定形同虚设。**新 verifier 必须真正验签** |
| A2 | 证书每次启动重新生成（`quic.rs:225`） | 指纹每次重启都变，无法固定 → 必须持久化密钥 |
| A3 | rustls 0.23.45 公开 `rustls::crypto::verify_tls13_signature(msg, cert, dss, &WebPkiSupportedAlgorithms)`（`src/crypto/mod.rs:14`） | 验签可直接复用标准实现，不手写密码学 |
| A4 | 客户端取 SPKI：`webpki::EndEntityCert::try_from(&der)?.subject_public_key_info()`（rustls-webpki 0.103.15，含外层 SEQUENCE）；服务端取 SPKI：rcgen 0.13.2 `KeyPair::public_key_der()`（同为完整 SPKI SEQUENCE） | 两端对同一把密钥算出**逐字节相同**的 SPKI → 指纹一致。rustls-webpki 已在依赖树中，只需在 `quic` 特性下声明为直接依赖，**不引入新 crate** |
| A5 | rcgen 可 `KeyPair::from_pem` 读回私钥、`CertificateParams::self_signed(&key)` 重新签发 | 只持久化**私钥**即可：每次启动用同一私钥重签证书，SPKI（公钥）不变 |
| A6 | `mirage://` 链接只含 `密码@host:port?sni=`（`src/node_uri.rs:80-100`），**不携带 transport / quic_obfs** | QUIC 出站本就需手工配 `transport: "quic"` 等字段；只给链接加 `pin` 只解决一半（见 §9 Q1） |
| A7 | `install.sh` 无任何 QUIC 配置流程；release 不含 quic 特性 | 本轮**不改 install.sh** |

## 3. 方案规格

### 3.1 服务端：持久化私钥

- `mirage_server` 入站新增 `quic_key_path: Option<String>`；缺省 `"quic_key.pem"`，相对进程工作目录（systemd 部署下
  `WorkingDirectory=/var/lib/mirage-rs` → `/var/lib/mirage-rs/quic_key.pem`）。仅 `transport: "quic"` 时使用。
- 启动（`server_endpoint`）逻辑：
  1. 文件存在 → `KeyPair::from_pem` 读取；**读取或解析失败 → 启动报错退出**，不静默重新生成
     （否则指纹悄悄改变，所有客户端连不上且原因难查）。
  2. 文件不存在 → 生成新私钥（rcgen 默认 ECDSA P-256），**以 0600 原子写入**（`.tmp` + rename，同 `atomic_write_config`
     的写法）。
  3. 用该私钥重新自签证书（SAN 沿用 `localhost`，见 §9 Q3），装入 rustls ServerConfig。
- 启动日志以 `info` 打印一行：`QUIC 服务端证书指纹 (quic_pin): <指纹>`。

### 3.2 指纹

- `pin = base64url_nopad( SHA-256( SPKI DER ) )`，固定 43 字符。
- 用 SPKI 而非整张证书：证书每次启动重签（序列号/有效期会变），公钥不变；将来续期或改 SAN 也不需要重新分发指纹。
- 实现一个共用函数 `spki_pin(spki_der: &[u8]) -> String`（放 `quic.rs`），服务端与客户端、CLI、测试都用它，杜绝两端编码不一致。

### 3.3 分发

- **启动日志**（§3.1）。
- **CLI**：新增子命令 `mirage-rs quic-pin -c <服务端配置>`：读取该配置中 `mirage_server` 的 `quic_key_path`，
  私钥存在则打印指纹；不存在则**生成并保存**后打印（便于先拿到指纹再起服务）。不启动任何服务、不联网。
- **客户端配置**：Mirage 出站新增 `quic_pin: Option<String>`（上述 43 字符）。

### 3.4 客户端校验：`PinnedVerifier`（替换 `NoVerify`，删除后者）

```text
verify_server_cert(end_entity, ..):
    spki = webpki::EndEntityCert::try_from(end_entity)?.subject_public_key_info()
    若 spki_pin(spki) 与配置的 pin 常数时间比较不等 → Err(证书不匹配)，握手失败
    不校验证书链 / 域名 / 有效期（自签，认证只靠 pin）

verify_tls13_signature(msg, cert, dss):
    rustls::crypto::verify_tls13_signature(msg, cert, dss, &ring 提供者的 signature_verification_algorithms)
    ← 关键：证明对端持有被固定公钥对应的私钥（修 A1）

verify_tls12_signature(..):
    同上走 rustls::crypto::verify_tls12_signature（客户端只启用 TLS1.3，正常不会调到，但不得返回无条件 Ok）

supported_verify_schemes(): 沿用 ring 提供者的 supported_schemes()
```

`QuicMux`（`quic.rs:169` 懒建 endpoint 时调 `client_config`）增加 pin 参数，由 `PoolConfig` 从出站配置传入。

### 3.5 未配 pin：强制必填、失败即断

- `transport: "quic"` 的 Mirage 出站**缺 `quic_pin` 或格式非法**（非 43 位 base64url）→ `mirage-rs check` 报语义问题；
  运行时拒绝建立 QUIC 连接并打印明确错误（fail-closed）。**不存在"未配就不验证"的回退路径**。
- QUIC 腿未进 release，无存量用户，强制必填没有兼容负担。

### 3.6 轮换

删除（或替换）服务端 `quic_key.pem` → 重启生成新密钥 → `mirage-rs quic-pin` 取新指纹 → 更新所有客户端的 `quic_pin`。
旧指纹的客户端握手失败（fail-closed），日志提示"证书指纹不匹配，服务端可能已轮换密钥或遭中间人攻击"。

## 4. 安全性评估

| 场景 | 结果 |
|---|---|
| 主动中间人终止客户端 QUIC-TLS | 中间人没有服务端私钥：出示自己的证书 → 指纹不符；出示服务端的证书 → 无法完成握手签名 → **握手失败，客户端不发送任何 token/target/数据** ✅ |
| 指纹泄露 | 无害（公钥的摘要） |
| 服务端私钥泄露 | 攻击者可冒充服务端 → 私钥 0600，泄露时按 §3.6 轮换 |
| 主动探测者直连服务端 | 能看到固定的自签证书（`CN=localhost`）；持久化后跨重启不变，可被关联。**缓解：同时启用 `quic_obfs`**（不知道混淆口令的探测者连 QUIC Initial 都解不出） |
| 被动观察 | TLS1.3 证书在加密的 Handshake 包内，不可见 |

残余：不提供前向的"服务端吊销"通知机制（轮换即需人工更新客户端）——按用户"有一定安全性即可"的取舍接受。

## 5. 改动文件清单

| 文件 | 改动 |
|---|---|
| `Cargo.toml` | `quic` 特性加入 `dep:rustls-webpki`（0.103，已在依赖树中） |
| `src/proxy/quic.rs` | `server_endpoint` 加载/生成持久化私钥并重签证书；`spki_pin()`；`PinnedVerifier` 替换 `NoVerify`；`client_config` / `QuicMux` 接收 pin |
| `src/config.rs` | 入站 `quic_key_path`、出站 `quic_pin`；`semantic_issues` 校验 pin 必填与格式 |
| `src/proxy/mirage_server/mod.rs` | 传 `quic_key_path` 给 `server_endpoint` |
| `src/proxy/pool.rs`（及构造 `PoolConfig` 的出站代码） | 把 `quic_pin` 传给 `QuicMux` |
| `src/bin/mirage.rs` | 新增 `quic-pin` 子命令 |
| `templates/*.jsonc` | 注释示例补 `quic_pin` / `quic_key_path` |
| `docs/threat-model.md` | T6 中 QUIC 条改为"已 pinning"，说明残余（§4） |
| `CHANGELOG.md` / `README.md` | 条目与 QUIC 段落说明 |

## 6. 测试计划

1. **指纹一致性**：同一 rcgen 私钥，`spki_pin(key.public_key_der())` == 客户端从其自签证书经 webpki 解析出的 SPKI 指纹。
2. **编码**：指纹为 43 字符 base64url；非法 pin 被 `check` 报出。
3. **错误 pin 拒绝**：`PinnedVerifier` 对指纹不符的证书返回错误。
4. **签名校验回归（关键）**：用服务端 A 的证书、但以另一把私钥 B 签握手消息 → `verify_tls13_signature` 必须失败
   （锁住 A1，防止将来有人把验签改回无条件 `Ok`）。
5. **端到端**：进程内起 QUIC 服务端 + 客户端，正确 pin 能建流；错误 pin 握手失败且客户端未发出任何流数据。
6. **MITM 回归**：进程内中间人用自有自签证书终止客户端连接 → 客户端握手失败。
7. **持久化**：两次启动指纹不变；私钥文件权限 0600；私钥文件损坏 → 启动报错而非重新生成。

以上均在 `--features quic` 下运行（CI 的 `cargo test --features quic --lib` 已覆盖该特性）。

## 7. 未采纳方案

- **(b) 口令绑定的通道证明**（TLS exporter + 双向 HMAC）：无需分发、天然多用户，但每条连接多一个往返，且要设计新的握手帧；
  超出"有一定安全性即可"的预算。
- **(c) (a)+(b) 组合**：复杂度最高，收益边际。

## 8. 与其它文档的关系

- 与 v0.15 TCP 主协议（`docs/protocol-freshness-design.md`）互不影响：本方案只动 QUIC 外层 TLS 的证书与校验。
- QUIC lean 每流 token 仍用 `QUIC_LEAN_BIND` 域分隔（`src/crypto/hello_auth.rs`），不变。
- 实现后更新 memory「QUIC Leg Auth Gap」：缺口由 pinning 关闭（QUIC 转正前置条件之一达成）。

## 9. 已决策（用户确认按推荐）

| # | 问题 | 决策 |
|---|---|---|
| Q1 | `mirage://` 链接是否加 `&pin=` | **本轮不加**。链接目前连 transport / quic_obfs 都不带（A6），单加 pin 只解决一半；等将来做"QUIC 节点链接"时 transport、obfs、pin 一并加入 |
| Q2 | QUIC 出站未配 pin 时 | **强制必填、fail-closed**（§3.5）。QUIC 未进 release，无兼容负担 |
| Q3 | 私钥默认路径与证书 SAN | 默认 `quic_key.pem`（相对工作目录，systemd 下落在 `/var/lib/mirage-rs/`）；SAN **沿用 `localhost`**（改成伪装域名对探测者同样可疑，且自签无论如何可辨；靠 `quic_obfs` 缓解） |
