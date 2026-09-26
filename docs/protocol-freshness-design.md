# Mirage 协议新鲜度与会话安全加固设计 (阶段 2: Protocol Freshness & Replay Hardening)

> 状态：**定稿，已实现**（分支 `feat/protocol-v2-freshness`）—— 用户决策：**v0.15 协议断代，不兼容任何旧协议**。初稿由 agy 生成，经审阅对照代码修正（标注「审阅补充/纠正」）。  
> 目标版本：`v0.15.0`  
> 责任范围：协议层密码学加固（非 PFS 模式新鲜度注入、Cipher Agility 密钥隔离、抗重放与抗降级）  
> 约束红线：**协议改造必须保持 fake-TLS 线上可观测字节形状与长度 100% 不变**（只变 random / session_id 的取值，二者本就是随机字节）。

---

## 1. 概述与设计背景

Mirage-rs 作为一款抗审查高性能透明代理，其核心伪装机制建立在对真实 TLS 握手特征的严格仿真（fake-TLS）与内层多路复用（Multiplexing/WarmPool）之上。

在当前实现（`v0.14.1`）中，审查者通过被动指纹和主动探测已被 [[threat-model]]（T1–T5）有效防御。然而，通过对核心密码学模块（`src/crypto/`）与握手/控制流（`src/proxy/`）的深度代码审计，发现了两个属于 **P1 级别** 的协议设计缺陷：

1. **P1-A（非 PFS 模式下缺失服务端新鲜性）**：非 PFS 模式下，会话主密钥由客户端随机数及口令单向决定，`ClientHello.session_id`（认证 Token）的 MAC 未覆盖 `ClientHello.random`，且服务端下发的 `ServerHello.random` 未参与密钥派生。导致主动中间人可通过替换 Random 实施跨会话重放与 Two-Time Pad（密钥流复用）解密攻击；
2. **P1-B（Cipher Agility 协商 ChaCha20 时的 (Key, Nonce) 复用）**：当开启密码套件敏捷协商（`tuning.cipher_agility: true`）且两端协商决定维持 ChaCha20-Poly1305 时，`rekey()` 派生出与引导阶段完全相同的密钥，并将 Nonce 强制归零，导致 `TIME_SYNC`/`CIPHER_ACK` 与后续数据包发生严重的密钥流重用与 Poly1305 认证密钥泄露。

本设计旨在彻底消除上述两个 P1 协议隐患，建立完整的双向新鲜度保证，并给出零可观测特征变化的落地路径（v0.15 协议断代，见 §4）。

---

## 2. 问题分析与根因判定

### 2.1 P1-A 非 PFS 模式缺失服务端新鲜性

#### 2.1.1 代码路径与根因定位

在非前向保密模式（`pfs: false`，默认配置）下，连接生命周期的密钥派生与握手校验逻辑如下：

1. **主密钥派生只依赖 `client_random`**：  
   根据 [src/crypto/aead.rs#L29-L38](file:///opt/Mirage-rs/src/crypto/aead.rs#L29-L38)，主密钥由 `derive_master(password, salt)` 计算，其中 `salt` 传入的是 `client_random`；在 [src/crypto/aead.rs#L364-L376](file:///opt/Mirage-rs/src/crypto/aead.rs#L364-L376) 的 `create_crypto_pair` 中直接将 `client_random` 作为唯一 salt。服务端在 [src/proxy/mirage_server/control.rs#L55-L61](file:///opt/Mirage-rs/src/proxy/mirage_server/control.rs#L55-L61) 同样调用 `create_crypto_pair(..., &password, &client_random, false)`。
2. **Token MAC 未绑定 `ClientHello.random`**：  
   客户端在 `ClientHello.session_id` 中携带 32 字节 Token。根据 [src/crypto/hello_auth.rs#L19-L53](file:///opt/Mirage-rs/src/crypto/hello_auth.rs#L19-L53)：
   $$\text{Token} = \text{prefix}(8) \parallel \text{hidden\_ts}(8) \parallel \text{tag}(16)$$
   其中：
   $$\text{one\_time\_key} = \text{SHA256}(\text{password} \parallel \text{ts} \parallel \text{prefix})$$
   $$\text{tag} = \text{Poly1305}_{\text{one\_time\_key}}(\text{ts})$$
   `poly1305_tag` 的输入只有 `password`、`ts` 和 `random_prefix`，**完全不包含 `ClientHello.random`（32 字节）**。
3. **服务端认证与解包解耦**：  
   服务端握手处理位于 [src/proxy/mirage_server/handshake.rs#L124-L149](file:///opt/Mirage-rs/src/proxy/mirage_server/handshake.rs#L124-L149)。服务端从 `body[39..71]` 取出 `session_id`，调用 `verify_session_token(pw, &sid_array, auth_ts_tolerance_secs)`。只要该 Token 时间戳在 $\pm 60\text{s}$ 容差内且未在 `REPLAY_CACHE` 中，认证即通过；随后服务端直接从 `body[6..38]` 提取 `client_random`。
4. **服务端的 `ServerHello.random` 未参与密钥计算**：  
   虽然在 `v0.13.1` 中，服务端通过 [src/crypto/handshake_cache.rs#L272-L280](file:///opt/Mirage-rs/src/crypto/handshake_cache.rs#L272-L280) 的 `apply_server_random` 对每个回放模板的 `ServerHello.random` 填充了全新的 `rand::fill`，但该随机数在非 PFS 模式下**从未**传给 `control.rs`，也**从未**参与任何 HKDF 密钥派生。

#### 2.1.2 攻击场景

- **场景 1：主动中间人篡改 Random 实施会话重放与 Two-Time Pad**  
  假设合法客户端曾发起会话 1，明文包含请求 $M_1$，`ClientHello` 携带随机数 $R_1$ 与 Token $T_1$，派生密钥 $K_{c2s}^{(1)}, K_{s2c}^{(1)}$，中间人录制了全部上行密文 $C_1 = \text{AEAD}_{K_{c2s}^{(1)}}(N=0, M_1)$ 与服务端响应 $S_1 = \text{AEAD}_{K_{s2c}^{(1)}}(N=0, \text{TIME\_SYNC}) \dots$。  
  稍后，合法客户端发起新鲜会话 2，携带新鲜随机数 $R_2$ 与新鲜 Token $T_2$。  
  主动攻击者拦截会话 2 的 `ClientHello`，将报文中的 $R_2$ 替换为历史的 $R_1$，而保留新鲜的 $T_2$：
  1. 服务端收到篡改报文，校验 $T_2$ 成功（时间戳新鲜，tag 正确，且未曾见过）；
  2. 服务端提取 `client_random` 为 $R_1$；
  3. 服务端计算 $\text{derive\_master}(\text{password}, R_1)$，派生出的会话主密钥恰好是 $K^{(1)}$；
  4. 攻击者向服务端重放会话 1 的上行数据 $C_1$：服务端由于密钥一致且 Nonce 从 0 开始，**完全能够成功解密并执行该请求**；
  5. 服务端向下行发送新的会话响应 $S_2$（Nonce 从 0 起）：由于 $S_1$ 与 $S_2$ 使用了相同的密钥 $K_{s2c}^{(1)}$ 与相同的 Nonce 序列，攻击者通过 $S_1 \oplus S_2$ 立即获得 $M_{s2c}^{(1)} \oplus M_{s2c}^{(2)}$（Two-Time Pad 密钥流复用），同时 Poly1305 单次密钥被复用，攻击者可推导认证密钥并伪造后续密文。
- **场景 2：服务端重启窗口内的重放攻击**  
  服务端的 `TokenReplayCache` 是纯内存结构（[src/crypto/hello_auth.rs#L125](file:///opt/Mirage-rs/src/crypto/hello_auth.rs#L125) `static REPLAY_CACHE: OnceLock<TokenReplayCache>`）。若服务端因升级、崩溃或运维重启，内存缓存清空。在重启前的容差窗口（默认 60s）内录制的会话，中间人可原样重放整个 TCP 连接，服务端认证通过、派生出同款密钥并再次执行历史流量。

#### 2.1.3 PFS 模式为什么不受影响

开启 PFS 时（`pfs: true`，见 [src/crypto/pfs.rs](file:///opt/Mirage-rs/src/crypto/pfs.rs)）：
- `ClientHello.random` 承载客户端临时 X25519 公钥 $C_{pk}$；
- 服务端生成一次性私钥并将其临时公钥 $S_{pk}$ 填入 `ServerHello.random`；
- [src/crypto/aead.rs#L384-L392](file:///opt/Mirage-rs/src/crypto/aead.rs#L384-L392) 的 `derive_master_pfs` 将 ECDH 共享秘密 $\text{X25519}(S_{sk}, C_{pk})$ 混入 IKM。  
因为服务端私钥 $S_{sk}$ 每连接随机且用完即弃，即便中间人替换或重放历史的 $C_{pk1}$，服务端算出的 ECDH 共享秘密依然是全新的，攻击者无法解密也无法使服务端派生出历史密钥。

---

### 2.2 P1-B Cipher Agility 协商 ChaCha20 时的 (Key, Nonce) 复用

#### 2.2.1 代码路径与根因定位

Cipher Agility（[src/crypto/cipher.rs](file:///opt/Mirage-rs/src/crypto/cipher.rs)）允许两端在握手后的首包内协商是否升级至 AES-256-GCM：

1. **`hkdf_suffix` 对 ChaCha20 为空**：  
   查看 [src/crypto/cipher.rs#L41-L46](file:///opt/Mirage-rs/src/crypto/cipher.rs#L41-L46)：
   ```rust
   pub fn hkdf_suffix(self) -> &'static [u8] {
       match self {
           Cipher::ChaCha20Poly1305 => b"", // 保持与旧版一致 (info="c2s"/"s2c" 不变, 向后兼容)
           Cipher::Aes256Gcm => b"-aes256gcm",
       }
   }
   ```
2. **`expand_key` 计算无域分隔**：  
   查看 [src/crypto/aead.rs#L43-L52](file:///opt/Mirage-rs/src/crypto/aead.rs#L43-L52)：
   ```rust
   let mut full_info = Vec::with_capacity(info.len() + 10);
   full_info.extend_from_slice(info);
   full_info.extend_from_slice(cipher.hkdf_suffix());
   hk.expand(&full_info, &mut okm).unwrap();
   ```
   当 `cipher` 为 `ChaCha20Poly1305` 时，`full_info` 依然是 `b"c2s"` 或 `b"s2c"`。这意味着此时计算出的 Key 与连接初始 Bootstrap 使用的 Key **在字节级别 100% 相同**。
3. **`rekey()` 强制归零 Nonce**：  
   查看 [src/crypto/aead.rs#L122-L127](file:///opt/Mirage-rs/src/crypto/aead.rs#L122-L127) 与 [#L271-L276](file:///opt/Mirage-rs/src/crypto/aead.rs#L271-L276)：
   ```rust
   pub fn rekey(&mut self, cipher: Cipher) {
       let info: &[u8] = if self.is_initiator { b"c2s" } else { b"s2c" };
       self.cipher = expand_key(&self.master, info, cipher);
       self.cipher_kind = cipher;
       self.nonce = 0; // ⚠️ 致命归零
   }
   ```
4. **触发路径**：  
   当开启 `tuning.cipher_agility: true` 时，服务端与客户端交互时序如下（见 [control.rs#L134-L158](file:///opt/Mirage-rs/src/proxy/mirage_server/control.rs#L134-L158) 与 [pool.rs#L691-L707](file:///opt/Mirage-rs/src/proxy/pool.rs#L691-L707)）：
   - 服务端发出 `TIME_SYNC` 帧（$s2c$ 方向，Key = $K_{s2c}$，**$\text{Nonce} = 0$**）；
   - 客户端发出 `CIPHER_NEGO` 帧（$c2s$ 方向，Key = $K_{c2s}$，**$\text{Nonce} = 0$**）；
   - 服务端发出 `CIPHER_ACK` 帧（$s2c$ 方向，Key = $K_{s2c}$，**$\text{Nonce} = 1$**）；
   - 两端调用 `negotiate()`：若客户端或服务端任一方不支持硬件 AES 加速，协商结果判定为 `Cipher::ChaCha20Poly1305`；
   - 两端无条件执行 `writer.rekey(ChaCha20Poly1305)` 与 `reader.rekey(ChaCha20Poly1305)`；
   - 此时，两端 Nonce 均归零，密钥维持原样！
   - 客户端立即发送实际目标地址首帧（Target Frame），使用 Key = $K_{c2s}$，**$\text{Nonce} = 0$**；
   - 服务端向客户端返回数据，使用 Key = $K_{s2c}$，**$\text{Nonce} = 0$**。

#### 2.2.2 安全后果与单测盲区

- **灾难性后果**：  
  在 $c2s$ 方向上，`CIPHER_NEGO`（格式固定，明文已知）与用户的 Target 帧（包含目标域名和端口）使用了完全相同的 $(K_{c2s}, \text{Nonce}=0)$。攻击者仅需将两个密文异或，即可直接解出 Target 目标明文！同时，Poly1305 的 One-time Key 被重复使用，导致整个连接的完整性校验形同虚设。
- **单测盲区剖析**：  
  现存单测 [tests/test_cipher_agility.rs#L76-L80](file:///opt/Mirage-rs/tests/test_cipher_agility.rs#L76-L80) 包含了 `one_side_no_aes_stays_chacha` 测试用例。该测试在模拟协商为 ChaCha20 后，断言两端能正常解密 `ECHO-BODY`。然而，因为 `LessSafeKey` 并不检测全局历史 Nonce 重复，只要发送端和接收端步调一致地归零，解密就能成功。单测只验证了"功能通不通"，完全漏掉了"底层密钥流是否复用"的安全断言。

---

## 3. 协议加固方案对比与设计抉择

### 3.1 P1-A 候选方案对比评估

为了给非 PFS 模式注入新鲜度并消除重放风险，针对以下 4 个方案进行系统权衡：

- **方案 (a)：将 `ServerHello.random` 混入会话主密钥**  
  派生时将 salt 改为 `client_random || server_random`（64 字节）。
- **方案 (b)：将 `ClientHello.random` 绑进 Token 的 MAC**  
  修改 Token tag 计算方式，使 `tag = Poly1305(key, ts || client_random)`。
- **方案 (c)：两者都做（方案 a + 方案 b）**  
  Token 强校验 `client_random`，同时主密钥派生混入 `server_random`。
- **方案 (d)：直接默认开启 PFS**  
  废弃/弃用非 PFS 模式，全面强制 X25519 ECDH。

#### 5 大维度对比矩阵

| 评估维度 | 方案 (a) 仅混入 Server.random | 方案 (b) 仅 Token 绑定 Client.random | 方案 (c) 两者都做 ⭐ (推荐) | 方案 (d) 默认开 PFS |
|---|---|---|---|---|
| **防 Random 替换攻击** | ✅ **能防御**（服务端 $S_{rand}$ 新鲜，派生密钥不一致，旧会话无法解密） | ✅ **能防御**（篡改 Random 导致 Token MAC 校验失败，握手直接被拒） | ✅ **双重防御**（握手阶段立即 fail-closed，且密钥派生具备双向新鲜度） | ✅ **能防御**（临时密钥对单次有效，替换导致 ECDH 失败） |
| **防重启后窗口内重放** | ✅ **能防御**（重启后服务端生成新 $S_{rand}$，旧连接密文无法被新密钥解密） | ❌ **无法防御**（重启后 ReplayCache 清空，录制的合法 $(R_1, T_1)$ 可再次通过） | ✅ **彻底解决**（即使重放缓存丢失，新鲜的 $S_{rand}$ 保证新旧会话密钥完全绝缘） | ✅ **彻底解决**（服务端新 $S_{sk}$ 导致旧会话 ECDH 必然不同） |
| **fake-TLS 指纹影响** | ✅ **零影响**（$S_{rand}$ 现网已是 `rand::fill`，字节形状/长度无变动） | ✅ **零影响**（Token 保持 32 字节，Poly1305 只是增加哈希输入长度） | ✅ **零影响**（双端协议报文线上长度、格式、伪装特征 100% 保持现状） | ⚠️ **需审视**（客户端发出的 ClientHello.random 必须做最高位掩码抗指纹） |
| **客户端获取 Server.random 成本** | ✅ **零新增网络开销**（客户端代码已内置提取逻辑，见下文分析） | ✅ **无需提取** | ✅ **零新增开销**（复用已有解析能力） | 需执行 X25519 标量乘法运算 |
| **计算开销与复杂度** | 低（仅增加 HKDF 少量输入） | 低（Poly1305 吸收 40 字节代替 8 字节） | **极低**（仅涉及微秒级对称哈希与内存拼接） | 中（每连接 1 次 X25519 标量乘法，低端 MIPS/老 ARM 路由有一定压力） |

#### 客户端获取 `ServerHello.random` 的可行性核实

通过对客户端源码的实际审查，确认**客户端现已具备无缝获取 `ServerHello.random` 的能力**：
查看 [src/proxy/pool.rs#L281-L354](file:///opt/Mirage-rs/src/proxy/pool.rs#L281-L354) 的 `read_server_handshake` 函数：
```rust
// src/proxy/pool.rs:312-324
else if ct == 0x16 {
    // 首个 ServerHello: 捕获 random (body[6..38])。ServerHello body 布局:
    // [0x02 type][3B len][2B version][32B random]... → random 在 [6..38]。
    if !saw_sh && body.len() >= 38 {
        server_random.copy_from_slice(&body[6..38]);
    }
    saw_sh = true;
}
```
并且在 [src/proxy/pool.rs#L825](file:///opt/Mirage-rs/src/proxy/pool.rs#L825) 的 `do_fake_tls` 中：
```rust
let server_random = read_server_handshake(rh).await?;
```
在现有代码中，无论是否开启 PFS，`read_server_handshake` 都会准确捕获并返回 `server_random`（非 PFS 模式下此前只是未存入 `ClientHandshake` 结构体）。

> **审阅补充 —— 两个实现约束**：
> 1. **客户端必须 fail-closed**：pool.rs ~320 注释指出，ServerHello 被拆到首条 record 且不足 38B 时 (极罕见) 捕获不到, `server_random` 保持全 0。现在非 PFS 下这无所谓 (不用它), 但 v2 下若拿全 0 参与派生, 与服务端必然失配 (或更糟: 若服务端某路径也回落 0 则新鲜性失效)。v2 会话捕获失败必须**直接断开**, 不得用 0 派生 (PFS 分支 ~835 已有同类判断, 照做)。
> 2. **服务端必须把"实际发出的" ServerHello.random 传到密钥派生**：当前 `apply_server_random` (handshake_cache.rs) 生成后即写入回包, 未传给 control.rs。v2 需把这 32 字节沿 handshake → control 管道传下去, 且必须是**线上实际发出的那份** (模板回放/补丁路径都要覆盖)。PFS 下它即服务端临时公钥, 已有管道可复用。因此，实现方案 (a) 与方案 (c) **在客户端完全无需新增任何 TLS 解析逻辑或协议往返，仅需将已捕获的 `server_random` 传递至密钥派生函数**。

#### 推荐方案与决策理由

**强烈推荐采用方案 (c)：两者都做。**
- **理由 1：深层防御（Defense-in-Depth）**  
  若仅做 (a)，中间人篡改 Random 虽无法解密后续报文，但服务端的 Token 认证却会先判定为成功，导致服务端为非法连接分配隧道资源并回发 `ServerHello`，直至第一帧解密失败才断开；而方案 (c) 在 `handshake.rs` 首包校验阶段即发现 MAC 不符，直接转伪装站，时序行为与真实非 Mirage 探针完全一致（符合 [[threat-model]] T1 与 T5）。
- **理由 2：彻底堵死服务端重启重放**  
  方案 (b) 无法防御单点重启后的 60s 内存重放窗口；只有引入服务端贡献的 $S_{rand}$（方案 a/c），才能从数学上保证即使服务端重放缓存被清空，重放的历史会话也绝不可能派生出匹配的解密密钥。
- **为什么不直接一步到位切到方案 (d)（纯 PFS）？**  
  1. PFS 需两端同开且每连接多一次 X25519，强制它等于替用户做部署决策（v0.15 仍保留 PFS 为可选项，新鲜性由 (c) 在两种模式下都保证）；
  2. 低端嵌入式网关（如 MT7621 等无 NEON 的 MIPS 架构）在瞬间高并发建连时，X25519 可能会造成 CPU 尖刺；方案 (c) 提供极佳的对称加密性能。方案 (d) 可作为长期演进终态，但阶段 2 必须给基础协议补齐对称层面的根本安全。

---

### 3.2 P1-B 修复方案对比评估

针对 Cipher Agility 协商结果为 ChaCha20 时的密钥复用，评估以下两种方案：

#### 方案 1：协商结果等于当前 Cipher 时，跳过 `rekey`，保持 Nonce 递增
- **原理**：  
  Bootstrap 阶段初始使用的即是 ChaCha20-Poly1305。若 `negotiate()` 决策出的最终套件依然是 `Cipher::ChaCha20Poly1305`，说明算法未发生变更。此时**不调用 `rekey()`，也不归零 Nonce**，连接继续沿用当前的密钥，Nonce 自然累加（$c2s$ 发送 Target 时使用 Nonce=1；$s2c$ 回包时使用 Nonce=2）。
- **优点**：  
  完全符合流密码/AEAD 的单调递增规范；零额外密钥派生计算开销；实现最简洁可靠。

#### 方案 2：`rekey` 引入独立域分隔后缀（HKDF Info 分隔）
- **原理**：  
  修改 [src/crypto/cipher.rs#L41-L46](file:///opt/Mirage-rs/src/crypto/cipher.rs#L41-L46)，将 `ChaCha20Poly1305` 的 `hkdf_suffix` 由 `b""` 修改为区分阶段的后缀。例如初始 Bootstrap 使用 `b"-bootstrap"`，协商后再 rekey 使用 `b"-chacha20-rekey"`。
- **优点**：  
  即使 Nonce 归零，由于 Key 彻底改变，也不会构成同一密钥下的 Nonce 复用。
- **缺点**：  
  破环了与未升级对端的字节兼容性；且如果在已经用过一次 key 的通道上平滑更换 key，容易引入额外的派生延迟。

#### 推荐方案：方案 1（主逻辑）+ `rekey()` 内部防呆（双保险）

1. **核心逻辑（方案 1）**：在 [control.rs](file:///opt/Mirage-rs/src/proxy/mirage_server/control.rs) 与 [pool.rs](file:///opt/Mirage-rs/src/proxy/pool.rs) 的协商代码中，显式增加守卫：
   ```rust
   if final_cipher != self.cipher_kind {
       writer.rekey(final_cipher);
       reader.rekey(final_cipher);
   }
   // 若 final_cipher == cipher_kind (即保持 ChaCha20)，不调 rekey，保持 nonce 递增
   ```
2. **防呆双保险**：在 `CryptoWriter::rekey` 与 `CryptoReader::rekey` 内部增加保护断言：若目标 `cipher` 与当前 `self.cipher_kind` 完全相同，直接 `debug_assert!` 并静默无视或维持 Nonce，防止其他外部调用者误用导致灾难性重置。
3. **无需按会话版本门控**：审阅时曾指出「跳过 rekey」若与仍会 rekey 归零的旧对端混跑会 nonce 错位；v0.15 **协议断代**后新旧版本根本无法完成握手（token/密钥派生都不同），不存在混跑，故新行为对所有会话生效。

---

## 4. 协议断代与版本策略（最终决策）

**决策：v0.15 起只存在一套协议，不做任何向后兼容**（用户："不完善的协议趁早断舍离"）。草稿中的双轨校验、`enforce_freshness` 开关、客户端 `legacy_server` 回退全部**作废**，也不再有降级面可分析。

### 4.1 时序约束（保留的关键论证）

`TIME_SYNC` 本身是一条 AEAD 加密帧，会话密钥必须在它之前就确定；因此"用哪套规则派生密钥"只能由握手明文段（ClientHello / ServerHello）决定，不能靠 `TIME_SYNC.proto_ver` 协商。断代方案天然满足：只有一套规则，无需协商。

### 4.2 v0.15 协议规格

| 项 | v0.15 规格 | 说明 |
|---|---|---|
| Token 布局 | `prefix(8) ‖ hidden_ts(8) ‖ tag(16)` = 32B | 布局、长度、`hidden_ts` 计算与旧版相同 |
| 一次性 Poly1305 key | `SHA256(password ‖ ts ‖ prefix ‖ "mirage-token-v2")` | `TOKEN_DOMAIN` 版本域分隔 |
| tag | `Poly1305(key, ts ‖ bind)` | TCP fake-TLS: `bind = ClientHello.random`；QUIC lean: `bind = "mirage-quic-lean-v2"`（`QUIC_LEAN_BIND`，两种 token 互不可冒用） |
| 会话主密钥 (非 PFS) | `HKDF-SHA256(salt = client_random ‖ server_random, ikm = password, info = "mirage-session-v2")` | server_random = 线上实际发出的 ServerHello.random |
| 会话主密钥 (PFS) | 同 salt，`ikm = password ‖ ecdh`，`info = "mirage-session-v2-pfs"` | PFS 下 server_random 即服务端临时公钥 |
| server_random 全 0 | **客户端与服务端都 fail-closed** | 服务端：模板未写入 random 即拒绝连接（防攻击者扮客户端时派生退化）。前提：伪装模板首条 0x16 record 含完整 ServerHello.random（≥38B，真实服务器几乎不拆），否则 fail-closed（可用性，非安全） |
| cipher agility | 协商结果 == 当前 cipher 时不 rekey；`rekey()` 只允许 bootstrap ChaCha20 → 其它 cipher，拒绝同 cipher 与回切 ChaCha20 | 修 P1-B（回切会重派 bootstrap 密钥 + nonce 归零） |

实现位置：`src/crypto/hello_auth.rs`（token）、`src/crypto/aead.rs`（`derive_master` / `derive_master_pfs`、rekey 防呆）、`src/crypto/handshake_cache.rs`（`apply_server_random` 返回实际写入的 random）、`src/proxy/mirage_server/handshake.rs`（bind 校验 + server_random 全 0 拒绝）、`src/proxy/mirage_server/control.rs` 与 `src/proxy/pool.rs`（派生 + agility）、`src/proxy/pool.rs::read_server_handshake`（客户端全 0 fail-closed）、`src/proxy/probe.rs`、QUIC lean 两端（`mirage_server/mod.rs`、`handler.rs`、`outbound.rs`）。

### 4.3 新旧版本互连行为

| 组合 | 结果 |
|---|---|
| 旧客户端 → v0.15 服务端 | 旧 token 的 tag 不含 bind/域分隔 → 校验失败 → 转伪装站（与任何非 Mirage 探针无异） |
| v0.15 客户端 → 旧服务端 | 旧服务端按旧公式校验 → 失败 → 转伪装站；客户端表现为握手失败 |
| v0.15 ↔ v0.15 | 正常，具备双向新鲜性 |

没有配置开关、没有回退路径，因此**不存在降级攻击面**。代价：客户端与服务端（含 Android 客户端，见 §6）必须同时升级。

### 4.4 新鲜性论证

- **随机数替换攻击**：MITM 把新鲜 token T2 与旧 random R1 拼接 → tag 绑定的是 R2 → 服务端校验失败，直接转伪装站，不分配会话。
- **完整会话重放（含服务端重启后 replay cache 清空）**：录制的 (R1, T1) 虽能过 token 校验，但服务端这次生成新的 server_random → 会话密钥与原会话不同 → 重放的 c2s 记录首帧即解密失败，任何请求都不会被执行，也不会出现 (key, nonce) 复用。
- replay cache 仍保留（拒绝窗口内同一 token 二次建会话，省资源），但不再是新鲜性的唯一保障。

---

## 5. QUIC 传输路径与 Lean 模式评估

### 5.1 QUIC Lean 路径架构梳理

在开启 QUIC 特性时，Mirage 支持 Model X 精简 QUIC 流传输（[src/proxy/mirage_server/mod.rs#L215-L274](file:///opt/Mirage-rs/src/proxy/mirage_server/mod.rs#L215-L274) `handle_quic_stream_lean`）。
在该路径下：
- 外层连接是标准的 QUIC 连接，由 TLS 1.3 提供信道加密；**但不提供服务端认证** —— 服务端证书为 rcgen 临时自签、客户端 `NoVerify` 接受任意证书，也没有客户端证书 (审阅纠正: 原稿此处写"服务端/客户端认证"不成立)；
- 内层多路复用时，每个双向流的开头包含：
  $$\text{Payload} = [\text{token}(32\text{B})][2\text{B target\_len}][\text{target}][\text{data}\dots]$$
- 服务端直接读取 32 字节并调用 `verify_session_token(pw, &token, tol)` 校验，认证通过后直接执行 `copy_bidirectional`。

### 5.2 P1-A 与 P1-B 对 QUIC Lean 的影响分析

1. **不受 P1-A（Two-Time Pad 密钥流复用）影响**：  
   QUIC Lean 路径在流内部**根本没有第二层 AEAD**，也没有使用 `derive_master` 和 `client_random`。流数据的保密性由外层 QUIC 协议保证。因此不存在 TCP 伪装层上的会话主密钥替换和两时间填充漏洞。
2. **不受 P1-B 影响**：  
   QUIC Lean 不运行 `cipher_agility` 协商逻辑，内部无 `rekey` 概念。
3. **Token 重放维度的表现**：  
   `verify_session_token` 同样会向 `REPLAY_CACHE` 插入该 Token。**但这层保护意义有限 (审阅纠正)**：因客户端 NoVerify，主动中间人可直接终止客户端的 QUIC 连接、读出明文 token 与 target，再用该**新鲜** token 以自己的 QUIC 连接连服务端并转发/篡改数据 —— 这不是重放而是完整 MITM，token 机制挡不住。QUIC lean 的安全前提是先补**服务端证书 pinning**。
4. **结论与演进建议**：  
   QUIC Lean 路径**不受 P1-A/P1-B 的密钥派生机制影响**，但因 NoVerify 本身已可被主动 MITM 完整读改 (更严重, 独立问题)。由于 QUIC Lean 数据流首部没有 `client_random`，若强制将其纳入 Token v2 会导致 QUIC 协议帧结构改变。建议在阶段 2 中：
   - **已实现**：QUIC lean 的每流 token 使用固定 `bind = QUIC_LEAN_BIND` 做域分隔（载荷结构不变，仍是 32B token 开头），使 QUIC token 与 TCP token 不可互相冒用；
   - 其真正缺口是外层 NoVerify（见 5.3），留待 QUIC 转正前以证书 pinning 解决。

### 5.3 QUIC 腿外层证书认证缺陷（NoVerify）的关系与范围界定

在 [src/proxy/quic.rs#L211](file:///opt/Mirage-rs/src/proxy/quic.rs#L211) 与 [#L311-L318](file:///opt/Mirage-rs/src/proxy/quic.rs#L311-L318) 中：
```rust
struct NoVerify;
impl rustls::client::danger::ServerCertVerifier for NoVerify { ... }
```
客户端跳过了外层 QUIC 服务端证书的合法性校验。  
- **关系说明**：这是 QUIC 传输模式特有的证书吊销/自签名信任问题（容易遭受外层 TLS 中间人劫持）。
- **范围划分**：此问题属于传输层证书信任体系缺陷，与本次 fake-TLS 协议的 P1 密码学新鲜度漏洞彼此正交，明确列为**阶段 2 范围外事项**，后续由 QUIC 传输专项重构统一解决。

---

## 6. 跨端生态同步 (Android 客户端 mirage-core)

### 6.1 移动端仓库现状与 Vendoring 架构

移动端内核独立维护于 `/opt/Mirage-android`，其核心网络引擎在 `native/mirage-core` 下。
- 同步机制：通过脚本 `native/vendor-sync.sh` 从 `/opt/Mirage-rs` **单向复制** 22 个核心协议源文件；
- 当前版本状态：查看 `/opt/Mirage-android/native/mirage-core/src/vendor/SYNC.md`，当前 vendored 副本停留在 commit `da640f3201b13d90b14f6848a09e2edf7135e882`（2026-08-28），尚未同步主仓库近期的多项特性。

### 6.2 必须同步的文件清单与执行顺序

当 Mirage-rs 完成协议加固实现后，需在 Android 仓库执行同步。涉及的核心协议文件包括：

1. `crypto/aead.rs`：主密钥派生与安全 rekey 逻辑；
2. `crypto/cipher.rs`：套件协商与防复用逻辑；
3. `crypto/hello_auth.rs`：Token v2 构造与校验；
4. `proxy/pool.rs`：客户端提取 `server_random` 并参与密钥派生；
5. `config.rs`：配置兼容项。

**同步操作规范**：
```bash
# 在 /opt/Mirage-android 根目录下执行 (只读审阅，切勿在当前任务改动)
./native/vendor-sync.sh /opt/Mirage-rs
```

### 6.3 移动端特有补丁维护与编译边界

同步后必须人工复核并恢复移动端特有补丁：
- `proxy/brutal.rs`：必须保留 `#[cfg(target_os = "android")] const SO_COOKIE = 67;` 补丁（因 Android bionic libc crate 缺失该系统常量定义）；
- 裁剪边界检查：确保未将桌面端专有依赖（`crate::ebpf`、`crate::api`、`crate::config_watcher` 等）引入移动端编译范围。

### 6.4 跨端兼容性与版本发布协同表现

- **断代影响**：v0.15 服务端上线后，**现有全部 Android 客户端（vendored 旧协议）都将认证失败**，反之亦然。
- **必须同步发布**：在 `/opt/Mirage-android` 执行 `native/vendor-sync.sh` 同步 `crypto/{hello_auth,aead,cipher,handshake_cache}.rs`、`proxy/pool.rs` 等，重施移动端补丁（`proxy/brutal.rs` SO_COOKIE）、检查裁剪边界并跑通 mirage-core 测试后，与服务端 v0.15.0 **同一时间窗发布**。建议先发 Android 新版（对旧服务端会连不上，故需与服务端升级时间对齐，或先升级服务端后立即推送 App 更新）。

---

## 7. 测试与验证计划

为确保加固方案无回归且真实有效，必须建立完备的三级测试防线：

### 7.1 单元测试套件设计

1. **Token v2 互通与防篡改测试 (`tests/test_hello_auth_v2.rs`)**：
   - 验证 `make_session_token_v2(pw, client_random)` 生成的 Token 能够被 `verify_session_token_v2` 成功验证；
   - 断言：将 `client_random` 任意翻转 1 bit，`verify_session_token_v2` 必须恒返回 `false`；
   - 断言：旧版 `verify_session_token_v1` 校验 v2 Token 必定失败（隔离性验证）。
2. **主密钥派生唯一性断言 (`src/crypto/aead.rs`)**：
   - 给定相同的口令和 `client_random`，当 `server_random` 改变时，断言派生的 Master Key 发生位雪崩级变化；
   - 断言：不同 info label（`b"pyrealiy-session-v2"` vs `b"pyrealiy-session"`）派生出的密钥互不相同。
3. **Cipher Agility Rekey 安全性测试 (`src/crypto/cipher.rs`)**：
   - 覆盖协商结果为 `ChaCha20Poly1305` 的场景；
   - 显式断言：在发送 Target 之前与之后，Writer 的 Nonce 保持连续自增（0 $\to$ 1 $\to$ 2），绝不允许出现 Nonce 再次从 0 发送的情况。

### 7.2 已实现的测试（v0.15）

断代后无需跨版本互通矩阵。实际落地的测试：
- `tests/test_hello_auth.rs`：`test_token_bind_bit_flip_fails`（bind 翻 1 bit 必失败）、`test_token_domain_quic_tcp_separation`（QUIC/TCP token 互不可冒用）、`random_substitution_attack_blocked`（攻击回归）。
- `src/crypto/aead.rs`：`master_deterministic_and_depends_on_both_randoms`（不同 server_random → 不同 master；PFS 与非 PFS 域分隔）、`non_pfs_pair_roundtrips` / `pfs_pair_roundtrips`、`writer_rekey_identical_cipher_debug_assert`。
- `src/crypto/handshake_cache.rs`：`apply_server_random` 返回值 == 实际写入 flight 的 random。
- `src/proxy/pool.rs`：`read_server_handshake_fails_closed_on_all_zero_random` / `..._succeeds_on_valid_random`。
- `tests/test_cipher_agility.rs`：协商为 ChaCha 时端到端收发正常且不重置 nonce。
- 端到端（`test_full_e2e_proxy` / `test_lite_e2e` / `test_ss_upstream_e2e` 等）在新协议下全部通过，证明客户端 ↔ 服务端真实握手互通。

### 7.3 针对 P1-A 的攻击复现回归测试 (PoC Regression Test)

编写针对历史漏洞的确定性回归用例 `test_p1a_random_substitution_blocked`：
1. **构造历史会话 1**：客户端用 $(R_1, T_1)$ 握手，录制其首个上行加密数据报 $C_1$；
2. **模拟活体客户端发起会话 2**：生成合法新鲜的 $(R_2, T_2)$；
3. **执行中间人攻击**：拦截会话 2，将 `ClientHello.random` 替换为 $R_1$，Token 保持为新鲜的 $T_2$，并发给服务端；
4. **安全断言**：
   - **旧协议下行为（漏洞复现）**：服务端校验通过，并且重放历史的 $C_1$ 能够被服务端成功解密（证明漏洞存在）；
   - **加固协议下行为（通过断言）**：服务端在 `verify_session_token_v2` 处直接报错失败，连接被即刻引流至伪装站；攻击者重放的 $C_1$ 永远无法被服务端接收与执行。

---

## 8. 发布与迁移规划

### 8.1 版本命名与节奏

- **目标版本**：`v0.15.0`（**BREAKING**：协议断代）。
- 服务端、Linux 客户端、Android 客户端需在同一时间窗升级；CHANGELOG / README 显著标注升级要求。
- 不设过渡期、不设兼容开关。

### 8.2 对 [[threat-model]] 的更新同步

在协议加固实现合并前，需同步对 `docs/threat-model.md` 进行以下修订：
1. **更新 T1（抗主动探测）**：
   - 补充对 `ClientHello.random` 密码学绑定的明确条目：`ClientHello.session_id` 覆盖 `ClientHello.random`，杜绝中间人随机数替换。
2. **补充抗重放威胁模型（T6: 会话防重放与双向新鲜度）**：
   - 明确定义系统必须抵御服务端重启后的窗口期重放攻击；
   - 明确定义主密钥必须强依赖服务端单次下发的 `ServerHello.random`，确保每次连接密钥流空间彻底正交。
3. **场景测试映射表（§7）追加**：
   - 登记 `tests/test_protocol_compat.rs` 与 `test_p1a_random_substitution_blocked` 至 CI 验收断言清单。

---

## 9. 已决策记录

| # | 问题 | 决策 |
|---|---|---|
| Q1 | Token 一次性密钥是否加版本域分隔 | 加：`"mirage-token-v2"` |
| Q2/Q3/Q6 | 兼容开关命名、新客户端连老服务端、过渡期 | **全部作废**：v0.15 协议断代，不兼容旧协议，无开关、无回退、无过渡期 |
| Q4 | QUIC lean 是否改动 | 载荷结构不变，token 改用 `QUIC_LEAN_BIND` 域分隔；外层 NoVerify 留待证书 pinning |
| Q5 | P1-B 修法 | 同 cipher 不 rekey + `rekey()` 防呆，对所有会话生效（断代后无需门控） |
| 审阅补充 | server_random 为全 0 | 客户端与服务端都 fail-closed |
