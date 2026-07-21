# Changelog - Mirage-rs

## [未发布] - handler active_fd guard 析构顺序 (2026-07-21)

### fix(handler): active_fd guard 在 cancel 路径也保证"先移出 set、再关 fd"

外部审计指出 `handler.rs` 里 `_guard` (active_fds 成员管理) 的析构顺序在 task 被 cancel
时不对。**核实: 观察属实, 注释本身写错了, 但严重性被大幅夸大。**

- **真核**: `tunnel_reader/writer` 被 **move 进** upload/download 两个 async 块, 而它们声明在
  `_guard` **之后**。原注释以为 fd 的关闭时机绑定在 `let tunnel_*` 那两行、故 guard 会先析构 ——
  实则绑定在 upload/download 上, cancel 时按声明逆序是 `download→upload`(关 fd)`→_guard`(移出 set),
  即先关 fd 后移出, 与注释承诺相反。**已把 `_guard` 声明挪到 upload/download 之后**, 逆序析构
  变为 guard 最先 → 移出 set 再关 fd, cancel 路径也正确。

- **严重性证伪**: 审计称"串位篡改 / 逻辑死锁"严重夸大。① relay 外**无 select!/timeout/abort**,
  cancel 只发生在**进程退出**, 此时 active_fds 与所有连接一并销毁, **不存在 fd 被复用给合法新连接**;
  ② active_fds 只驱动 Brutal CC 调速 + 指标汇总, 最坏后果是某连接 CC 速率误设/统计读到脏 socket
  一个周期 —— **不碰数据(无"串位")、setsockopt 坏 fd 返 EBADF 直接忽略(无死锁)**;
  ③ 消费侧竞态项目早已加固 (F2: update_brutal_rate 持 active_fds 锁期间 setsockopt, 阻塞 guard
  的 remove、fd 保活)。

故这是**防御性正确 + 修正误导性注释**, 而非现存 bug。之所以仍修: 注释承诺了一个 cancel 路径
不成立的保证, 且日后若给 relay 加超时/竞速, 这个窗口会变成真 (虽仍轻微) 的 bug。140 测试全过。


## [未发布] - 清理 mss_clamp 死代码 (2026-07-21)

### chore(ebpf): 移除独立的 mss_clamp 死代码 (含其 CI 验证器)

MSS clamp 功能早已内联进 `tc_divert.c`(`clamp_tcp_mss`, 对转发 SYN 生效), 独立的
`ebpf-src/mss_clamp.c/.elf` 从未在生产被加载 —— 只有 `build.rs` 编译它。

**顺带发现一个"假信心"隐患**: CI 的 `verify_mss_clamp` 加载并验证的是那个**独立死 elf**,
而非生产实际运行的内联版。它证明的是一份**不会被使用**的副本能工作 —— 覆盖是虚的,
且两份实现已分叉。故成套删除:

- `ebpf-src/mss_clamp.c` / `mss_clamp.elf`
- `examples/verify_mss_clamp.rs` / `.sh` + Cargo.toml 的 example 声明 + CI 步骤
- `build.rs` 里编译它的两行

保留 `tc_divert.rs` 那句 `mss_clamp mtu={}` 日志 —— 它描述的是**内联版**的 mtu 配置, 是真的。

> 📌 代价: MSS clamp 从此**没有专门的 CI 验证器**。但被删的验证器本就在验非生产的副本,
> 删它不损失真实覆盖。若要给内联版补 CI 覆盖, 需让验证器改加载 `tc_divert.elf` 并配齐
> 其 config map —— 那是独立的一件事, 非本次清理范围。


## [v0.6.0-alpha.5] - 路由标量字段 + 伪装域名确认 + 易用性 (2026-07-21)

### fix(install): 伪装域名搜索的确认逻辑 —— 回车即采用推荐值

原先扫描完提示"留空 = 放弃, 回落手动输入", 默认值给的是空串 —— **回车是放弃**, 与直觉相反,
而且工具自己算出的推荐域名走 stderr, 脚本没捕获、用不上。

改为: 用 `tee` 把工具输出**既展示又捕获一份**, 提取末尾的 "✅ 推荐 camouflage_host: <域名>"
作为 `ask` 的默认值。于是 **回车直接采用推荐域名, 手动输入则用输入的**(靠 `ask` 的
`${val:-$default}` 语义)。提取用 "推荐 " 前缀精确匹配, 避开紧随的 `config 改法` 提示行。
无理想推荐时(工具打印 ⚠️ 而非推荐)保持旧行为: 手动填或留空放弃。

采用推荐前仍提示先人工过目表格(廉价机房同段邻居可能本身也是代理/空壳站)。


### feat(config): 路由规则的列表字段可写单值, 不再强制数组

用户反馈: `"port": 443` 会**解析失败**, 必须写 `"port": [443]` —— 而 sing-box/Clash 都允许
单值省略 `[]`。现全部 10 个列表字段 (`domain_suffix` / `domain_keyword` / `domain_regex` /
`geosite` / `ip_cidr` / `geoip` / `source_ip_cidr` / `source_mac` / `protocol` / `port`)
都接受标量或数组两种写法:

```jsonc
{ "outbound": "direct", "port": 443 }            // ← 现在可以
{ "outbound": "direct", "port": [80, 443] }      // ← 仍然可以
{ "outbound": "direct", "domain_suffix": "cn" }  // 所有列表字段同理
```

纯易用性, 不改变任何匹配语义。单值被解成单元素数组 (`443` → `[443]`), 缺省仍是空。
2 个单测锁定 (标量→单元素 / 数组原样 / 全 10 字段都支持)。


## [v0.6.0-alpha.4] - Shadowsocks 2022 + 服务名区分 + 搜索范围扩大 (2026-07-21)

### feat(install): 轻量版服务名与完整版区分 (`mirage-rs-lite-*`)

此前两种形态共用 `mirage-rs-{server,client}` —— 当初这么设计是为了避免两个 unit 抢同一
端口, 但代价是 `systemctl status` 看不出装的是哪个模式。现改为:

| 形态 | 服务名 | 子命令 | 配置 |
|---|---|---|---|
| 完整版 | `mirage-rs-{server,client}` | `server`/`client` | `config_*.json` |
| 轻量版 | `mirage-rs-lite-{server,client}` | `lite-server`/`lite-client` | `lite_*.json` |

**区分服务名带来一个新风险, 已一并处理**: 两个 unit 现在可以并存, 而它们**默认监听同一
端口** —— 旧模式的服务若还开机自启, 重启后两个抢一个端口, 后启动的 bind 失败, 表现为
"装完却时好时坏"且极难联想到原因。故安装时会主动**停止并 disable 另一形态的同角色服务**
(配置文件保留, 想切回去重跑安装选另一形态即可)。

配套修正:
- 服务名不再散落在各处硬编码, 统一走 `svc_name()`; systemd/OpenRC/SysV 三种 init 与
  start/restart/log 提示、`svc_ctl`、`service_active` 全部跟随。
- **卸载覆盖全部四个名字**(两形态 × 两角色)+ 两个历史旧名 —— 漏掉任何一个都会留下
  开机自启的残留服务。
- README 三处硬编码服务名同步。

### fix(shadowsocks): 握手合并为一次 write —— 消除可观察的握手指纹

上线前自审发现: 开着 `TCP_NODELAY` 却逐段 `write+flush`, 使握手拆成**三个 TCP 段**
(salt / 定长头 / 变长头), 而真实 SS 客户端是**一段**(总共才百来字节, 远小于 MSS)。
观察 Mirage→SS 这条链路的人能据此区分出这不是标准客户端 —— 对一个以"不可区分"为核心的
项目, 这是实打实的缺陷。SIP004 路径同样是两段。现拼成一整块一次送出。

> 📌 **一个失效测试的自我纠正**: 我最初在服务端侧"只做一次 read, 断言能拿全握手"来验证
> 这个性质。**变异后(改回分两次发、中间 sleep 50ms)该测试照样通过** —— 因为 TCP 接收侧
> 会把多段合并进缓冲, 一次 read 自然全拿到。这个性质**在网络层根本测不出来**。
> 已删掉该测试(假信心比没有更糟), 改为把握手拼装抽成独立函数、在**写入层**断言它一次性
> 产出完整字节; 新版做过变异验证(头部不拼进去 → 如实变红)。

### feat(tools): 伪装域名搜索支持按子网掩码扩大范围

`find_camouflage.py` 新增 `--prefix N`(扫包含本机 IP 的 /N), `install.sh` 里也可交互
选择搜索范围(通告前缀 / /22 / /20)。同机房常在相邻网段还有别的前缀, 它们仍属同一 ASN,
照样满足 SNI/IP 一致性。

**只扩范围是不够的 —— 判据也必须改**: 原先的一致性判据是"解析回的 IP 是否落在**通告前缀**内",
扩出去的候选会被**全部判为跨段而淘汰**, 等于白扩。现改为**按 ASN 归属**校验:

    精确IP > 同/24 > 同通告前缀 > 同ASN(不同前缀) > 跨ASN(淘汰)

真机实测(AS906, 通告前缀 `154.21.90.0/24`)对比:

| 范围 | 候选域名数 |
|---|---|
| 默认(通告前缀) | 25 |
| `--prefix 22` | **241** |

新增的候选落在 `154.21.88.x`/`154.21.89.x` —— 在通告前缀之外但仍属 AS906, 被正确标注为
`同ASN`。若沿用旧判据, 这 241 个会一个不剩地被淘汰。

ASN 查询按 /24 缓存(同段 IP 几乎必属同一 ASN), 把请求数从"每候选一次"降到"每 /24 一次",
避免被 RIPEstat 限流。扩大范围时 install.sh 的超时也从 300s 放宽到 1200s, 否则总在快出
结果时被砍掉。

### feat(shadowsocks): 上游出口支持 SIP022 三种加密方式

`2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` / `2022-blake3-chacha20-poly1305`。
(chacha20 变体在无 AES 硬件加速的设备上更快 —— ARM 路由器/树莓派/低端 VPS 常见。)

SIP022 与 SIP004 **不是"换个哈希"那么简单**, 密钥来源与帧结构都是另一套:

| | SIP004 | SIP022 |
|---|---|---|
| 密钥来源 | 任意密码经 `EVP_BytesToKey`(MD5)拉伸 | **base64 编码的密钥本身**, 不做拉伸, 长度固定 |
| 会话子密钥 | `HKDF-SHA1(主密钥, salt, "ss-subkey")` | `BLAKE3::derive_key("shadowsocks 2022 session subkey", PSK‖salt)` |
| 请求头 | 首个 chunk 就是目标地址 | 定长头(类型/时间戳/长度)+ 变长头(地址/padding/首载荷) |
| 抗重放 | 无 | 时间戳 ±30s + 服务端响应**回显请求 salt** |

- 响应头的三项校验(类型 / 时间戳 / **salt 回显**)一项都不能少: 不校验 salt 回显,
  攻击者就能把另一会话的响应重放过来。
- **PSK 校验前移到建连之前**: 密钥格式/长度错是配置问题, 若先建连, 网络错误
  (Connection refused / 超时)会把真正的原因盖住, 用户对着"连接被拒"根本查不到是密钥写错。
- 无 padding 的请求会塞一段随机 padding(协议规定), 避免"只建连不发数据"呈现固定长度特征。

**上线前自审又发现一个同类闸门漏洞**(与 alpha.2 那次同一类): `check` 放行了长度不对的
SIP022 密钥。而这个错**不会**让服务端起不来 —— 它会正常启动, 然后**每条连接都静默失败**,
服务看着健康却什么都代理不了, 比起不来更难查。已在 `check` 与启动路径**两处**都加上校验
(启动侧直接拒绝启动而非带病运行), 并加回归测试。

**验证**:
- **加解密层对照验证**: 用 `shadowsocks-crypto`(成熟第三方实现, **dev-dependency, 不进
  发布二进制**)在测试里搭一个 SS2022 服务端, 它成功解开本实现的定长头与变长头, 本实现
  也正确解开它的响应。BLAKE3 context 字符串、`PSK‖salt` 拼接顺序、nonce 递进任何一处错
  都会让这条测试红。**AES 与 chacha20 两条路径各跑一遍完整互通** —— 光"编译过"说明不了
  新算法那条路对; chacha20 那条做过变异验证(把算法映射改错 → 参考实现解密失败, 测试如实变红)。
- 另有单测锁定: 会话子密钥与参考实现逐字节一致、分次 `update` 等价于拼接、PSK 长度强制、
  错误 PSK 必须解密失败。

> ⚠️ **诚实的边界**: 帧结构(定长/变长头布局)两侧都出自同一份规范解读, 因此上述验证
> **不能**证明与真实 SS2022 服务器互通, 只能证明"加解密层正确 + 收发自洽"。
> 真正的互通结论需要对着一台真实的 SS2022 服务器验证 —— 手上没有这样的环境。
>
> 📌 `2022-blake3-chacha8-poly1305` 未实现(非标准算法, 生态罕见), 会明确报错。
> SIP022 的 UDP 同样未实现(沿用 `upstream.udp` 默认 `block`)。

## [v0.6.0-alpha.3] - 安装向导与文档补齐 SS 中转 (2026-07-20)

### feat(install): 安装向导补上 Shadowsocks 上游出口配置

v0.6.0-alpha.2 加了 SS 中转能力, 但 `install.sh` **完全没有对应选项** —— 用户跑完向导后
想做中转只能手改配置文件, 等于功能通过安装路径**不可达**。

新增 `ask_ss_upstream()`, 服务端(完整版与轻量版共用)在问完 SNI 后询问是否配置上游:
交互填服务器/端口/密码, 加密方式用选单(只给 SIP004 AEAD 三种, **不提供 legacy 流式加密
选项** —— 无完整性校验、已废弃), UDP 策略默认 `block` 并解释代价。密码经 `json_escape`,
含引号也不会写坏配置。不配则输出空串, 生成的配置与之前完全一致。

### docs(readme): 同步 v0.6.0-alpha.2 的功能与安装引导

README 有多处停留在旧版本:
- **核心特性**完全没提本版新增(轻量模式 / 中转站 / `check`·`format`·`import` / 入站认证)。
- **一键安装描述**说菜单是"4=卸载", 实际已是 6 项, 且没提选完角色后还会问「部署形态」。
- **客户端配置示例**里 mixed 入站写的是 `"listen": "0.0.0.0"` 且无 `auth` ——
  **示例本身演示的就是我们刚修掉的开放代理**。已改为 `127.0.0.1`, 并在代码块**外**
  补 LAN 共享须加 `auth` 的说明(刻意不写进 JSON: 伪注释键会被 `check` 判为未知字段,
  那是在教用户踩自己刚建的校验)。

## [v0.6.0-alpha.2] - 轻量模式 + SS 中转 + CLI 工具 + 入站认证 (2026-07-20)

### 🔴 security(inbound): SOCKS5/HTTP 入站补认证 —— 修默认开放代理

**这是一个真实安全缺陷, 不是加固。** 此前 SOCKS5 只接受无认证方法 `0x00`、HTTP 侧完全没有
`Proxy-Authorization` 处理, 而 `install.sh` 的本地代理监听地址**默认填 `0.0.0.0`** ——
**默认安装出来就是一个开放代理**: 任何能连到 1080 的人都能白嫖隧道, 流量从你的服务端出去,
出口 IP 会被滥用/拉黑。对抗审查部署尤其致命, 因为招来注意力正是最不能承受的。

讽刺的是 v0.5.0-alpha.2 早已给 **Web 看板**加了 bearer token(理由正是"绑 0.0.0.0 即泄漏"),
但价值高得多的**代理本身**却零防护且默认就绑 0.0.0.0 —— 看板锁了, 门开着。

- **新增可选 `auth`** 到 `socks` / `mixed` 入站: `{"username": "...", "password": "..."}`。
  **不配 = 不鉴权**, 既有配置行为完全不变(向后兼容)。
- **SOCKS5**: 实现 RFC 1929 用户名/密码子协商。配了 auth 就**只接受方法 0x02** ——
  否则客户端只要声明"我不想认证"(0x00)就能绕过, 等于没鉴权。失败按协议回 `[0x01,0x01]` 再断,
  不是裸 RST。
- **HTTP**: 校验 `Proxy-Authorization: Basic`, 不通过回 **407 + `Proxy-Authenticate`**
  (浏览器/curl 可弹凭据重试)。header 名大小写不敏感; 密码允许含冒号(只按第一个冒号切分)。
  自带 ~20 行 base64 解码, 不为此引入依赖。
- **凭据比较为常量时间**且用非短路 `&`(用户名与密码都算完), 避免时序泄漏凭据前缀。
- **启动告警**: 监听非回环地址却没配 auth → WARN 指出这是开放代理并给出两种修法。
  不阻止启动(向后兼容 + 可信内网仍是合法用法)。
- **`install.sh`**: 监听地址默认改回 **`127.0.0.1`**; 选非回环时**强制**设账号密码
  (密码可留空自动生成), 并显式警告开放代理风险。

验证: 9 个新测试。SOCKS5 侧用**真实 TCP** 端到端跑四条路径(认证成功 / 密码错拒绝 /
**声明 0x00 不能绕过** / 未配 auth 保持无认证); HTTP 侧覆盖合法 Basic、用户名或密码错、
缺头、`Authorization` 冒充、header 大小写、密码含冒号、base64 已知向量。
"0x00 不能绕过"这条做过变异验证(放宽为也接受 0x00 → 该测试如实变红)。

### feat(shadowsocks): 服务端支持 SS 上游出口 —— Mirage 可作中转站

服务端不再只能直连目标, 可配置把流量再经 Shadowsocks 发往上游:

```
客户端 ──(Mirage 隧道)──▶ Mirage 服务端 ──(Shadowsocks)──▶ SS 服务器 ──▶ 目标
```

典型用途: Mirage 服务端放在离用户近、线路好的位置(如香港)只做中转, 真正出口落在另一台
SS 服务器上。给 `mirage_server` 入站或轻量服务端配置加 `upstream` 即可; 不配 = 直连(原行为)。

- **新增 `src/proxy/shadowsocks.rs`**: SIP004 AEAD 客户端 (TCP)。支持 `aes-128-gcm` /
  `aes-256-gcm` / `chacha20-ietf-poly1305`, 复用 `ring` 的 AEAD 与 HKDF-SHA1;
  密码派生按 SS 的历史约定用 OpenSSL `EVP_BytesToKey`(MD5 链, 新增 `md-5` 依赖 —— 这是
  互通的硬要求, 换任何"更好"的 KDF 都会连不上现存服务器)。
- **明确拒绝 legacy 流式加密**(`aes-256-cfb` 等): 无完整性校验、已被社区废弃、易被主动
  探测识别。错误信息会解释原因而非只说"不支持"。
- **加密方式写错直接报错拒绝启动**, 不静默降级为直连 —— 配了中转却走直连意味着出口 IP
  与预期完全不同, 属于必须立刻知道的错配。
- 中继路径与直连路径结构一致(共享 fd + 任一方退出即 `shutdown(SHUT_RDWR)` 唤醒另一方),
  差别仅在下行按**整块解密**读取: SS 已按 ≤16KB 分块, 直连路径那个基于 `try_read` 的
  贪婪收割在这里没有意义。直连热路径**未受影响**。

> ⚠️ **仅作用于 TCP**。SS 的 UDP 是另一套包格式, 未实现 —— 配了上游后服务端 UDP 中继
> **仍走直连**, 故 UDP 与 TCP 的出口 IP 不同。这是真实的信息泄漏面, 因此启动时会 WARN
> 并在 README/模板中显著标注。

**UDP 策略: 配了上游时默认阻断 (`upstream.udp`, 默认 `block`)**。

原先配了 SS 上游后 UDP 仍走直连, 意味着 UDP 从**本机 IP** 出去而 TCP 从上游出去。这不只是
"不一致" —— 对中转最典型的用途(落地解锁)是**功能性错误**: 流媒体越来越多走 QUIC, QUIC
走直连会被目标判成错误区域, 而且它**不会**像"UDP 被封"那样回落 TCP(QUIC 成功了, 只是从
错误的出口成功的), 表现为解锁时灵时不灵且极难排查。

**你配了中转, 意图就是流量从上游出去; 安全的失败方式是"不发", 而不是"发到别处去"。**
故默认改为直接拒绝 UDP 中继 —— 客户端立刻知道 UDP 不可用, QUIC 回落 TCP(页面照常),
代价是游戏/WebRTC 不可用。确需旧行为写 `"udp": "direct"`(启动会 WARN 说明风险)。
轻量客户端本就仅 TCP, **不受任何影响**。

> 未实现 SS UDP 而是先阻断, 是因为: ①多数 SS 服务器默认不开 UDP, 而 SS UDP 无握手 ——
> 上游不支持时表现为"包石沉大海", 无法探测、只能等用户报障, 实现了也不等于能用;
> ②阻断只要十几行就消除了"走错出口"这个真问题。SS UDP 待有实际需求再做。

**上线前自审发现并修掉一个闸门漏洞**: `check` 命令对写错的 SS 加密方式(如 `aes-256-cfb`)
报"校验通过" —— 而该配置会让服务端**拒绝启动**。也就是说 `check && systemctl restart`
这个闸门在这条路径上形同虚设: 校验放行 → 重启 → 服务起不来。现已把上游校验(加密方式
可解析 / server 非空 / port≠0 / password 非空)加进 `semantic_issues`, 并加了 3 个回归测试。

**验证分三层, 重点在"证明能与真实 SS 服务器互通"而非自洽**:

1. **交叉验证**: 用 Python `cryptography` 按 SIP004 规范**独立**写一遍服务端解密, 成功解开
   本实现产出的三种加密方式的真实流(含地址、跨 chunk 的 20KB 载荷)。自洽回环证明不了
   互通 —— 两边可以以同样的方式错而依然对得上。
2. **黄金向量**: 把上述已被独立实现确认合规的字节流固化进单测, 锁死 EVP_BytesToKey /
   HKDF 子密钥 / 分块格式 / 小端 nonce / 地址编码这一整套对外契约(CI 无需 Python)。
3. **端到端**: 集成测试起一个独立实现的最小 SS 服务器验证互通; 另在本机跑通**完整中转链路**
   (轻量客户端 → Mirage 中转 → Python SS 上游 → 真实 HTTPS 请求), SS 侧日志确认目标地址
   `api.ipify.org:443` 正确送达。

### feat(install): install.sh 支持轻量模式部署

此前轻量模式只能手写配置 + 手动跑二进制, `install.sh` 里零支持。现在选完
"部署服务端/客户端"后会再问一次**部署形态**(完整版 / 轻量版):

- **轻量服务端**: 问端口(**默认 443 但可自定义**)、密码、SNI(可选自动搜同 ASN 伪装域名),
  生成平铺 `lite_server.json` 并注册服务; 同样导出 `mirage://` 节点串 + 二维码。
- **轻量客户端**: 支持**直接粘贴服务端的 `mirage://` 串**导入(免手抄密码/SNI 出错),
  或手动填; 问本地 SOCKS5 监听地址与端口; 非回环监听时**强制设 SOCKS5 认证**
  (与完整版同一策略, 防开放代理)。生成 `lite_client.json` 并注册服务。
- **服务名仍是 `mirage-rs-{server,client}`** —— 一个角色一个服务, 避免完整版与轻量版
  两个 unit 抢同一个端口。systemd/OpenRC/SysV 三种 init 的 ExecStart 都会按形态
  切换到 `lite-server`/`lite-client` 子命令与 `lite_*.json` 配置。
- 轻量客户端不走透明网关那套(它本来就没有), 因此不会去动 NAT/ip rule/resolv.conf。

**顺带修一个真 bug**: 新增 `json_escape()` —— 密码里含 `"` 或 `\` 时, 直接内插会生成
**非法 JSON**, 服务起不来且报错难懂。实测密码 `p@ss"with\quote` 原先直接把配置写坏,
转义后可正常握手连通。

### fix(install): 完整版配置生成同样做 JSON 转义 (密码含引号不再写坏配置)

上一条只修了新增的轻量路径, 完整版仍留着同一个 bug。本次补齐所有**现实中真会含特殊
字符**的字段:

- `config_server`: `password` / `camouflage_host`
- `config_client`: `server` / `password` / `camouflage_host`
- mixed 入站的 `auth.username` / `auth.password`(开放代理修复时新加的, 同样有此问题)

`generate_password` 产出十六进制故默认安全, 但用户**手输**带引号的密码会直接把
`config.json` 写成非法 JSON —— 服务起不来, 且错误信息指向 JSON 解析而非密码, 极难排查。

> 📌 **有意未处理**: 透明网关那段的网络参数(`inbound_listen` / `lan_iface` / `dns_listen` /
> `direct_dns` / `remote_dns` / `fakeip_range`)仍是裸内插。它们同属一个 bug 类, 但
> ①在网卡名或 IP 里打引号属荒诞 typo; ②那段配置生成**无法在开发机上端到端验证**(需真网关)。
> 为防一个不现实的输入去改无法验证的代码, 风险大于收益。

验证: 用 `p@ss"with\back\\slash<TAB>tab` 这种同时含引号、单/双反斜杠、制表符的密码, 走完
完整版服务端 / 完整版客户端 / mixed 认证三条 JSON 生成路径, 均**合法且内容原样还原**;
再用同一密码起真的两端, **握手成功并跑通真实 HTTPS 请求**。

验证: `bash -n` 通过; 用 `json_escape` 生成含 `"` 与 `\` 的配置, 起真的 lite-server +
lite-client **握手成功并跑通真实 HTTPS 请求**; 逐一核对两种形态下 systemd/OpenRC/SysV
的 ExecStart 与配置路径推导正确。

### docs(lite): 补上轻量模式的配置模板 (含端口设置说明)

轻量模式此前**没有任何模板** —— `templates/` 里只有完整版的 client/server, 用户想知道
"服务端端口怎么配"无处可查(功能一直支持, 只是没文档)。新增两份带完整注释的模板:

- `templates/lite_server.jsonc` — 每个字段的含义与取值建议, 其中 `port` 明确说明:
  **可自由自定义不限于 443**; 443 伪装最好但属特权端口(<1024), 非 root 会 bind 失败,
  需 systemd/root 或 `CAP_NET_BIND_SERVICE` 或换 `>1024` 端口。
- `templates/lite_client.jsonc` — 含 `server_port` 必须与服务端 `port` 一致的提示、
  开放代理风险说明、以及"仅 TCP"的已知限制。

同时新增**防模板腐烂**的测试: 断言仓库里发布的模板能被当前代码解析。字段一旦在代码里
改名而模板没跟着改, 用户照着写就会踩坑 —— 仓库中那个用旧 schema、连解析都过不了的
`transparent_config.json` 就是活例子。测试自带一个 JSONC 去注释器(只在引号外识别 `//`,
避免误伤值里的 `http://`, 有专门回归用例)。

验证: 从模板去注释生成真配置, 用**非 443 的自定义端口**(17777/17080)起真的
lite-server + lite-client, 经隧道跑通一条真实 HTTPS 请求。

### feat(lite): 新增轻量模式 `lite-client` / `lite-server`

给"只要能翻墙、不需要分流"的场景一条最短路径: 本机 SOCKS5 → 全部走隧道。

```bash
mirage-rs lite-server -c lite_server.json    # 墙外 VPS
mirage-rs lite-client -c lite_client.json    # 本机
```

- **平铺极简配置**: `{listen, port, server, server_port, password, sni, auth?}`,
  没有 inbounds/outbounds/routing 嵌套。客户端仅 `server`/`server_port`/`password` 必填。
- **不加载**: 分流规则、DNS/fake-IP、透明代理、Web 看板、geo 数据下载、配置热重载。
- **一个都没少**: 加密、TLS 指纹伪装、握手认证、认证失败转发真站。**协议与完整版完全一致,
  轻量客户端可直连完整版服务端, 反之亦然。**
- **仅 TCP**: SOCKS5 UDP ASSOCIATE 按规范回 `REP=0x07` 明确拒绝, 而非静默断开让客户端干等。
  代价是 QUIC/HTTP3 走不了代理(浏览器会自动回落 TCP)。
- 客户端同样带**开放代理告警**: 监听非回环且未配 `auth` 时启动 WARN。

**实现上刻意不复制引擎**: 把平铺配置在内存里展开成内部 `CoreState`(单个 mirage 出站 +
空规则 + default 指向它), 之后直接复用现成的 `proxy_tcp_target` / `mirage_server::start_server`
—— 隧道池、换隧道重试、中继、伪装握手都只有一份实现, 不会与完整版分叉。
「全部转发」因此是**结构性成立**的: 规则为空, 一切都落到唯一的 mirage 出站,
不存在"漏配某条规则导致直连泄漏"的可能。

> 📌 轻量模式是**运行时**精简, **不是**单独编译的小二进制 —— 体积与完整版相同(仍 ~15M)。
> 真正减小体积需要 cargo feature 把 router/dns/api/ebpf 整块编译掉, 那是另一件事。
>
> 📌 `OutboundManager` 会无条件注入内置的 `direct`/`block` 节点, 轻量模式下它们**存在但不可达**
> ——「全部转发」的保证来自路由(零规则 + default 指向 proxy), 不是来自"没有 direct 出站"。
> 已有单测守这条线。

验证: 6 个单测 (配置默认值/必填项/认证/路由全部指向隧道) + 2 个端到端集成测试 ——
起真的 lite-server + lite-client, 经 SOCKS5 打通到本测试自建的 echo 服务并校验数据原样往返
(不依赖外网, CI 可稳定跑), 以及 UDP ASSOCIATE 确实回 `0x07`。
另在真机手工验过一条经隧道的真实 HTTPS 请求。

### feat(cli): 新增 `import` 子命令 —— 导入 mirage:// 节点

```bash
mirage-rs import -c config.json "mirage://密码@host:443?sni=www.apple.com"
```

把节点 URI 转成一个新的 mirage 出站并写回配置。URI 格式与 `install.sh` 的
`build_node_uri` / `parse_node_uri` 严格对齐(密码与 SNI 均百分号编码)。

- **交互询问 tag 并强制不冲突**: 撞上已有出站 tag 就提示现有 tag 列表并**重问**,
  绝不覆盖既有节点(静默顶掉用户的节点是不可接受的)。默认值取 URI 的 host;
  若默认值本身已被占用则不提示它, 免得回车又撞车。stdin 非 TTY 时同样可用(读管道)。
- **写回是破坏性操作, 三重保护**: 先备份 `config.json.bak` → 写 `.tmp` → `rename` 原子替换,
  任一步失败都不留半截配置; URI 解析失败时**完全不碰**原文件。
- **走 `serde_json::Value` 增量插入**, 保留原键序与全部字段(含未知字段), 不会把配置
  过一遍结构体重写。
- **只加出站、不动路由**: 要不要让流量走新节点是策略决定, 命令结束时提示后续步骤
  (改 `default_outbound` 或某条 rule → `check` → 重启)。
- URI 解析独立为 `src/node_uri.rs` 便于单测: 7 个用例覆盖百分号解码、`+` 保持字面量
  (当空格会改掉密码)、域名 host、各类畸形输入、非法转义、未知 query 参数向后兼容。

验证: 5 个集成测试跑真二进制 —— 正常导入(含密码 `p%40ss` → `p@ss` 解码)、
冲突后重问且既有出站不被顶掉、备份内容正确、导入后仍能通过 `check`、
URI 非法时配置零改动。"tag 冲突必须拒绝"做过变异验证(去掉冲突判断 → 该测试如实变红)。

### feat(cli): 新增 `check` / `format` 子命令

启动时校验有个顺序问题: 你得**先重启服务**才知道配置有没有问题 —— 对网关来说反了。
新增两个纯本地子命令(不初始化日志、不起服务、不碰网络):

```bash
# 校验, 有问题即非零退出 → 可当重启前的闸门
mirage-rs check -c config.json && systemctl restart mirage-rs-client

# 格式化输出到 stdout (不改原文件)
mirage-rs format -c config.json > config.pretty.json
```

- **`check` 与启动时校验共用同一个 `parse_with_diagnostics`, 但严格度刻意不同**:
  启动求"不中断"(问题只 WARN), `check` 求"拦得住"(有问题即 exit 1) —— 后者的用途正是当闸门。
  读不了文件 / 解析失败 / 有校验问题, 三种情况均非零退出。
- **`format` 走 `serde_json::Value` 而非 `Config` 结构体**: 后者会**吞掉未知字段**并把默认值
  写进来, 那是改写不是格式化。为此给 serde_json 开 `preserve_order` feature ——
  默认 `BTreeMap` 会把键**按字母序重排**, 格式化器不该动用户的键序。
- **只输出到 stdout, 不就地改写**: 就地重写一个正在跑的配置风险太大; 要落盘用重定向。

验证: 7 个集成测试直接跑编译产物断言**退出码**(库函数测不到这个契约)与关键性质 ——
键序保持、未知字段保留、幂等、各类失败均非零退出。"有问题必须非零退出"做过变异验证
(改成返回 0 → 该测试如实变红)。

### feat(config): 启动时校验配置 —— 拼错的键不再静默失效

配置此前**只做语法解析**: 键名拼错被 serde 静默忽略(用户永远不知道自己配了个寂寞),
引用了不存在的 outbound 也毫无提示。`api.secret` 那个"设了却零作用"的 footgun 正是这类的产物。

- **未知字段检测**: 借 `serde_ignored` 逐个报出被忽略的键并**带嵌套路径**
  (如 `routing.defalut_outbound`)。不手维护字段名清单 —— 那种清单必然与结构体漂移,
  比没有更糟。新增依赖仅 `serde_ignored`(传递依赖只有 `serde_core`)。
- **语义校验**(语法合法但逻辑不成立):
  - `routing.default_outbound` / 每条 `routing.rules[].outbound` 引用的出站必须存在;
  - selector/urltest/fallback 的成员必须存在、组不能为空、不能自引用;
  - outbound / inbound 的 tag 重复定义;
  - mirage 出站的 `server`/`server_port`/`password` 非空; inbound `port` 非 0;
  - `mirage_server` 入站空密码(任何人都能连)。
- **刻意不致命**: 全部走 WARN, 不阻止启动。配置里多一个字段就让网关起不来, 代价远大于
  收益(升级二进制时尤其危险)。校验的价值是"让你看见", 不是"拦住你" —— 与 `api.secret`
  当初"保留字段 + WARN"的处理一致。无问题时打一行"配置校验通过"。

验证: 11 个测试覆盖每一类问题(含嵌套路径未知字段、自引用、空组等)。
另拿仓库内真实配置回归确认**零误报**(`config.json` / `sandbox_config.json` 均干净)。

> 📌 顺带发现(**未修**, 非本次引入): 仓库里的 `transparent_config.json` 用的是旧 schema
> (`outbounds` 写成带 `default` 的 map 而非扁平数组 + `routing.default_outbound`),
> **原有解析器同样解析失败**, 且全仓库无人引用 —— 是个陈旧样例文件。

### feat(install): 服务端配置可自动搜索同 ASN 伪装域名 (`f48a78a`)

`config_server` 问伪装 SNI 前新增**可选(默认否)**的自动搜索: 调 `tools/find_camouflage.py`
扫本机 /24 的 :443, 从证书 SAN 找出真实托管在同 ASN 的域名, 让 SNI 与目的 IP 名实相符,
削弱"SNI 归属 ASN vs 目的 IP ASN"一致性检查这个被动暴露面。搜到的域名作为**默认值**喂给
原有 `ask_camouflage_host`, TLS1.3 探测 + 人工确认流程不变。

- 不在 install.sh 内复制那 240 行逻辑: 本地仓库副本优先, 否则按 `MIRAGE_TAG` 从
  raw.githubusercontent 拉 (适配 `curl | bash`), 避免两处漂移。
- **刻意不自动采用推荐值**: 廉价机房同段邻居很可能本身也是代理/空壳站, 须人工过目。
- 全路径优雅降级回落手动输入: 缺 python3/openssl、IP 无效、下载失败、扫描超时(300s)、用户留空。

### feat(tools): `find_camouflage.py` —— 零 API key 找 SNI/IP 一致的伪装站 (`42b402d`)

RIPEstat(keyless) 查 IP→ASN/前缀, 扫段抓 :443 证书读 SAN 得"域名↔所在 IP", 再校验解析回本前缀 +
TLS1.3 + HTTP 可达并打分排序。**ASN/前缀级**一致(打掉常见 NGFW 检查), 非精确 IP 绑定。

### feat(udp): 透明 UDP uplink 机会式合帧 (`4f5b299`)

原来每个 UDP 数据报 1:1 封成一条 TLS 记录, QUIC 满 MTU 时记录众数卡在 ~1372B, 与真 bulk
HTTPS-over-TCP 塞满 16KB 记录的尺寸签名不同 = 长度指纹。改为 `send_data` 前用 `try_recv`
非阻塞榨干已排队的突发包合进同一条记录 (`UPLINK_COALESCE_CAP=16KB`)。只合并本已在 channel
里的包 → **近零新增延迟**; 服务端 reassembler 本就支持一条记录内多帧, **无协议/服务端改动**。

### feat(net-monitor): netlink 变更过滤, 收窄误 flush (`8dd0159`)

链路自愈原来收到任何 LINK/ADDR/ROUTE 通知就清空重建连接池, 忙机 (BGP/大量具体路由增删) 上会被
路由抖动频繁误 flush。新增 `should_bump` 解析 RTM_* 类型: LINK (载波 up/down)、ADDR (源地址
增删/续租) 一律触发, ROUTE **只认默认路由** (`rtmsg.rtm_dst_len==0`)。ENOBUFS (溢出无法解析)
保守仍触发。6 单测 + 变异验证。

> 注: 收尾一份工作区遗留 WIP。该 WIP 只认默认路由、**漏掉 LINK/ADDR** → "换源 IP 但网关不变"
> (DHCP 续租常见) 只发 `RTM_NEWADDR` 会被漏刷, 隧道绑旧源 IP。本次补回。

### fix(geo): `.dat` 解析两处健壮性 (`a935567`, `ceba36e`)

- **不再假设 protobuf 字段序**: 原代码只在 `code` 已知时才解析 entry, 若某 `.dat` 把 entries 排在
  code 之前, **整个国家的规则会被静默丢弃**。改为先收集 entries、与 code 收齐后再判定。
- **跳过 fixed32/fixed64 而非 break 截断**: wire-type 1/5 原落到 `else` 直接 break, 遇到 schema
  扩展或非标 `.dat` 会截断解析、丢掉其后内容。改为正确跳 8/4 字节继续。
- 两处均带回归测试并做过**变异验证**(退回旧逻辑测试如实变红)。

### docs(brain): 引入 Open Project Brain (`eb1b73d`)

落地 `BRAIN.md` + `brain/`(6 根页 + 15 个页面), 沉淀"代码里读不出来"的判断: eBPF 职责边界、
splice(2) 弃 sockmap 的反转、fake-IP 远端解析的前提、只对首 SYN sk_assign 的不变式、
auth 时间容差的 bootstrap 死锁、外部审计"真伪参半"的核实方法论(含**已证伪条目**防重复返工)。

### chore

- gitignore `__pycache__` (`6297a74`)。
- 移除 `memory-bank/`(v0.2–v0.3 期的本地知识残留, 已被 `brain/` 取代; 原本就被 gitignore 未入库),
  并清掉 `.gitignore` 中悬空的对应规则。

---

## [v0.6.0-alpha.1] - TLS 指纹多 profile 轮换 (2026-07-19)

单一 ClientHello 指纹意味着该出口所有连接共享一个 JA3/JA4, 便于聚类。改为按权重轮换三套
**字节级**仿真的真实客户端指纹, 稀释单一出口特征。各 profile 均取自真机抓包。

- **Firefox 152** (`be4e8be`): 无 cipher GREASE、固定扩展定序(17 个)、3 个 key_share
  (MLKEM768+X25519+P256)、`record_size_limit`、`delegated_credentials`。
- **OkHttp / Android Conscrypt** (`579e6b1`): 有 GREASE 但**无 MLKEM**(X25519/P256/P384)、
  TLS 1.3–1.0、8 个 sigalg、无 ECH/ALPS、padding 到 512。同时收敛服务端 ServerHello 曲线,
  使模板对三套 profile 通用。
- 加权选择 `pick_profile()`: Chromium ~60% / Firefox ~25% / OkHttp ~15%。
- **JA4 对照 harness** (`1aa4dd5`): `dump_tls --ja4 <hexfile>` 可算抓包的 JA4;
  `ja4_locks_all_profiles` 锁死三套指纹值防回归。

> ⚠️ 服务端与客户端**都需升级**到 0.6.0-alpha.1 才完整生效。

---

## [v0.5.0-alpha.8] - 审计加固 + dns_xdp 现代内核复活 (2026-07-18)

### harden: 外部审计中 4 处真实缺口 (`648579d`)

逐条对 HEAD 核实一份 7 项审计后只修其中真实的 4 条(其余证伪不动):
DNS `0xC00C` 自引用(构造包可让 `make_fake_ip_response` 生成自引用指针 → 加 `QDCOUNT>=1 &&
question_end>12` 门控 + 二道防线)、`dns_xdp` 补 `ihl != 5` 守卫、fake-IP flush `.tmp` 窄竞态
(加 `flush_lock`)、fake-IP 池未排除 `.0`/`.1`/广播。

### fix(xdp): dns_xdp 在内核 ≥6.1 上加载被拒 —— 且一直如此 (`0e3f47e`)

**即用户网关上 XDP 极速 DNS 从未生效**, 全靠用户态兜底。三个根因: ① `static inline` →
`__always_inline`(否则编成 BPF-to-BPF call, 传包指针验证器跟不住); ② `int off` → `__u32`
(符号扩展判负越界); ③ 10×63 嵌套 unroll → 单层扁平状态机(嵌套内联状态爆炸 E2BIG)。
重写的 `hash_domain` 与用户态 `update_dns_cache` **逐字节一致**。补 `verify_dns_xdp`
端到端 + 哈希一致性验证器 (`f2f7ffd`) 并接入 CI。

> ⚠️ 该路径对带 EDNS0 的查询处理仍不完整, `advanced_dns.xdp_interface` **默认不开也不建议开**。

---

## [v0.5.0-alpha.7] - auth 时钟容差 + UDP 快速拆流 (2026-07-18)

### fix(auth): 时钟偏差把客户端**永久锁死** (`3f0aa00`)

真机 e2e 第一步即撞上: 两端时钟差 >10s → 握手令牌时间戳被拒。**这是设计缺陷非数值问题** ——
首次握手用的是未经校正的裸系统时钟, 而 `TIME_SYNC` 帧**只在 auth 成功后**下发 → auth 卡在窗口上
→ TIME_SYNC 永远 bootstrap 不了 → 偏差大的机器永久锁死。且 auth 失败必须走 camouflage 转发,
不能回时间提示(否则破坏抗探测), 所以该窗口是首次握手唯一容错。

- `TOKEN_TS_TOLERANCE_SECS` → 服务端 config **`auth_ts_tolerance_secs`(默认 60)**, 旧 config 兼容。
- 重放缓存保留桶数从容差自动推导; 客户端"TIME_SYNC 解密失败"改一次性详细提示(查密码/时钟/NTP)。

> 💡 同一病灶群: **NTP 若走代理** → 隧道挂则 NTP 同步不了 → 时钟更偏 → 隧道更挂 死循环。
> 建议路由加 `{"outbound":"direct","port":[123]}`。

### feat(udp): 上游过滤 UDP 时快速拆流 + 诊断 (`3080a49`)

真机 e2e 暴露: 某些 VPS 过滤出向 UDP:443/QUIC 回包, 每条流白占一条隧道 60s。加
`FIRST_DOWNLINK_TIMEOUT=8s` 快速拆流 + 零下行时一次性 WARN"上游可能滤 UDP";
服务端 `udp_relay` 的 `send_to` 错误不再静默吞掉。

---

## [v0.5.0-alpha.6] - 孤儿 tc 过滤器黑洞 + 三个审计纰漏 (2026-07-17)

### fix: 孤儿 tc 过滤器把 LAN 打成黑洞 (`3eb675b`)

进程被 SIGKILL/停止后 tc 过滤器**仍挂在网卡上**(tc 持有 prog 引用), 而 `fwmark→local` 的
`ip rule` 由独立 service 装、只在卸载时删。两者叠加把每个已建流的包引到 local 表却无 socket
可收 → **整段非直连 TCP 黑洞**。修: 已建流打 mark **前**先 `bpf_sk_lookup_tcp` 探 listener,
不在就走正常转发 —— **代理没了顶多不加速, 不该断网**。同时补退出时显式 detach。
其余三条: guard 释放序、陈旧 resolv 备份、裸 IP 连接无超时。

### ci: netns eBPF 验证器接入 CI (`607d175`)

5 个验证器进 `ebpf-verify` job。**关键前提**: 它们原先只 println PASS/FAIL、从不返非零退出码
(是诊断工具不是测试), 直接进 CI 会永远绿灯 = **假信心比没 CI 更糟** → 先全改成 `exit(1)` 才接入。
故意跑在 ubuntu-22.04 / 内核 5.15 以检验 README 声称的"≥5.10 支持"。

> ⚠️ 孤儿过滤器验证器经多轮尝试后**仍从 CI 摘掉**(`b96ac23`): 5.15 上红的是**测试脚手架**竞态
> (`connect: Network is unreachable`, 根本没走到 sk_lookup), **产品已确认无恙**。脚本保留, 本地 ≥6.1 可跑。

---

## [v0.5.0-alpha.5] - 两个真实 footgun (2026-07-17)

### fix: `proxy_local` 停服导致整机丢 DNS (`2ad65fa`)

比预想更严重: `resolv.conf` 指向 127.0.0.1 是**安装时**做、只在**卸载时**还原, **完全没绑服务
生命周期** → **`systemctl stop` 就让机器彻底没 DNS**(不只 SIGKILL)。修: 新增
`/usr/local/sbin/mirage-resolv-guard {apply|restore}`, unit 加 `ExecStartPost`/`ExecStopPost` ——
systemd 即便主进程被 SIGKILL 也保证跑 `ExecStopPost`。5 场景实测(含"重复 apply 不冲掉备份")。

### fix: 废弃 stub 配置误导用户

`api.secret` 被解析但**零使用**、不提供任何鉴权(alpha.2 加了真 `gui.token` 后更易混淆)。
不静默删(设过的人永远不知被骗), 改为**保留字段检测 + 启动 WARN**; `advanced_dns.rules` 同样处理。

---

## [v0.5.0-alpha.4] - fake-IP 映射持久化 (2026-07-16)

`973c8b2`: opt-in 写专用缓存文件, 重启后 fake-IP↔域名映射不丢, 免得客户端持有的旧 fake-IP
失效导致代理连接断代。

## [v0.5.0-alpha.3] - DNS 响应缓存 (2026-07-16)

`a512689`: 接上原为 stub 的 `advanced_dns.cache`, 按 TTL 缓存上游响应。
抗审查路线是**远端解析 + 缓存**, 而非墙内不可靠的 DoH/DoT。

## [v0.5.0-alpha.2] - Web API bearer token 鉴权 (2026-07-16)

`395488d`: 原 `api/` 全 endpoint **无鉴权**, 绑 0.0.0.0 即泄漏日志/配置。新增 config `gui.token`
(可选, 不设=向后兼容), axum 中间件常量时间比较, token 三来源 (Bearer / cookie / `?token=`);
根路由带合法 `?token` 即种 HttpOnly+SameSite=Strict cookie。非 localhost 暴露且未设 token 时启动 WARN。
`install.sh` 选 0.0.0.0 自动生成 32 位 token。

## [v0.5.0-alpha.1] - 连接健康 / 链路自愈 (2026-07-16)

- **WarmPool 死链主动剔除** (`4c6848a`): `get()` 加 stale 探测, handler 首次写失败自动换隧道重试。
- **链路自愈** (`48b800e`): netlink 订阅 LINK/ADDR/ROUTE 变更, 网络一变 (Wi-Fi↔蜂窝 / 宽带续租 /
  载波变化) 就广播 epoch, WarmPool **清空整池**并用新路径并发重建 —— 毫秒级切换而非等超时。
  500ms 去抖合并一次切换产生的十几条消息。

---

## [v0.4.5] - DNS 抗风暴 + 全量审计 + 日志滚动 (2026-07-15)

**0.4.5 收尾版** (final, 去 `-alpha` 标记版本完成)。汇总 alpha.21 → final 的改动。
**后续开发从 `v0.5.0` 版本号开始。**

### feat: 抗 DNS 查询风暴 (根治开网页时 ~11s 卡顿)

真机定位: 两次 curl 间隔 <1s 快、>1s 就 11s。根因是 fake-IP 响应 TTL 过短 + 空答复
无负缓存, 导致客户端 (Windows) 反复重查网关 DNS, 查询量被 grass.io/遥测放大数百倍 →
网关 DNS 偶发丢包 → Windows 重传累积 ~11s。

- **fake-IP A 记录 TTL 1s → 300s** (alpha.33): fake-IP 映射本就稳定 (一域名固定一 IP,
  池 131071 淘汰极罕见), 1s 短 TTL 纯属自造风暴。提到 300s 查询频率降数百倍。
- **AAAA / type65(HTTPS) 空答复带合成 SOA 负缓存** (alpha.34): 原空答复 NSCOUNT=0 无 SOA,
  按 RFC 2308 客户端不做负缓存 → `getaddrinfo` 每次并发重查 AAAA/type65 (残留风暴源)。
  现 authority 段带一条最小 SOA (owner/MNAME/RNAME 均压缩指针 0xC00C, TTL/MINIMUM=300),
  客户端缓存 NODATA 5 分钟。dnspython 校验 wire 合法。

### feat(dns): 国内域名上游解析加重传 + 多上游并行兜底 (alpha.35)

国内/直连域名走真实上游 (`udp_query` → cn_dns)。旧实现**单上游单发不重传**: 上游 (114/223
公共 DNS 高峰偶发丢包/限速) 丢一个 UDP 包就返 None → 网关不回 → 客户端自身重传累积 ~11s
(国外走 fake-IP 不碰上游故不暴露)。

- `udp_query` 重写为**多上游并行 + 重传**: 每轮向所有上游各发一份, 等 800ms, 无匹配则重传,
  最多 3 轮 (总上限 2.4s ≪ 11s)。响应一到就返回 (健康时仍几十毫秒), 只有真丢包才重传/换上游。
  校验 tx_id + QR + ≥12B 头, 丢串扰/迟到包。
- `cached_cn_dns: Option<SocketAddr>` → `Vec<SocketAddr>`, 收集**全部** `tag=cn/direct` resolver。
  尊重配置不掺公共 DNS (免污染内网视图); 一个都没配才默认双公共兜底 (114 + 223)。
- `install.sh` 透明网关模式新增"备用直连 DNS"询问, 默认生成双 direct 上游。

### feat(log): 文件日志按大小自动滚动 + gzip 压缩归档 (final)

`config.log_file` 此前无限 append 单文件, 长跑网关会撑爆磁盘。

- 单文件超 **10MB** 滚动: 归档号后移 (.1.gz→.2.gz …), 当前日志改名后重开新文件, 后台线程
  gzip 临时文件为 .1.gz。保留最近 **10** 份压缩归档 (约 10:1 → 磁盘 ~10MB)。
- 压缩在后台线程, 不阻塞日志写入热路径; best-effort, 任一步失败只 eprintln 不影响记日志。
- 纯 Rust flate2 (miniz_oxide 后端, 无外部 gzip / C zlib 依赖)。

### fix: 全量代码审计 5 修 (alpha.34)

逐行审计 ~11K 行 Rust + 852 行 eBPF C, 修复:

- **F4** `sniff.rs::parse_tls_sni` `<43` off-by-one → `data[43]` 越界 panic (裸 IP 发恰好
  43B TLS 首段触发, tokio spawn 内被捕获但远程可刷 panic 日志)。改 `< 44`。
- **F7** `geo.rs` varint 两处整数溢出: `read_varint` 无 shift 上限 (shift≥64 溢出),
  `read_len_delim` 的 `*pos+length` 回绕使边界检查失效 → 切片 panic。畸形/损坏 geo.dat 可致
  `RouterEngine::new` panic。加 shift 上限 + 减法比较。
- **F8** `dns_xdp.c` 对带 EDNS0 (arcount≥1, 现代客户端近乎必带) 的 A 查询回畸形响应 (answer
  覆盖 OPT 记录、arcount 未清)。加 `ancount/nscount/arcount==0` 守卫, 这类查询交用户态。
- **F1** `hello_auth.rs` 重放缓存桶淘汰用"token 自身桶"作参考 → 重放旧 token 复活已淘汰桶
  漏检。改用单调 hwm (只增不减)。
- **F2** `pool.rs::update_brutal_rate` 收集裸 fd 后跨 await setsockopt → fd 关闭后复用竞态
  (brutal CC 误套无关 socket)。改持锁期间直接 setsockopt。

均带回归测试。死代码 (未清, 非 bug): `spawn_fallback_monitor` / `mss_clamp.elf` / `sockmap.c::extract_ip`。

### fix: 真机部署踩坑修复 (alpha.27-31)

- **透明 listener EINVAL 根治** (alpha.31): 真凶是 `nix::Backlog::new(1024)` —— nix 校验
  val < SOMAXCONN, 该内核 SOMAXCONN=128, 1024 直接 EINVAL (与 IP_TRANSPARENT/sockmap 无关)。
  改 `Backlog::MAXCONN`。此前三次误判一个 EINVAL 的教训: 逐 syscall 加 context 让日志说话。
- **透明网关 fake-IP TCP/UDP 真机端到端首次跑通** (alpha.30/31): 满屏 `[TPROXY]` google/bing/github。
- 本机流量走代理 (cgroup/connect4, alpha.19+, 默认关): connect4 改写 fake-IP 段目的 → 本地
  listener, sockops 存 srcport→origdst 供反查。

### 协议调整摘要 (v0.4 → v0.4.5)

- **DNS 空答复带合成 SOA** (RFC 2308 负缓存); **fake-IP A 记录 TTL 固定 300s**。
- 时间同步内嵌协议 (v0.4 起): 服务端 handshake 后经加密 channel 下发 `[0x01][ver][8B unix sec]`
  帧, 客户端写全局 offset, 0 外部依赖 / 0 探测指纹。
- ⚠️ 密码派生 info 常量 `pyrealiy-session` 是历史冻结值 (拼写错误), **切勿"修正"** —— 两端
  必须完全一致, 改了新旧版本密钥不兼容、静默解密失败。

---

## [v0.4.5-alpha.20] - UDP 透明代理 + Mirage-UDP 隧道腿 (2026-07-07)

真机测试里程碑版。alpha.19 以来 16 个 commit, 补齐 UDP 透明代理整条线。

### feat: UDP 透明代理 (sk_lookup + IP_TRANSPARENT)

- `transparent.c` 按 `ctx->protocol` 分流, UDP → 新 `mirage_udp_sk` sockmap
  (原来 UDP 被 assign 给 TCP socket 而丢, QUIC/HTTP3/DNS-over-UDP 走不了)。
- `transparent_udp.rs`: 主 socket IP_TRANSPARENT+IP_RECVORIGDSTADDR recvmsg 取
  (client, orig_dst); 反查域名 → 路由 Direct 直发 / Block 丢 / **Mirage 走加密
  隧道**; 回包经绑 fake-IP:port 的 IP_TRANSPARENT+FREEBIND reply socket 伪源发回。
- **Mirage-UDP 隧道腿**: FlowSink{Direct|Mirage} per-flow mpsc, 封帧 ATYP=3 域名
  让服务端远程解析, 帧格式对齐 mirage_server::udp_relay。
- 健壮性: FlowSlot::Setting 原子占位 (防突发重复建流), reply socket 引用计数 +
  FlowGuard RAII 保证清理, MAX_FLOWS=4096 总上限 + MAX_MIRAGE_UDP_FLOWS=256 子上限。
- **内核机制已在 kernel 6.1 隔离 netns 实测** (`examples/verify_udp_transparent.rs`):
  IP_ORIGDSTADDR 正确报 fake-IP, IP_TRANSPARENT 源伪造 ✅, 无需退回 TPROXY。

### feat(client): Direct 出口 UDP 转发 (SOCKS5 UDP ASSOCIATE)

- `handle_udp_associate_direct`: 直连出口 UDP 不再静默丢弃。

### fix: 并发/资源 bug (用户 review)

- [高危] handler.rs Mirage TCP relay 300s "绝对墙钟寿命" → 空闲超时 (长连接不再
  满 5 分钟必断)。
- [泄漏] 客户端 SOCKS UDP handle_udp_associate spawn 后 select! 无 abort → 僵尸
  泄漏 UDP socket, 补 abort。
- reply socket FD 泄漏 / 建流竞态 / 锁跨 await / reply refcount 虚漏 (transparent_udp)。

### fix(camouflage): 抗识别时序

- 暖池 SYN 阶梯延迟改抖动 (200→200~500ms, 消除机械节拍)。
- camouflage 暖连接随机寿命 15~27s (消除 8-SYN 集体过期脉冲)。

### install.sh

- 识别 32 位架构 (i686/armv7); 二进制更新选项 (版本比对); 显示服务端节点配置;
  节点串移除 brutal (单边加速服务端专属)。

### ⚠️ 未竟

- IPv6 (Direct/透明 UDP 仍 v4-only); 真机整链路端到端冒烟未做; SNI 伪装身份取舍
  (speedtest QoS vs 被动隐蔽)。见 known_issues。

## [v0.4.5-alpha.19] - Release CI 增加 32 位构建目标 (2026-07-06)

### ci(release): i686 + armv7 (gnu/musl, 纯用户态)

**背景**: 面向老式 x86 软路由与 ARMv7 路由器 (OpenWrt/树莓派). 这类设备内核多
<5.9, sk_lookup 透明代理不可用, 故新目标**不含 ebpf feature** (纯用户态 SOCKS/
上游代理).

**新增 4 个 release 产物**:

- `mirage-rs-i386`       — i686-unknown-linux-gnu
- `mirage-rs-i386-musl`  — i686-unknown-linux-musl (静态)
- `mirage-rs-armv7`      — armv7-unknown-linux-gnueabihf
- `mirage-rs-armv7-musl` — armv7-unknown-linux-musleabihf (静态)

**实现**: matrix 每行加 `ebpf` 布尔字段; BPF 编译与嵌入校验两步 `if: matrix.ebpf`;
构建命令按 `ebpf` 字段条件注入 `--features ebpf`; 补 i686/armv7 gnu 交叉工具链与
armv7 LINKER env; musl 目标复用现有 cross-rs 分支. `build.rs` 缺 clang 时回退已
提交的 `ebpf-src/*.elf`, 且 `include_bytes!` 受 `#[cfg(feature=ebpf)]` 门控, 故
无 ebpf 构建在 cross 容器内不会因缺 clang 失败.

### 影响面

- 仅 CI/发布产物; 无源码/协议/配置变化

## [v0.4.5-alpha.18] - GUI 面板闪烁 + 日志方块修复 (2026-07-06)

### fix(gui): eBPF/Brutal/Tunnels 面板闪烁 (try_lock → lock().await)

**问题**: GUI 的 "Active BPF Tunnels" / "eBPF Engine" / "Brutal CC" 状态时有时无
闪烁. 根因: `overview` + `bpf_tunnels` handler 用 `engine.try_lock()` 读 BPF map,
锁被 sampler (每秒读 stats) / brutal 动态速率 (读 RTT) 短暂占用那一帧 try_lock
失败 → 返回 engine_online=false / tunnel_count=0 / brutal_cc_active=false / 空
tunnel 列表 → 面板消失; 下一帧拿到锁又出现.

**修复**: 两个 handler 改 `engine.lock().await`. handler 是 async, 锁只被持有
~µs (读内核 map), await 等一下即可, 消除闪烁. (accept loop 的 try_lock 保留 —
那里不能阻塞 accept.)

### fix(log): GUI/文件日志 ANSI 颜色码渲染成方块

**问题**: GUI 日志面板 (和 log_file) 满屏方块. 根因: tracing fmt subscriber 默认
开 ANSI 颜色, 同一 formatter 的带颜色码字节同时写 stdout + GUI MemoryLogger +
文件, GUI/文件把 ESC 转义码渲染成方块 (mojibake).

**修复**: subscriber 加 `.with_ansi(false)`. 服务端 daemon 不需要终端颜色, 纯文本
全通道 (stdout/GUI/文件) 干净且 grep 友好.

### 影响面

- 仅 GUI/日志展示; 非破坏性, 无协议/配置变化

## [v0.4.5-alpha.17] - 客户端握手放弃超时随机化 (消除时序指纹) (2026-07-06)

### security(client): read_server_handshake 超时随机化

**背景**: 握手审计残余项. 客户端读服务端 ServerHello flight 时用两个**固定**放弃
超时: 12s (等 ServerHello 前) / 1.5s (CCS 后等加密 flight). 正常情况客户端看到
0x17 立即返回不等超时, 但 GFW 若**主动操纵服务端响应时序** (拦截/延迟 ServerHello)
测客户端恒定的放弃时间 (恒 12s / 恒 1.5s), 可识别为 Mirage 客户端 (真实浏览器
超时行为各异).

**修复**: 每连接各随机一次 (非每轮循环, 保持单次握手内一致), 围绕原值抖动:
- pre-CCS: 10~14s (原 12s)
- post-CCS: 1.2~1.8s (原 1.5s)

仍足够宽容真实慢链路, 但放弃阈值不再恒定.

### 影响面

- 仅客户端; 客户端行为非主防御面 (GFW 主要观察服务端), 低危补漏
- 非破坏性, 无协议/配置变化

## [v0.4.5-alpha.16] - UDP DNS 缓存/限流 + 时钟回拨 panic 兜底 (2026-07-06)

### fix(server): UDP 转发 DNS 走缓存 + 并发限流 (防阻塞池饿死)

**问题**: `mirage_server/udp_relay.rs` 对每个域名类型 (ATYP=3) 的 UDP 包**裸调
`tokio::net::lookup_host`**, 完全绕过 resolver.rs 的 60s DNS 缓存. UDP 无连接,
高频 QUIC/HTTP3 (网页瞬间数百包) 或恶意唯一域名洪泛 (每包随机 `*.invalid`) 会瞬间
向 tokio spawn_blocking 阻塞池 (默认 512 线程) 发起海量 getaddrinfo, 打满阻塞池
饿死其他异步任务 (文件 IO / 其他 TCP 解析).

**修复**:
- `resolver.rs` 新增 `pub(crate) resolve_first(host, port) -> SocketAddr`: IP 字面量
  直接构造; 域名走 60s 缓存 + IPv4 优先. UDP relay 改用它.
- `resolver.rs` 加**全局 DNS 并发信号量** (128 permit): resolve_cached 实际
  lookup_host 前先拿 permit, 唯一域名洪泛时新解析排队而非无限 spawn, 给阻塞池留
  384 线程. 缓存命中不占 permit. 同时保护 TCP connect_smart + UDP resolve_first.

### fix: 时钟 < UNIX_EPOCH 时的 panic 兜底 (嵌入式/软路由)

**问题**: OpenWRT 路由器/无 RTC 软路由开机未同步 NTP 时, 系统时钟可能 < UNIX_EPOCH,
`SystemTime::now().duration_since(UNIX_EPOCH)` 返回 Err, `.unwrap()` 直接 panic 崩溃
整个进程. 排查发现 **3 处生产 + 1 处测试** 同类隐患 (报告只提了 control.rs 一处,
最致命的是核心时间基准 `now_sec`):
- `time_sync::now_sec` (全代码库时间基准, token/replay 都用) 🔴
- `time_sync::set_offset_from_server_time` (客户端 offset 计算)
- `mirage_server/control.rs` TIME_SYNC 帧 (报告指出的)
- `time_sync` test helper

全部 `.unwrap()` → `.unwrap_or_default()`: 时钟异常回落 0 (epoch), NTP 同步后自动
恢复, 服务端 TIME_SYNC 也纠正客户端 offset. 绝不在核心协议时间运算里 panic.

### 影响面

- 仅服务端 (UDP relay) + 全平台 (时钟兜底); 非破坏性, 无协议/配置变化

## [v0.4.5-alpha.15] - handshake_cache 启动主动预热 (消除冷启动窗口) (2026-07-06)

### security(server): HandshakeCache 服务端启动时主动预热

**背景**: 旧版 HandshakeCache 是**懒预热** —— 首个连接调 get_server_hello 时才
fetch 真实模板. 造成冷启动窗口: 服务端重启后头几个连接明显更慢 (触发/等待 fetch)
或拿到 fallback. GFW 探针在重启窗口打过来能捕获这个时序异常, 识别差别对待.

**修复**:
- 新增 `handshake_cache::prewarm(camouflage_host)`: 抢先拉真实模板填充 cache +
  启动 30min 刷新任务.
- `mirage_server::start_server` 在 **accept loop 之前 await prewarm** —— 首个连接
  到来时 cache 已就绪, 无冷启动窗口.
- camouflage 不可达时 prewarm 最多阻塞 ~5s (fetch 内建超时) 后放行, cache 留空由
  懒路径在首连接兜底, 不长期挂起启动.

### refactor: 去重 warmup 逻辑

抽出 `fetch_batch` (并发拉 5 模板) + `spawn_refresh_task` (幂等, REFRESH_SPAWNED
守卫全局只一个刷新任务) + `cache()` helper. prewarm 与懒路径共用, 消除原
get_server_hello 里内联重复的 fetch-loop + refresh-spawn.

### 影响面

- 仅服务端; 启动多 ~1 RTT (camouflage 可达时) 或 ~5s (不可达时) 换取无冷启动窗口
- 非破坏性, 无协议/配置变化. 懒预热路径保留作兜底

## [v0.4.5-alpha.14] - fallback 合成 ServerHello 质量提升 (2026-07-06)

### fix(crypto): handshake_cache fallback 合成模板结构合法化

**背景**: camouflage_host 从启动起不可达时, get_server_hello 回落
`fallback_server_hello` 合成模板. 旧版有三处破绽:
- **key_share 畸形**: `0033 0004 001d 0017` 声明 X25519 key 长 23B 但后面 0 字节
  → 真实 TLS 解析直接报错
- **加密 flight 仅 21B**: 真实 TLS 1.3 的 EncryptedExtensions+Certificate+
  CertVerify+Finished flight 约 2-5KB (证书链主导), 21B 一眼假
- **cipher 硬编码 0x1301**: 不看 ClientHello 是否提供

**修复**:
- key_share 改合法: `0033 0024 001d 0020` + 真实 32B X25519 随机公钥
- `pick_cipher`: 从 ClientHello 解析并选客户端**确实提供**的 TLS 1.3 cipher
  (偏好 AES256>AES128>ChaCha)
- 加密 flight 改 ~2.8-4.2KB 随机 (单条 ApplicationData record), 模拟真实证书
  flight 尺寸

### ⚠️ 根本限制 (诚实声明)

fallback 无真实后端, 无法产出有效证书/CertVerify/Finished. 完成完整握手的**深度
探针必然识破** (推导密钥解密加密 flight → MAC 失败). 本次改进只骗过被动观测 +
浅层探针 (只读 ServerHello 不完成握手). **真正的解**: 保持 camouflage 可达 /
多域名备份 —— fallback 是最后回落, 不是主防线.

### test

新增 handshake_cache 单元测试: pick_cipher 从提供列表选中 / fallback ServerHello
结构合法 (key_share X25519 32B、supported_versions TLS1.3、flight 尺寸、长度自洽).

## [v0.4.5-alpha.13] - auth-succ/fail 时序对齐 (消除差别对待侧信道) (2026-07-06)

### security(server): auth-succ 注入匹配延迟消除时序侧信道

**背景**: camouflage 系列最后一个时序侧信道.
- auth-**成功** (真实用户): 本地缓存模板回放, 首字节 ~0-1ms
- auth-**失败** (探针): 预热池转发到 camouflage_host, 首字节 ~1 RTT

真实服务器对所有连接延迟一致. Mirage 对认证/未认证**差别对待** (快/慢) → GFW
关联"真实用户秒回、我的探针慢回" → 识破服务器区别对待 = 暴露 Reality 式代理.

**为何只能延后 auth-succ**: auth-fail 无法变快 —— 探针要完成**真实 TLS 握手**,
必须转发到真站 (回放缓存模板过不了探针的真实 TLS 校验, 见 alpha.11 的教训). 所以
在 auth-succ 注入等量延迟, 使两路时序一致.

**实现**:
- `CamouflagePool`: 补给连接时测 TCP 3-way 耗时 (≈1 网络 RTT ≈ auth-fail 转发
  延迟), EWMA 平滑 (1/8 新样本) 存入 `rtt_us` atomic, 上限 1s 防毛刺.
- `handshake.rs` auth-succ: 发模板前 `sleep(rtt × [75%,125%])`. ±25% 抖动模拟
  网络方差 (固定延迟太规整反成特征).
- rtt=0 (camouflage 未测到/不可达) 时不注入, 不影响降级路径.

**代价**: 每次 tunnel build 服务端多 ~1 RTT. WarmPool 客户端预建吸收, **用户
无感** (池里有现成 tunnel).

**残余** (v2): 注入用均匀 ±25% 抖动, 真实网络抖动是右偏分布. 深度分析抖动分布
形状理论上可区分, 但需海量样本 + 分布分析, 远超当前 GFW 能力. 一阶信号 (均值差)
已消除.

### 部署建议

即使有时序对齐, 仍建议 camouflage_host 选**网络就近** (同区域/同 CDN 回源) 的站,
让 auth-fail 转发的绝对延迟本身就小 —— 对齐是兜底, 就近是根本.

## [v0.4.5-alpha.12] - CamouflagePool 死连接检测 (探针一致性硬化) (2026-07-05)

### fix(server): camouflage 预热池探活 + 转发三级降级

**背景**: CamouflagePool (alpha.7) 预热的 TCP 连接可能被 camouflage_host 的 idle
timeout 提前关闭 (FIN/RST). 之前 acquire 直接交出, 转发写入立即失败, 探针收到
RST —— 与真实站点行为不一致, 反而暴露 camouflage (GFW 探针做后端一致性检测时可
识别).

**修复**:
- `camouflage_pool.rs::is_alive`: 非阻塞 `try_read` 探活. 未发 ClientHello 的预热
  连接健康态应无可读数据无 EOF → WouldBlock=活; Ok(0)=FIN 死; Ok(n)=意外数据
  不可用; 其他 Err=RST 死.
- `acquire()`: 逐条探活, 跳过并丢弃死连接, 返回首条存活的 (全死则 None).
- `maintain()` 清理: 过期条件加上 `is_alive`, 主动清死连接不只按 age.
- `camouflage.rs`: 三级降级 + 写失败探测 —— pooled (已探活) → 写失败则即时
  connect → 再失败才回落 HandshakeCache 模板. 堵住 acquire 后的微秒级 TOCTOU
  竞态 (拿到时活写入前刚关), 确保探针永远收到真实站点响应或干净降级, 不会收到
  死连接的 RST.

### 影响面

- 仅服务端 auth-fail (探针) 路径; 正常认证/数据转发不受影响
- 非破坏性, 无协议/配置变化

## [v0.4.5-alpha.11] - TLS 指纹 byte-exact 重写为真实 Chromium 150 (2026-07-05)

### ⚠️ 破坏性变更: client + server 必须同步升级

ClientHello 结构大改 (~550B → ~1786B). 无协议帧格式变化 (session_id token 机制
不变), 但强烈建议成对升级以保持行为一致.

### security(crypto): tls_raw.rs 重写 —— 旧三浏览器指纹全是 2019 年老货

**审计发现** (抓真实 Edge 150.0.4078 / Chrome 150.0.7871 字节 + JA4 交叉验证):
旧 build_chrome/firefox/safari 的 JA3/JA4 匹配不上任何真实浏览器 —— Chrome 缺
ChaCha20 (cca9/cca8)、有假 00ff cipher、缺 ML-KEM 后量子 key_share、缺 ECH/ALPS/
cert_compress/SCT, 大小仅 ~550B (真实 Chromium 150 因后量子 key_share 达 1786B).
即旧指纹相当于 Chrome 70, 反而成为**独有可识别特征**, 彻底违背 mimicry 初衷.

**重写为 byte-exact Chromium 150** (Chrome/Edge 同 Chromium, 一份模板通吃):
- 15 cipher (含 cca9/cca8), 删假 00ff
- **X25519MLKEM768 (0x11ec) 后量子 key_share** —— 2024+ Chromium 默认. ML-KEM-768
  ek 按 FIPS 203 生成合法系数 (768 系数取 [0,q=3329), 12-bit Kyber 打包), 通过真实
  服务器模数校验 (随机字节会被 illegal_parameter 拒绝). 每连接新生成避免固定 key
  成指纹.
- ECH GREASE (fe0d 250B) / ALPS (44cd) / cert_compress brotli (001b) / SCT (0012)
- 扩展中段每连接 Fisher-Yates 随机洗牌 (复刻 Chrome 110+), 首尾 GREASE 书挡且
  保证两值不同 (撞值会产生重复扩展 → 服务器拒绝)
- 动态: client_random / session_id (Poly1305 token) / SNI / key_share 公钥 /
  ECH enc / 各 GREASE 每连接随机

**验证**: 生成的 ClientHello JA4 = `t13d1516h2_8daaf6152771_806a8c22fdea`, 与真实
Chromium 150 完全一致; 实测被 cloudflare 等真实 TLS 服务器接受 (回 ServerHello).

### fix(crypto): handshake_cache fetch 校验首记录 0x16, 防 alert 毒化缓存

`fetch_real_server_hello` 之前不校验对端响应类型, 若 camouflage_host 拒绝
ClientHello 回 Alert (0x15), 会把 alert 当 ServerHello 模板缓存 → 所有客户端收到
alert 握手全挂. 现在首记录非 0x16 (Handshake) 即返回 Err → 上层回落
fallback_server_hello. (此 bug 由上面 ClientHello 变大偶发暴露, 属既有隐患根治.)

### test: 新增 tests/test_tls_fingerprint.rs

锁定 Chromium 150 JA4 决定成分: cipher 集合 / 扩展集合 / 无重复扩展 (200 次随机)
/ ML-KEM key_share 系数合法性 / CH 大小 ~1786B. 防未来改动静默破坏 mimicry.

### 后续 (记录)

- TODO(v2): 增加 Android OkHttp profile (稳定指纹 + SNI 灵活) 做客户端多样性.
- 扩展洗牌已做; GREASE 跨槽关联 (Chrome 确定性派生) 未复刻, 但 JA3/JA4 排除
  GREASE, 不影响指纹, 低优先.

## [v0.4.5-alpha.10] - UNAUTH 限流 IPv6 /64 归一 (逃逸修复) (2026-07-05)

### fix(server): UNAUTH 限流 key IPv6 归一到 /64

**背景**: 握手审计 #4. `handshake.rs` 的 auth-fail 每 IP 限流用完整 `peer_addr.ip()`
(IPv6 128 位) 做 key. 攻击者控制一个 /64 段 (家宽/VPS 常见分配) 可造 2^64 个"独立
IP", 每个用满 100 次, **完全逃逸单 IP 限流**, 把 camouflage 路径打到 GLOBAL_UNAUTH
5000 全局上限.

**修法**: 新增 `rate_limit_key(ip)`:
- IPv4 → 原样 (单地址已是最细粒度)
- IPv6 → 清零低 64 位, 归一到 /64 前缀

同一 /64 段的所有地址共享一个限流计数 → 攻击者一个 /64 只能发 100 次 auth-fail.
`IpSlotGuard` 持有归一后的 IP, Drop 时递减同一 key, 计数一致. 日志仍打印完整
`peer_addr` (定位真实来源不受影响).

/64 是 IPv6 最小终端分配单位 (RFC 6177), 按 /64 归一既拦得住段内洪泛, 又不会误伤
不同真实用户 (不同用户在不同 /64).

### 影响面

- 仅服务端 auth-fail 限流路径; 正常认证/客户端不受影响
- 非破坏性, 无协议/配置变化

## [v0.4.5-alpha.9] - 透明代理 fake-IP 本地路由自动管理 (网关拦截修复) (2026-07-04)

### fix(transparent): sk_lookup 网关/客户端拦截静默失效的根因修复

**审计发现**: sk_lookup 只在内核【本地投递路径】的 socket 查找时触发, 而路由
决策发生在它之前 (`ip_route_input` → `ip_local_deliver` vs `ip_forward`).
fake-IP (198.18.0.0/15) 在网关/客户端上默认**不是本机地址**:

- **网关转发场景**: LAN 设备发 fake-IP 包到网关 → 内核判定"转发" → 走 ip_forward
  → 绕过本地投递 → **sk_lookup 从不运行** → 包发往默认路由 → fake-IP 不可路由丢弃
- **客户端本机场景**: app connect(fake-IP) → 输出路由走默认 → 不回本地投递 →
  sk_lookup 同样不触发

即透明拦截**静默失效**. 之前若"能用"大概率是测试环境外部/手动加过 local 路由.

**根因**: 缺一条把 fake-IP 段标记为本机可投递的路由. 全仓库 (install.sh /
Rust / systemd / README) 都没有设置它.

### 修法: 自动管理 (`transparent_net.rs` 新增)

fake-IP 透明代理启用时 (`start_transparent` attach sk_lookup 成功后) 自动装:
```
ip route replace local <fakeip_net>/<prefix> dev lo
```
让内核把 fake-IP 段当本机可投递 → 包进 socket 查找路径 → sk_lookup 触发 →
bpf_sk_assign 到 mirage listener. 进程退出 (SIGTERM/ctrl_c) 时 `ip route del`
清理. **用户无感, 跟随 fake-IP 开关生命周期** (dae/sing-box/clash 同款做法).

- `ip route replace` 幂等 (已存在不报错)
- 装失败仅 warn 不 panic (提示需 CAP_NET_ADMIN)
- 退出清理 best-effort (失败无害: fake-IP 不可路由, mirage 停后 DNS 也不再下发)

### 只装严格必需的一条路由

- **不碰 rp_filter**: 它校验的是【源地址】(LAN 客户端合法可达), fake-IP 是目标
  地址, 不受影响 —— 之前审计报告里担心的 rp_filter/martian 实际不触发
- **不碰 ip_forward / NAT**: 那是直连流量转发的网关级配置, 与 sk_lookup 拦截
  无关, 由用户/install.sh 另行负责 (`sysctl net.ipv4.ip_forward=1` +
  `iptables MASQUERADE`)

### 影响面

- 只在透明代理 + fake-IP 启用时生效; SOCKS5/HTTP/Mixed 入站不受影响
- 需要进程有 CAP_NET_ADMIN (透明模式本来就要 root 跑 eBPF attach, 权限已具备)
- 非破坏性, 无协议变化, 无配置迁移

## [v0.4.5-alpha.8] - 直连 DNS 缓存 + IPv4 优先 (国内延迟修复) (2026-07-04)

### perf(proxy): connect_smart 替代裸 TcpStream::connect(域名)

**现网诊断** (客户端 Alpine musl):
```
getent hosts jra.jd.com   → 0.12s  (DNS 解析 120ms)
curl -4 connect            → 0.065s (拿到 IP 后连接快)
IPv6                       → 受限
```

**根因**: musl libc 无内建 DNS 缓存, Alpine 默认无 nscd/systemd-resolved.
`handler.rs` Direct 分支 `TcpStream::connect(域名)` 每连接走一次完整 getaddrinfo
(~120ms, GSLB/CDN 域名更慢). 一个网页 200 子请求, 未缓存域名各 +120ms → 累积
秒级延迟. 透明代理模式下浏览器自己缓存 DNS 所以感觉快, SOCKS5h 模式把域名甩给
mirage 现场解析, 压力堆在连接热路径.

此外 tokio `TcpStream::connect` 顺序试地址无 Happy-Eyeballs, 域名有 AAAA 记录 +
IPv6 受限时会 hang 在 v6 尝试.

### 实现 (`resolver.rs` 新增)

- **DNS 缓存**: 解析结果按 60s TTL 缓存, 重复访问 0 网络开销. 容量上限 8192,
  超限先清过期项, 仍超则整体清空 (有界)
- **IPv4 优先**: 解析结果 stable sort v4 在前, 受限 IPv6 网络不 hang 在 v6
- **每尝试 3s 超时**: 单个坏地址 (如不通的 v6) 不拖垮整体, 快速 fallback 下一个
- **IP 直连短路**: target 本身是 IP 字面量 (如 180.101.49.44:443) 直接连, 不解析
  不缓存, 保持原 6ms 快路径

只改 Direct 分支 (`handler.rs`), Mirage 隧道出站不受影响 (target 域名由服务端解析).

### 60s TTL 权衡

GSLB/CDN (如 *.gslb.qianxun.com) IP 会轮转, 60s 缓存平衡"重复访问加速"与"IP
新鲜度". 家用/网关域名基数下缓存表内存可忽略.

### 未覆盖 (记录)

- 服务端 `tcp_relay` 也 `TcpStream::connect(域名)`, 但服务端通常在机房 DNS 快,
  暂不加缓存. 若未来服务端也慢再补.
- 未做真 Happy-Eyeballs (v4/v6 并发赛跑). 当前"v4 优先 + 每尝试超时"对受限 IPv6
  场景已足够, 且更简单. 若未来遇到 v4 慢 v6 快的场景再升级.

## [v0.4.5-alpha.7] - Mirage 协议握手三项安全强化 (2026-07-04)

### ⚠️ 破坏性变更: 客户端 + 服务端必须同步升级到 alpha.7+

Fake Client Finished tail 尺寸从 63B → 64B (Body 52 → 53). 旧版客户端连接新版
服务端会被 read_exact 卡 5s 超时后 close, 反之亦然. 必须成对升级.

### fix(server): ClientHello 精确 5B header + body 分段读取

**背景**: 老版 `stream.read(&mut vec![0u8; 1024])` 一次性读最多 1024B, 遇到:
- iOS Safari 完整 ECH + Encrypted SNI 扩展 → ClientHello ~1300B
- Chrome 带 4 个 QUIC ALPN + PSK ticket → ~1200B
- 会被截断 → auth 校验虽然能过 (session_id 在前 76B), 但转发到 camouflage_host
  时是**残缺 ClientHello**, 触发对面回 TLS alert, camouflage 路径失败

**修法** (`handshake.rs`):
```rust
let mut header = [0u8; 5];
stream.read_exact(&mut header).await?;
let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
if record_len > 16384 { return; } // RFC 8446 §5.1 硬 cap 2^14
let mut body = vec![0u8; record_len];
stream.read_exact(&mut body).await?;
```

TLS 记录最大合法长度 16384 (2^14), 超出即恶意报文, 静默丢包不给 camouflage
消耗对面连接. `client_random` / `session_id` offset 全部从 `body` 相对偏移
重新推导, 边界更清晰.

### fix(crypto): Fake Client Finished tail body 52 → 53B

**背景**: `build_fake_client_tail()` 假 Finished 密文体固定 52B, 但真实 TLS 1.3
Client Finished (ChaCha20-Poly1305 + SHA-256 HMAC) 加密后 record body 是:
```
4B handshake header + 32B HMAC digest + 1B content_type + 16B AEAD tag = 53B
```

52 → 53 后跟主流浏览器 Client Finished record body 长度分布完全一致, 消除
DPI histogram 潜在识别特征.

### feat(server): CamouflagePool 预热连接池, 消除 auth-fail 分支时序侧信道

**问题**: auth-fail 分支需要 `TcpStream::connect(camouflage_host:443)` 新建 TCP,
1 个 RTT (5-100ms) vs auth-succ 分支的本地模板拷贝 (~0-1ms). GFW 用大量样本
统计首字节返程时间可分类为 mirage 服务器.

**修法** (`camouflage_pool.rs`):
- 后台 task 维护 8 条 pre-warmed TCP 连接到 camouflage_host:443
- 500ms 补给间隔, 10s max_age 淘汰 (camouflage_host 通常 30s idle timeout, 留余量)
- 3s connect 超时, 对面抖动时不 hammer
- auth-fail 时 `pool.acquire()` 抢一条已建 TCP → 无 3-way RTT
- 池空 fallback 到即时 connect (跟老版行为一致)

**残余时序差**: 仍有 1 个 RTT (camouflage_host 回 ServerHello) 无法消除. 完全对齐
需要 auth-succ 分支延迟注入, 权衡后**暂不做** — 会增加合法用户 WarmPool 补给
延迟, 且残余 RTT 差异对 GFW 需要成千上万样本才能识别, 单个用户不足以触发.

### fix(crypto): ReplayCache 满桶 fail-closed (拒绝) 而非 bypass (放行)

**攻击场景**: 老版满桶 (>100k) 时直接 `return true` 放行, 攻击者 DDoS 拉高
认证请求量填桶后, 就能**无限重放**截获的合法 token 直到桶回落到阈值以下.

**修法** (`hello_auth.rs`): 满桶 → `return false` (拒绝). 满桶期间合法 token 也会
被误判重放, 但同时攻击者的 replay 也被拦, 保守安全 > 可用性.

100k 桶 = 60s 内 10 万个不同 token, 正常业务不可能触发, 只有 DDoS 才可能碰到,
拒绝是对的.

### 未修的 (残余风险, 记录):

- **UNAUTH 限流对 IPv6 无效**: `map.entry(peer_addr.ip())` 用完整 IPv6 (128 位) 做
  key, 攻击者控制 /64 段可造 2^64 独立 IP 逃逸. IPv6 应按 /64 或 /48 归一.
  留 alpha.8+ 修.
- **auth-succ 路径残余 1 RTT 时序差**: 见上面 CamouflagePool 段末. 需要 config
  开关 + startup 测 camouflage RTT + auth-succ delay_injection. alpha.8+.
- **客户端 `read_server_handshake` 12s / 1.5s 固定超时**: 客户端行为指纹, GFW
  观察客户端断连时间可识别. 优先级低, 客户端行为不是主要防御面.

## [v0.4.5-alpha.6] - splice idle watchdog 时钟单调化 (NTP 前跳防御) (2026-07-04)

### fix(proxy): ActivityTracker 从 SystemTime 换成 Instant 单调时钟

**背景**: alpha.4 引入 `ActivityTracker` 时用 `SystemTime::now().duration_since(UNIX_EPOCH)`
拿墙钟秒数. `saturating_sub` 已经防了倒流下溢, 但**前跳**没防:

- **VM 启动 RTC 不准 → NTP 突然 +30 分钟同步**: watchdog 计算 `idle_secs =
  now(墙钟) - last_touch(旧墙钟) > 900s`, **所有活跃连接被瞬间误杀**
- **VM 从 suspend 恢复**: 墙钟跳过 suspend 时长, 同样触发误杀 (虽然此场景
  连接可能确实死了, 但决策不该建立在墙钟上)

### 实现

```rust
fn monotonic_secs() -> u64 {
    static ORIGIN: OnceLock<Instant> = OnceLock::new();
    ORIGIN.get_or_init(Instant::now).elapsed().as_secs()
}
```

- 首次调用初始化 `ORIGIN = Instant::now()` (进程启动基准)
- 之后所有 `touch()` / `idle_secs()` 都读相对秒数
- Linux 底层 `CLOCK_MONOTONIC` — 免疫 NTP 前后跳

### 副作用 (合理不改)

Linux `CLOCK_MONOTONIC` **不计 suspend 时长** (kernel 4.17+ 明确). VM 从
suspend 恢复后:
- SystemTime 视角: 已过了 20 小时, 连接被认为 idle 20h → 误杀
- Instant 视角: elapsed() 只涨了 suspend 前的相对时间 → 连接被视为"刚活跃过"

后者更合理 — 恢复后用户的第一个请求正常, 之后 15 分钟无活动才被淘汰。若真
需要计入 suspend 时长, kernel 有 `CLOCK_BOOTTIME` 可用, 但 Rust std::Instant
用的是 `CLOCK_MONOTONIC`, 目前 stable API 无法切换, 也无必要。

### 影响面

- 只有 splice_relay 里的 idle watchdog 用 tracker, 无外部 API
- 无配置迁移, 无行为破坏 (只修 NTP 边界)
- 对于 RTC 稳定的机器 (物理服务器 / 校时准确的容器), 表现跟 alpha.4 完全一致

## [v0.4.5-alpha.5] - splice pipe pool + 详细 debug 日志 (2026-07-03)

### perf(proxy): 加 pipe pool 复用, 消除每连接 pipe2()+F_SETPIPE_SZ() syscall

学 dae `control/tcp_copy_linux.go::relaySplicePipePool`:

- `OnceLock<Mutex<VecDeque<Pipe>>>` 静态 pool, 容量 64
- `acquire_pipe()` 先 pop_front, 无则 fallback 到 `Pipe::new()` (含 pipe2 +
  F_SETPIPE_SZ 两次 syscall)
- `release_pipe()` 归池, 池满则 Drop 关 fd, 无上限阻塞
- `PipeGuard` RAII: 出错走 Drop 关 fd; 成功走 `finish()` 归池 (成功路径
  in_pipe 保证为 0, 无残留数据)
- POOL_HITS / POOL_MISSES 全局 atomic, 供 debug 日志读

**收益**: 高频短连接场景 (每连接 2 个 pipe) 从 4 次 pipe 相关 syscall 降到 0.
低频场景无变化 (fallback 到 new 路径). dae 用同样机制, 生产验证过。

### fix(proxy): byte accounting 从函数末尾移到 splice 内部

alpha.4 的 `crate::monitor::add_up(n)` 在 `splice_one_way` 返回 Ok 后统一
调用 — 出错时 partial 字节数丢失。改为每次 `pipe→dst` 成功后立即 `counter(m)`,
出错也保留已传输的 partial:

```rust
async fn splice_one_way(..., counter: fn(u64)) -> io::Result<u64> {
    ...
    counter(m as u64); // 每 chunk 立即上报, 无 buffered 丢失
    ...
}
```

`splice_relay` 传 `crate::monitor::add_up` / `add_down` 函数指针, 类型安全,
无 closure lifetime 复杂度。

### feat(proxy): Direct 分支 debug 日志加详细字段

从

```
Direct splice relay to <target> closed: up=<N>B down=<N>B
```

改成

```
splice open: peer=<addr> target=<host> initial=<N>B connect=<M>ms
             pool_hits=<H> pool_misses=<M>
splice close: peer=<addr> target=<host> up=<N>B down=<N>B relay=<M>ms
              total=<M>ms pool_hits=<H> pool_misses=<M> pool_idle=<L>
splice err: peer=<addr> target=<host> reason=<class> err='<msg>'
            relay=<M>ms total=<M>ms
```

`reason` 分类: `idle_timeout` | `timeout` | `conn_reset` | `conn_aborted` |
`unexpected_eof` | `broken_pipe` | `write_zero` | `other`。

网关运维观察点: peer_addr 定位客户端, pool_hits/misses 看池命中率是否合理,
duration 分布定位慢查询, reason 分布定位问题类型。

### 无 API/config 变化, 向前兼容

pipe pool 完全内部实现, splice_relay 签名不变。debug 日志格式改变但只有
运维人肉观察, 无自动化 parser 依赖。

## [v0.4.5-alpha.4] - splice_relay idle timeout (透明网关场景准备) (2026-07-03)

### feat(proxy): splice_relay 加双向共享 idle timeout

**背景**: alpha.3 上线后 splice_relay 无任何 idle timeout — SOCKS5 客户端本地
场景下 keepalive + 短会话足够, 但**下一阶段计划让 Mirage 承担透明代理网关**
角色, 网关场景下僵尸连接会啃 fd + 内核内存, 需要主动止损. 参考 dae 也有
`relayCore.forceClose()` 靠外层 SetReadDeadline(past) 主动打断.

### 设计

- `ActivityTracker` 一个 `AtomicU64` (epoch 秒), 双向共享
- 每次 `splice()` 成功 (n > 0) 后 `tracker.touch()` — 热路径无锁, 性能可忽略
- `idle_watchdog` 每 30s 检查一次, 双向都静默 > 15 分钟 → 返回 TimedOut
- `splice_relay` 用 `tokio::select!` 包 `try_join!(up, down)` + `watchdog`,
  watchdog 触发时立刻取消双向 futures, sockets 走 Drop, kernel fd 自动释放

### 为什么是"双向共享"而非"每向独立"

若每向独立, HTTP 大文件上传场景 (up 忙, down 静默 20 分钟) 会误杀 down 方向.
双向共享确保**任一方向活跃就整条连接不 idle**, 只有真正双向都死才回收.

### 权衡: 15 分钟阈值

- 传统 SSE 心跳: 30s-5 分钟 → 安全
- WebSocket ping frame: 一般 30s-60s → 安全
- HTTP long-poll: 通常 25-30s → 安全
- 严重卡的 API (罕见 batch 处理 > 15 分钟) → 会被误杀, 但这类 API 本就该
  改设计, 不算合理场景

超时阈值可以未来提到 config, 目前硬编码常量即可.

### 影响面

- Direct 分支的 SOCKS5 客户端场景: 短连接不受影响, 长连接会在 15 分钟静默
  后被强关 (以前会挂到内核 keepalive 2 小时超时)
- 未来透明网关: 直接受益, 网关连接密度高时特别重要
- 无 API 变化, 无配置迁移

### 未做的

- 硬 max_lifetime cap (例如 24h 强制关) — 目前不需要, idle 足够兜底
- 配置化超时阈值 — 硬编码常量, 上生产观察后再决定要不要暴露
- 分方向独立超时 — 前述反例排除

## [v0.4.5-alpha.3] - 直连零拷贝换用 splice(2)+pipe (参考 dae) (2026-07-03)

### fix(proxy): sockmap sk_skb 数据面全部删除, 改 splice(2)+pipe

**背景**: alpha.1 顺序修 + alpha.2 bpf_printk 诊断跑完后, 现网仍然复现 "verdict SK_PASS
4 次但 curl 0 字节". 参考 dae 源码 `control/kern/tproxy.c:178` 官方注释:

> "BPF_PROG_TYPE_SOCK_OPS + BPF_PROG_TYPE_SK_MSG (bpf_msg_redirect_hash) combination
>  has been proven to cause Kernel Panic. We use TC-based redirect instead."

dae 团队在 sk_msg 侧遇到 kernel panic, 明确放弃整套 sockmap redirect 家族; 我们的
sk_skb + `bpf_sk_redirect_hash` 共享同一 sk_psock 底层, 表现是"静默丢包"而不是 panic,
但本质是同类问题, kernel 6.x 上不可靠。

### 换掉的技术方案

dae 数据面真身 = `control/tcp_copy_linux.go::relaySpliceCopyExact`:
- `pipe2(O_CLOEXEC | O_NONBLOCK)` 建 pipe
- `fcntl(F_SETPIPE_SZ, 256KB)` 设 pipe 缓冲
- `splice(src_sock, pipe_w, SPLICE_F_MOVE | MORE | NONBLOCK)` — 从 src socket 搬 page 到 pipe
- `splice(pipe_r, dst_sock, ...)` — 从 pipe 搬 page 到 dst socket
- 无 userspace 中转, kernel 只搬 page 引用, **真正零拷贝**

Mirage 客户端 SOCKS5 场景不需要 dae 的 tc-bpf 路由 (客户端主动 opt-in), 只搬数据面
到 splice 就够了。

### 具体改动

- **删** `src/ebpf/mod.rs::register_splice()` (aya SockHash 一整套)
- **删** `src/ebpf/mod.rs::init()` 里 SkSkb attach + sockmap fd
- **删** `ebpf-src/sockmap.c::mirage_stream_verdict` (SEC sk_skb) + `mirage_sockmap` (SOCKHASH)
  + `mirage_bpf_stats` (PERCPU_ARRAY) + alpha.2 bpf_printk
- **删** `src/proxy/handler.rs::proxy_tcp_target` Direct 分支 alpha.1 的 register_splice
  顺序修 + epoll RDHUP 等待循环 (共 ~90 行)
- **新增** `src/proxy/splice.rs`: `splice_relay(local, target)` 双向 tokio::try_join,
  每方向独立 256KB pipe, `TcpStream::async_io` 处理 EAGAIN 重试
- `EbpfEngine::get_stats()` 保留签名返回 `Ok((0, 0))`, sampler.rs/GUI 图不用改, 显示
  稳定 0 (新架构下 BPF fast-path counter 无语义)

### 保留的 eBPF 功能 (未受影响)

- ✅ `mirage_sockops` + `mirage_rtt_map` + `mirage_target_ips` — Brutal CC 动态速率反馈
- ✅ XDP DNS 加速 (`dns_xdp.c`, `mirage_dns_cache`)
- ✅ 服务端 `sk_lookup` 透明代理 (跟 sockmap redirect 是完全不同的 API)

### 客户端配置

`install.sh` `ebpf_mode: "off"` (alpha.7 起的临时 workaround) 可以在 alpha.3 上手工
测试 OK 后恢复 `"auto"`, 因为 alpha.3 不再依赖 sockmap 数据面, sockops+RTT 是纯反馈,
安全。

### 测试计划

1. cachefly 100MB 下载 (alpha.25 基线 25.8Mbps) — 期望 splice(2) 至少等同
2. `curl -x socks5://127.0.0.1:3180 https://www.baidu.com -o /dev/null -m 30` — 期望
   200 状态码, 非 0 字节, 无 timeout
3. `curl ... https://api.m.jd.com/...` — .cn 直连域名, 期望正常
4. YouTube 4K 播放 — 期望缓冲流畅 (走 Mirage 隧道, 直连路径不影响它)

## [v0.4.5-alpha.2] - eBPF verdict trace_pipe 诊断 (临时调试, 非生产) (2026-07-03)

### debug(ebpf): sockmap.c verdict 加 bpf_printk

alpha.1 顺序修复上线后现网仍复现: `curl -x socks5://... https://baidu.com -m 5`
超时 0 字节. bpftool 读 mirage_bpf_stats 显示 key=0 (SK_PASS) = 4, key=2 (SK_DROP) = 0.
矛盾: verdict fire 且 redirect_hash 声明成功, 但数据一字节都不到 curl.

**加 bpf_printk 定位 cookie/len/ret 真实值**:
```c
bpf_printk("verdict: cookie=%llu len=%u ret=%d", cookie, len, ret);
```

诊断步骤:
1. 客户端 `sudo cat /sys/kernel/debug/tracing/trace_pipe`
2. 另开 shell `curl -x socks5://127.0.0.1:3180 https://www.baidu.com -o /dev/null -m 5`
3. trace_pipe 输出的 cookie 值对比 `eBPF SockMap: spliced local_cookie=X <-> remote_cookie=Y`
   - 如 verdict 里 cookie 完全不匹配 Rust 日志 → cookie 语义错
   - 如匹配但 ret=SK_PASS 但数据不通 → EGRESS 方向反了 (需切 BPF_F_INGRESS)
   - 如 len 为 0 → skb 是空包 (只 TCP 控制帧, ACK 之类)

**警告**: bpf_printk 有 buffer 抢锁 + string table 开销, 每次生产化前 remove.

## [v0.4.5-alpha.1] - eBPF SockMap 零拷贝直连修复 (P0 长期未解 bug 根治) (2026-07-02)

### fix(ebpf): register_splice 顺序竞态修复

**背景**: alpha.7 (2026-06-24) 起 install.sh 客户端默认 `"ebpf_mode":
"off"` 因为发现 SockMap 直连零拷贝转发不工作: `register_splice()` 声
明"activated"但数据永远不流动, 浏览器超时。alpha.7 只是临时禁用整
个 BPF 客户端功能作为 workaround, 真正 root cause 未修. 影响:
- 直连 (.cn 域名) 走用户态 Tokio, 失去零拷贝加速
- 客户端 sockops RTT 反馈不可用, 动态 brutal CC 无法启用
- XDP DNS + sk_lookup 透明代理全部功能被停用

### 根因诊断

`src/proxy/handler.rs::proxy_tcp_target` 的 Direct 分支老顺序:
```
1. target_stream.write_all(&initial_payload)  ← 发到 target
2. (0-N ms 时间窗)                             ← 竞态窗口
3. register_splice(local, target_stream)      ← sk_psock 才安装到 target RX
4. epoll wait EPOLLRDHUP                      ← 只等 close
```

target (小 HTTP 请求场景, 如 .cn 门户站) 通常在 < 1ms 回响应, 响应
到达 target socket RX 队列时 sk_psock 还没安装, 数据被跳过 verdict
拦截. 然后 sk_psock 装好后已经在队列里的这段数据无人读 (handler
仅 epoll wait 不做 recv), 就永久卡在 kernel RX buffer 里. 客户端超
时后连接断开.

### 修复

`src/proxy/handler.rs:270-306` 交换 register_splice 和 write_all 顺序:
```
1. register_splice(local, target_stream)  ← 先装 sk_psock
2. target_stream.write_all(&initial_payload)  ← 用 target TX 路径, sk_psock 不拦
3. epoll wait                              ← target 响应到 RX 时 sk_psock 就位, verdict 立即 redirect
```

**为什么 write_all 在 register_splice 后仍能工作**: sk_skb/stream_verdict
BPF 程序只拦截 RX (received data) 路径, TX (send/write) 完全不受影响.
Tokio 的 `write_all` 走 tcp_sendmsg 直接送 kernel TX buffer, 与
sk_psock 的 RX 拦截正交.

### install.sh: 客户端 config 默认 ebpf_mode 改回 auto

`install.sh:754` 从 `"off"` 改回 `"auto"` (alpha.7 之前的原值). server
仍自动 skip BPF, 只有 client 启用. 新装用户直接享受零拷贝直连.

老用户 (config 里手动 `"ebpf_mode": "off"`) 升级后需要手动改成
`"auto"` 才生效:
```bash
sed -i 's/"ebpf_mode": "off"/"ebpf_mode": "auto"/' /etc/mirage-rs/config_client.json
sudo systemctl restart mirage-rs-client
```

或重跑 `install.sh` 让脚本重新生成 config.

### 影响 (再启用后恢复的功能)

- ★ 直连零拷贝 (Router 命中 direct outbound 时 kernel-side splice)
- sockops RTT_CB 收集 → 动态 brutal CC 速率调节 (客户端出站)
- XDP DNS 高速解析
- sk_lookup 透明代理 (kernel ≥ 5.9)

### 版本序列变化

v0.4.4-alpha (25 个 alpha 版本, 修了海量 bug + IO 性能) → **v0.4.5-alpha.1**
新序列开始, 主题是"eBPF 全栈重启用". 后续 alpha 若稳可能直接发 v0.4.5
stable.

## [v0.4.4-alpha.25] - 撤回 alpha.21 的显式 SO_SNDBUF/SO_RCVBUF (7× 回归元凶) (2026-07-01)

用户实测 alpha.21+ 相比 alpha.20 出现 **7× 吞吐回归** (Cloudflare 15
Mbps → 2 Mbps). 二分定位: alpha.22 已慢, 罪魁在 alpha.21 加的显式
`setsockopt(SO_SNDBUF/SO_RCVBUF = 8MB)`.

### 根因

Linux 上手动 `setsockopt(SO_SNDBUF/SO_RCVBUF)` 会**disable TCP window
auto-tuning**. auto-tune 会根据实际 BDP + 观测丢包动态调节窗口, 是
现代 Linux 的默认 (通常表现最优). 手动固定 8MB 反而在**高丢包链路**
(用户 iperf3 测出 7% 丢包) 造成 bufferbloat:

- 8MB 窗口 → TCP 允许 8MB in-flight
- 高丢包 → 大量重传排队在 8MB buffer 里
- BBR/brutal 都被拖垮, 有效吞吐掉 7×

alpha.20 没有这段代码, kernel auto-tune 智能调节, 因此稳定 15 Mbps.

### 修改

三处 socket 全撤回:
- `src/proxy/mirage_server/mod.rs`: server accept socket (server→client 方向)
- `src/proxy/mirage_server/tcp_relay.rs`: server upstream socket (server←YouTube)
- `src/proxy/pool.rs`: client outbound socket (client←server)

保留 alpha.21-24 的其他改动:
- server 读缓冲 16→64 KB (无副作用)
- alpha.22 header+body 合并 write_all (纯优化)
- alpha.23 CryptoWriter BufWriter + greedy try_read + 撤 mpsc
- alpha.24 BufWriter 容量 68KB 修算

### 教训

"手动置大值 disable auto-tune" 这种"性能优化"在**理论上正确, 实际上
灾难**. Linux TCP auto-tuning 是几十年优化沉淀的成果, 手动覆盖需要
非常精确的针对场景分析, 通用场景一律不动最好.

## [v0.4.4-alpha.24] - BufWriter 容量算错 22B×N 加密开销 (外部审计) (2026-07-01)

### fix(crypto): WRITER_BUF_CAPACITY 65536 → 68 * 1024 (69632)

外部审计精确定位: alpha.23 `WRITER_BUF_CAPACITY = 65536` **漏算了每
帧的 22 字节 AEAD/TLS 封装 overhead**, 满载时 syscall 不聚合.

### 数理推演 (逐位复核 aead.rs 源码)

单帧密文封装:
- 5 字节 TLS Header `[0x17, 0x03, 0x03, len_hi, len_lo]`
- chunk_len 字节明文
- 1 字节 inner content type `0x17` (encrypted with tag)
- 16 字节 Poly1305 tag (append after encrypt)

每帧 overhead: **22 字节**.

### Worst case 演练

上游 `tcp_relay::buf = vec![0u8; 65536]`, greedy 填满 65536 明文
后送 `send_data(65536)`. send_data 内部 chunk size 是 rng 三分桶
(50%=16384, 35%=8192, 15%=4096):

- 4 帧 16KB: 4 × 16406 = 65624 bytes (外部审计的例子)
- 16 帧 4KB (worst): 16 × 4118 = **65888 bytes** (更极端)

老 65536 容量:
- 前 3 帧 16KB 后 buffer 49218 已用
- 第 4 帧 16406 加入: 65624 > 65536 → BufWriter **flush 前 49218 一次
  syscall**, 剩 16406 buffer
- 末尾 `flush()`: 剩 16406 syscall 二次

**满载退化为 2 次 syscall**, 原本设计目标 1 次 syscall 打空.

### 修改

`const WRITER_BUF_CAPACITY: usize = 68 * 1024` (69632 bytes).

覆盖 65888 worst case + 3744 bytes headroom (未来提高 tcp_relay buf
到 65KB+ 也不必再改).

### 自审: 是否其他 send_data 调用点会超 65536

全项目 grep 确认:
- `src/proxy/mirage_server/tcp_relay.rs`: buf 65536 ✓ (主要用例)
- `src/proxy/handler.rs` upload: buf 16384 ✓ 远小
- `src/proxy/udp_relay.rs` (client): 小 UDP 帧 ✓
- `src/proxy/mirage_server/udp_relay.rs`: 小 UDP 包 ✓
- healthcheck / dns / control: 小控制帧 ✓

无其他大 send_data 输入, 68KB BufWriter 全覆盖.

## [v0.4.4-alpha.23] - BufWriter 内嵌 + server 贪婪 try_read + 客户端撤 mpsc (2026-07-01)

外部审计三方向剩余两项落地, 加上 alpha.21 客户端 mpsc 方案的撤回.

### feat(crypto): CryptoWriter 内嵌 tokio::io::BufWriter(64KB)

`src/crypto/aead.rs::CryptoWriter` 内部 `writer: W` 改为
`writer: BufWriter<W>`, 容量 64KB = 4× MAX_RECORD_SIZE.

send_data 处理一次 64KB plaintext 会内部拆 4 帧, 4× `write_all(framed)`
之前直接 4 次 syscall, 现在攒到 BufWriter 里, 末尾 flush() 一次
syscall 送出 64KB.

**关键: caller 契约完全不变**. send_data 尾部保留 flush() 主动 drain
BufWriter, healthcheck / dns / control / handler 所有 caller 全部无
需修改. BufWriter 的收益仅在 send_data 内部多帧写入时体现 (一次
send_data 处理大 plaintext), send_data 一次少 plaintext 时 flush 立即
drain 也不留任何数据.

### feat(server): tcp_relay download 用 try_read 贪婪收割 upstream

alpha.21 加大 read buf 到 64KB 只解决"能装多少", 没解决"每次装到多少":
tokio `read()` 只返回 kernel recv buffer 当前现成的数据, 剩下的等下
一轮 poll. 长 BDP 链路 kernel 里可能连续来了 64KB 但一次读只拿 8KB.

改法: blocking `read` 拿第一片后, 立刻 `try_read` 非阻塞收割 kernel
里剩余数据, 填满 64KB 或 WouldBlock 为止. 一次 `send_data(64KB)` 大
批送出 → CryptoWriter BufWriter 里 4 帧合成 1 syscall.

打破"读一片写一片"串行的碎片化.

### fix(handler): 撤回 alpha.21 的 mpsc channel 批量方案

外部审计明确指出: alpha.21 的 `mpsc::channel(32)` + producer/consumer
+ `try_recv` 攒 batch, 实际上被 tokio 抢占调度 立刻唤醒 consumer,
`try_recv` 大多找不到后续帧, 批量失效, 往往还是一帧一写.

alpha.23 撤回改回直连 `recv_data → write_all` 一对一 pattern. 简洁
+ 分析师验证无副作用. 真正的批量优化在服务端 CryptoWriter BufWriter
和 tcp_relay try_read 两处. 客户端接收侧因 CryptoReader 的 read_exact
语义无法安全加 try_recv (中途取消会丢帧半读), 保持一对一最稳.

### 综合预期

alpha.21 三方向 + alpha.22 concat + alpha.23 三处 联合起来:
- 服务端 syscall 数量: 每 64KB 从 9 次 (2 write + 1 flush × 3 帧) →
  1 次 (BufWriter 攒 3 帧 + flush drain)
- 服务端 read syscall 数量: 每 burst 从 4 次 (4 个 read) → 1 次
  (1 read + 3 try_read 非阻塞)
- 客户端复杂度: 撤 mpsc 后代码更简洁, 少 1 个 tokio task 少 1 个
  channel, 少内存占用

期望 rwnd_limited 从 alpha.22 的中间值 → 接近 POC 的 <5%.

## [v0.4.4-alpha.22] - CryptoWriter 单次 write_all 消除 3× syscall 碎片化 (2026-07-01)

外部审计指出核心 IO 瓶颈: `CryptoWriter::send_data` **每帧两次
`write_all` + `flush`**, 在 `TCP_NODELAY=on` 下 kernel 每次 `write_all`
都触发独立 segment 发送, 网络流量严重碎片化 (5B header + N KB body
分成两个 packet 各带 40B TCP header + IP header, per-byte 开销爆炸).

### 修改

- `CryptoWriter` 加 `framed: Vec<u8>` (预分配) 作出线组帧临时区
- `send_data` 每帧构造 `framed = [5B header, encrypted_body]`, 一次
  `write_all` 送出. Header 不再单独 `write_all`
- `send_close_notify` 同样合并 (但保留 flush, 因为终态需要立即刷网络层)

### 效果

单帧 syscall 数: `2× write_all + flush` → `1× write_all + flush`.
combined with TCP_NODELAY: kernel 每帧发一个 segment (16 KB), 而不是
两个 (5 B + 16 KB), 减少 TCP/IP header 开销, 提高 payload 占比.

### 未完成的分析师建议 (留 alpha.23)

分析师还提出:
- **方向一 Part 2**: 用 `tokio::io::BufWriter(64KB)` 内嵌 CryptoWriter,
  多帧写入自动聚合为一次 syscall (需重构 send_data flush 策略)
- **方向二**: 服务端 tcp_relay + 客户端 handler 用 `try_read` 贪婪收割
  kernel recv buffer 数据攒到 64KB 再一次 send. 打破"读一帧就等一帧"
  串行 (alpha.21 的 mpsc channel 方案分析师指出被 Tokio 调度器立即
  唤醒 consumer 导致批量失效)

先测本版单点改动效果, 再决定 alpha.23 深度重构范围.

## [v0.4.4-alpha.21] - IO 大缓冲 + producer/consumer 批量 (rwnd_limited 67% → 期望 <10%) (2026-07-01)

用户实测发现: 客户端 tcp 长连接 `rwnd_limited 67%` 卡住, brutal 有力
使不出. POC 版本同链路只有 2-5% rwnd_limited. 三方向系统性改造:

### 方向 1: server upstream 读缓冲 16KB → 64KB

`src/proxy/mirage_server/tcp_relay.rs:98`:
- 老 `let mut buf = [0u8; 16384];` — 单次 syscall 只搬 16KB
- 新 `let mut buf = vec![0u8; 65536];` — 一次搬 4× 数据, 减少 poll cycle 开销

用 vec! 而非 [_;N] 数组: tokio task 栈不大, 64KB 大对象放堆上更稳.

### 方向 3: 显式设 SO_SNDBUF / SO_RCVBUF = 8MB (三处 socket)

老代码只在 client outbound 设了 SO_SNDBUF=4MB, 其他 socket 完全靠
kernel auto-tune. Auto-tune 有慢启动, 长 BDP (200ms × 40Mbps ≈ 1MB)
链路起手 buffer 太小 → advertised window 撑不开 → rwnd_limited.

三处补 setsockopt (全 8MB):
1. **`src/proxy/mirage_server/mod.rs`** accept socket: SO_SNDBUF +
   SO_RCVBUF — server→client 视频下载主方向
2. **`src/proxy/mirage_server/tcp_relay.rs`** upstream socket:
   SO_SNDBUF + SO_RCVBUF — server 从 YouTube 等上游拉数据方向
3. **`src/proxy/pool.rs`** client outbound socket: SO_SNDBUF 从 4MB 抬到
   8MB, 新增 SO_RCVBUF = 8MB — server → client 视频下载客户端接收方向

8MB 匹配 install.sh `optimize_sysctl` 已经设的 `net.core.{rmem,wmem}_max
= 8388608`. kernel 内部会 clamp 到 cap, 代码有 getsockopt 校验实际值,
拿不到时 warn 一次提示用户重跑 install.sh 或手动 sysctl.

### 方向 2: client download 循环 producer/consumer + 64KB batching

`src/proxy/handler.rs` proxy_tcp_target 里 mirage outbound 的 download
分支:

- 老 `loop { recv_data().await → write_all().await }` 串行, 读到 1
  帧就得等 write 完再读下一帧, kernel recv buffer 排空慢
- 新: 单 task 读进 `mpsc::channel(capacity=32)`, consumer 从 channel
  拉多帧攒到 64KB 再一次 write_all

效果: TCP 层面读者持续排空 kernel recv buffer, advertised window 稳定
大. 应用层单次 write 搬 4 倍 payload, per-byte 开销 4× 降。

### 综合效果预期

服务端 ss -tipn 上 `rwnd_limited` 应从 67% → <10%. brutal pacing_rate
真正生效. 追平 Python POC 的应用层吞吐效率. `delivery_rate` 与
`pacing_rate` 比值从 30-40% 升到 90%+.

### 边缘 case + 兜底

- kernel clamp: 检查 getsockopt 返回值, capped 时 warn 一次
- producer panic: `unwrap_or_else(|_| panic!(...))` 静态防御, 实际
  recv_data 只返 Ok/Err 不 panic
- consumer timeout / 客户端断开: drop rx → producer tx.send Err → 循环
  正常退出, tunnel_reader 正确回收

## [v0.4.4-alpha.20] - WarmPool DEBUG 日志加当前状态快照 (2026-07-01)

### feat(pool): DEBUG 日志显示 idle / inflight / 即将过期 tunnel 数

之前的 Manager DEBUG 日志:
```
WarmPool Manager: target 2 → 3 (gets=6, wait=4 [66.7%], expired=0)
```
只在 target 变化时打, 缺当下时刻的池快照. 用户看到 wait_ratio 高时只
能猜: "是 pool 空? 是全在用? 还是全在过期挤波谷?"

改成每周期 (5s) 都打一行:
```
WarmPool: target=10 [idle=8 inflight=2 exp<10s=1] gets=15 wait=0(0.0%) expired=3
WarmPool: target=10→12 [idle=5 inflight=5 exp<10s=1] gets=30 wait=10(33.3%) expired=1
```

新字段:
- `idle`: 队列里现存可用 tunnel 数
- `inflight`: 已被 handler 借走的 tunnel 数 (in_flight AtomicUsize)
- `exp<10s`: 剩余寿命 < 10 秒的 tunnel 数 (即将波谷指示器)

诊断价值:
- wait_ratio 高 + inflight >> pool_size 想扩 pool_size
- wait_ratio 高 + idle 已经满 想查 handler 泄漏 (借走没还)
- wait_ratio 高 + exp<10s 很多 = 波谷, 想加 max_age_sec 减 refresh 频率
- wait_ratio 0 + idle 满 + expired 高 = 过供给, 可以缩 pool_size

只 DEBUG 级别, INFO 用户不受影响. 每 5s 一行, DEBUG 用户 12 行/分.
每周期 queue 遍历 O(pool_size) 微秒级. `saturating_sub` 防 elapsed
> max_age_sec 边界下溢.

## [v0.4.4-alpha.19] - 清理死字段 + README 大更新 (2026-07-01)

### chore(config): 清理 TuningConfig 里两个 dead field

- `decision_cache_max_entries: Option<usize>` — 定义了但**从没被任何代码路径引用**
- `tcp_keepalive: Option<u64>` — 同上, dead field

老用户 config 里如果写了这两个字段, serde 默认忽略未知字段, 不会
break 现有部署. 删掉是为了避免用户以为配了这两个就有效果, 属于 schema
诚实性修正.

### docs(README): 全面更新到 v0.4.4-alpha.18 现状

原 README 大量过时:
- 版本 badge 还是 v0.2.3
- 配置示例用老的 `listen_host` / `gui_listen` 单字段
- brutal 推荐值 "8-10 Mbps 上限 10" 是 alpha.4 时代的错误理解, alpha.10+
  实测正确值应该是"链路带宽 30-50%"
- 缺 install.sh / log_file / 节点 URI 导出 / 卸载 章节
- 缺"版本演进"章节让用户快速把握 alpha 系列变化

改动:
- 版本 badge 改 v0.4.4-alpha
- 装机流程首推 install.sh, 手动部署放次位
- 配置示例改成 install.sh 实际输出的结构 (schema_version + inbounds[]
  + gui 结构化 + tuning.ebpf_mode = "off" + via=proxy 等)
- brutal 章节按 alpha.5-11 苦学出的新哲学重写 (30-50% 链路带宽 /
  跨洲专线可到 150-200%, `ss -tipn` 观察 retrans 决策 rate)
- 加节点 URI 导出/导入 + 卸载章节
- 结尾加 alpha 版本演进表

保持原 README 结构 + Neon Dashboard / eBPF / Alpine 兼容性等章节不动.

## [v0.4.4-alpha.18] - alpha.17 遗留边界修复 (tuning 删除 + update_days=0) (2026-07-01)

外部审计 + 自查发现 alpha.17 方案 C 的两个边界:

### fix(config_watcher): 用户删除整个 tuning 块 (外部审计发现)

`extract_updater_state` 老实现:
```rust
let tuning = config.tuning?;   // ⚠️ 早退 None
```
用户运行中删除整个 `"tuning"` 块 (想放弃 geo) → `config.tuning` 为 None
→ 函数返 None → ConfigWatcher `if let Some(new_updater)` 跳过 update()
→ **updater 继续持有旧快照**, 每 7 天照样悄悄拉 GitHub, 违反用户意图.

修: `match config.tuning` 显式处理 None 分支, 视为空 sources, 返
`Some(UpdaterState{sources: vec![]})`. updater 收到后进入 idle 阻塞
在 `wake.notified()` 上, 不再周期性访问 GitHub.

### fix(pool ecosystem): geo_update_days = 0 tight-loop 防御 (自查发现)

顺着上面思路自查, `Duration::from_secs(update_days as u64 * 86_400)`
在 `update_days = 0` 时变成 `Duration::from_secs(0)`. tokio select! 里
`sleep(Duration::from_secs(0))` 立刻 ready → 循环无 sleep → tight loop
把 CPU 打满 + **每秒往 GitHub 猛拉直接被 IP-ban**.

老代码 (alpha.17 之前) 也有这个隐雷但没触发过, 因为默认值 7 且用户很少
误输 0. alpha.17 加了 wake 之后, sleep(0) 会立刻被 wake 覆盖后立刻醒
的组合 → tight loop 触发概率反而更高.

3 层防御 (belt+suspenders):
- L1 `src/lib.rs` 冷启动: `if d == 0 { warn + clamp 1 }`
- L2 `src/config_watcher.rs::extract_updater_state`: `MIN_UPDATE_DAYS = 1`
- L3 `src/router/geo_updater.rs` 循环: `snap.update_days.max(1)` 防守

3 层里任何一层都足够消除风险, 但也不冗余到伤脑. 未来新增其他 UpdaterState
构造路径不必额外记忆 clamp.

### 自查结论 — TuningConfig 剩下的字段都不构成类似陷阱
- `decision_cache_max_entries` / `tcp_keepalive`: 定义了但从没被用 (dead
  field, 不影响)
- `geodata_dir` / `ebpf_mode`: 非数值, 无 clamp 需求
- `geo_sources`: 空是合法状态 (updater 进 idle wait)

## [v0.4.4-alpha.17] - 外部审计 4 处纰漏修复 (2026-07-01)

外部代码审计发现 4 个真实问题, 全部修:

### fix(router): singbox JSON geosite 分支也不再静默吞错 (纰漏 1)

alpha.14 修 Issue 3 (geo integrity) 时改了 4 处 v2ray .dat load 站点,
**唯独遗漏了 `src/router/mod.rs:282` 的 geosite singbox JSON 分支**.
用户配 `"geosite": ["cn.json"]` 时若文件损坏或缺失, 依然静默跳过, 所
有依赖该 tag 的规则失效. 改成 match + tracing::error! 显式报错.

### fix(pool): WarmPool::get() timeout 分支补 wait_events (纰漏 2)

指标失真 + 反馈算法逻辑倒挂:
- 入口: `total_gets.fetch_add(1)` 一定加
- 队列拿到 tunnel 且等待 > 50ms: `wait_events.fetch_add(1)` 加
- **10s timeout 分支返 Err 时: 之前不加!**

100 请求全饿死超时 → total_gets=100 wait_events=0 → wait_ratio=0.0
→ Manager 判定"供给完美", 不但不扩容还可能触发缩容. 反馈算法在池
饿死时反而告诉自己"没问题". timeout 到这里意味着实际等了 10s 全被
阻塞, 显式计一次修 wait_events 语义.

### fix(lib): IPv6 SOCKS5 URL 加 RFC 3986 [] 包裹 (纰漏 3)

`src/lib.rs:129-130` 拼 socks5:// URL 时不区分 IPv4/IPv6:
```rust
format!("socks5://{}:{}", host, port)
```
用户配 `"listen": "::1"` → URL 变 `socks5://::1:37683` → 多个未包裹
冒号 → reqwest::Proxy::all() InvalidUrl → geo_updater 的 proxy 通
道直接崩. RFC 3986: URL 里 IPv6 主机必须 `[::1]` 包裹. `host.contains(':')
&& !starts_with('[')` 时自动加 `[...]`. 同时 `::` 通配符规范化到 `::1`
(loopback), 跟 `0.0.0.0` → `127.0.0.1` 对齐.

### feat(geo_updater, config_watcher): geo_sources 真正热更新 (纰漏 4, 方案 C)

老架构: `spawn_updater` 只在 `start_proxy` 时基于冷启动配置调一次,
task 内 sources / update_days 是 `move` 进闭包的死值. 后果:
1. 冷启动无 geo → 热改 config 加 geo → updater 永远未 spawn
2. 热改 tuning.geo_sources / geo_update_days → updater 循环用旧值

方案 C (完整热更新):
- 新增 `UpdaterState` (geodata_dir / sources / update_days / proxy_url)
- 新增 `UpdaterHandle { state: Arc<ArcSwap<UpdaterState>>, wake: Arc<Notify> }`
- `spawn_updater(handle)` 每次循环 `state.load_full()` 拿当前快照
- sources 空: 阻塞在 `wake.notified().await` 不空转
- 循环 sleep 用 `select!` 与 wake 争抢, 热改配置 100% ms 级响应
- 冷启动**无条件** spawn updater (不再有 `if !sources.is_empty()` 门)
- `ConfigWatcher` 接 `UpdaterHandle` clone. 文件变化时用
  `extract_updater_state` 重解析 tuning, 调 `handle.update(new)` 一次性
  Arc swap + notify_one. proxy_url 保留旧值 (inbounds 不热更新, 同步无意义)
- 全字段 update 幂等 (不做部分差分, 避免漏字段 bug)

行为对齐 CoreState hot-reload: 用户改 config 秒生效, 无需 restart.

### 自我审计通过项

- 0 编译警告 (default + ebpf feature 都通过)
- 18 tests 全过 (含 pool feedback + time_sync 全套)
- Rust borrow 检查通过 (NLL 保证 arc_swap Guard 生命周期)
- notify_one 语义正确 (permit-based, 顺序无关)

## [v0.4.4-alpha.16] - reload log 显示纠正 + ArcSwap guard 提前释放 (Issue 6 + drop) (2026-07-01)

### fix(config_watcher): reload log 显示真正触发 reload 的路径 (Issue 6)

之前用 `paths.first()` 取事件里第一个路径打日志:
```
INFO Watched path /etc/mirage-rs/geosite/geoip.dat.tmp changed. Attempting hot-reload...
```

但 notify 在 rename 事件里 paths 可能 `.tmp` 在前 `.dat` 在后, 而实际
的 reload 触发预测是 `.dat` (`.tmp` 被 predicate 过滤掉). log 显示的
路径跟真正被认可的路径不一致, 用户可能疑惑"是不是没原子 rename?".

修改 `src/config_watcher.rs::watch_config`:
- `paths.first()` → `paths.iter().find(<same predicate as trigger>)`
- 保证 log 显示的是真正满足 trigger 的 `.dat` 或 config 文件路径

不动 reload 触发逻辑本身, 只改 log 输出。

### perf(handler,dns): ArcSwap guard 提前 `drop()`, 让 hot-reload 后旧 state 立即可回收

3 处 (`src/dns/server.rs`, `src/proxy/handler.rs` 两处) 在提取 `Arc<OutboundNode>`
后立即 `drop(guard)`:

```rust
let leaf = outbound.resolve_leaf();
drop(current_state);  // ← 新增, guard 到此为止
match &*leaf {
    OutboundNode::Mirage { pool, .. } => {
        // 长期占用连接的 await, 此时不再引用旧 CoreState
    }
    ...
}
```

之前 guard 一直活到整个 `handle_client / proxy_tcp_target / DNS 转发`
结束 (几秒到几分钟). 期间 hot-reload swap 新 CoreState 时旧的**内存不
能立即回收**, 内存里存的是"用户所有 activeconnection 都放了 guard 才
能 drop 旧配置".

改后 guard 提取完 leaf 立刻释放, hot-reload 旧 state 内存能马上被 Arc
的 strong_count 降到 0 从而回收. 功能行为完全不变.

Rust NLL 保证 borrow 检查通过: `outbound` 引用在 `resolve_leaf()` 后
就不再使用, lifetime 已结束, `drop(current_state)` 合法.

### 影响
- Issue 6: 纯 log 显示问题, 无运行时行为改变
- drop: hot-reload 场景内存回收更快, 无功能变化
- 编译: 18 tests 全过, default + ebpf feature 都无 warning

## [v0.4.4-alpha.15] - geo_updater 30s 超时 + 空 body 拦截 (2026-07-01)

### fix(geo_updater): 补 alpha.14 审计出的 2 处纰漏

自查 alpha.14 后发现 2 个 alpha.14 引入或没解决的问题:

1. **reqwest client 无 timeout**: `build_client()` 用 `Client::builder().build()`,
   默认 timeout=None. proxy 抽风或服务端出网卡住时 `send()` 无限阻塞,
   fetch_with_fallback 里的 direct 重试永远等不到, updater 整个循环
   卡死. 加 `FETCH_TIMEOUT = 30s` 覆盖 connect + TLS + body 全流程.

2. **`bytes.len() == 0` 也会覆盖旧 .dat**: 服务端返回 200 但 body 空
   (中间 CDN 缓存 miss / 部署过程中的短暂空窗) 时, alpha.14 的
   `do_fetch` 会把 empty 字节写入 tmp 再 rename 覆盖旧 geosite.dat.
   下次 load 就报错, 全部规则失效. 加 `MIN_VALID_BYTES = 1024` 阈值,
   小于这个的 body 判定为异常, 不覆盖旧文件.

真实的 dlc.dat / geoip.dat 都 >= 1 MB, 1 KB 阈值宽松防误伤边缘 case
(理论上没有 legit 场景 < 1 KB).

## [v0.4.4-alpha.14] - log_file / geo 完整性 / geo proxy fallback (Issue 2/3/5) (2026-07-01)

### feat(log): 配置 log_file 字段生效 + log_level 真的读了 (Issue 2)

之前 `log_level` 字段 config 里定义了但**代码 hardcode `Level::DEBUG`**,
用户改 config 完全无效. `log_file` 字段甚至连 schema 都没有, install.sh
建的 /var/log/mirage-rs 目录闲置.

修改:
- `config.rs::Config` 加 `log_file: Option<String>` 字段
- `lib.rs::start_proxy` subscriber 初始化前主动读 config, 取:
  - `log_level` (info/warn/debug/error/trace, 严格 lowercase)
  - `log_file` (可选文件路径)
- 若 log_file 有效: append 打开, 用 `monitor::FileLogger` (Arc<Mutex<File>>
  + Clone + Write) 作 tracing MakeWriter, 同时保留 stdout + GLOBAL_LOGGER
  (GUI 内存 buffer). systemd journalctl 仍能抓 stdout 副本.
- 文件打开失败: eprintln + 降级到 stdout only, 不阻塞启动.
- install.sh: server 和 client config 默认写入
  `"log_file": "${LOG_DIR}/{server,client}.log"`

### fix(router): geo .dat load 失败静默 → error! 显式报错 (Issue 3)

`src/router/mod.rs` 5 处 `if let Ok(domains) = load_geosite_dat(...)` /
`load_geoip_dat` / `load_singbox_json` 静默吞错. 用户 geo 文件损坏时规
则集体消失, 无任何提示. 改成显式 `match` + `tracing::error!` 打出:
- 引用的 tag 名
- 完整文件路径
- 底层错误信息
- 提示 "Rules referencing this tag will match nothing"

方便用户知道"我这规则为啥不生效"是文件问题.

### feat(geo_updater): via=Proxy 失败真 fallback direct + install.sh 默认 via=proxy (Issue 5)

之前:
- install.sh 默认 `"via": "direct"`, 大陆用户 GitHub 直连超时/被墙,
  geo 数据永远拉不到, 路由规则全 fallback 到 default_outbound.
- geo_updater 里 via=Proxy 只在 proxy_url=None 时 fallback direct.
  实际 send/HTTP 失败**不 fallback**, 直接 return Err.

修改:
- `install.sh`: 两处 `"via": "direct"` → `"via": "proxy"`
- `geo_updater::update_one`: 拆成 `do_fetch` + `fetch_with_fallback`.
  via=Proxy 失败时自动重试 Direct 一次, info! 记录 fallback 成功.
  两次都失败 → error! 告知用户 "both proxy and direct fetch failed".

### 升级路径
现有 client 部署重装 (`sudo bash install.sh`) → 新 config 自动写
`log_file` + `via=proxy`. 手动 config 用户:
```json
"log_file": "/var/log/mirage-rs/client.log",
...
"geo_sources": [
  {"name": "geosite", "kind": "geosite", "url": "...", "via": "proxy"},
  {"name": "geoip",   "kind": "geoip",   "url": "...", "via": "proxy"}
]
```

## [v0.4.4-alpha.13] - TIME_SYNC 日志降噪 (Issue 1) (2026-07-01)

### fix(time_sync): |Δ| < 3s 的小抖动降到 DEBUG 级

Issue 1 修复. 之前 `set_offset_from_server_time` 只要 old != offset
就打 INFO, 但客户端系统时钟正常 jitter 通常 ±1s, 每条 WarmPool tunnel
建立都触发一次:

```
INFO TIME_SYNC: offset updated 0s → -1s (Δ -1s) from server...
INFO TIME_SYNC: offset updated -1s → 0s (Δ 1s) from server...
INFO TIME_SYNC: offset updated 0s → -1s (Δ -1s) from server...
```

pool_size=10 时启动就 10 行, 之后每次 tunnel refresh 又来一次, INFO
级别用户被淹没却看不到有意义的时钟事件.

修改 `src/time_sync.rs::set_offset_from_server_time`:
- `SIGNIFICANT_DELTA = 3` 秒阈值
- `|Δ| ≥ 3s`: INFO (真实时钟不同步, 用户需要知道)
- `0 < |Δ| < 3s`: DEBUG "minor drift" (小抖动, 想看细节可以调 log 级)
- `Δ == 0`: DEBUG "offset maintained" (保持原语义)

不改变 offset 存储行为, 7 项 time_sync 单测全过.

## [v0.4.4-alpha.12] - WarmPool 初始 target 修复 (alpha.11 遗漏) (2026-07-01)

### fix(pool): 初始 target 也应用 MIN_TARGET_FLOOR (alpha.11 遗漏)

alpha.11 把 decide_new_target 的缩容底线从 2 提到 10, 但**忘了改初始
化**. 用户实测日志:

```
02:23:43  WarmPool Manager: target 2 → 3 (gets=2, wait=2 [100.0%])
```

初始 target=2 (硬编码), 启动后前 2 个请求就 wait build, decide_new_target
5s 后才发现要扩, 每周期 +1 慢慢爬到 floor=10. 启动前几秒仍然卡.

修改 `src/proxy/pool.rs:331`:
- 之前: `AtomicUsize::new(2)`
- 现在: `AtomicUsize::new(MIN_TARGET_FLOOR.min(cfg.pool_size))`

现在客户端启动瞬间就有 10 (或 pool_size, 取较小者) 条常温 tunnel, 突发
真正无 wait.

## [v0.4.4-alpha.11] - WarmPool 缩容底线 2 → 10 (突发无 wait) (2026-07-01)

### fix(pool): 提高 idle 期最低 tunnel 数, 解决突发并发 66% wait build

用户实测 alpha.10 后发现:

|场景|POC (rate=10 × 多流)|mirage-rs (rate=40 单流)|
|---|---|---|
|YouTube 视频|流畅|流畅但 CPU 更低|
|突发多标签开页|流畅|明显卡顿|

client 日志确认原因:
```
WarmPool Manager: target 2 → 3 (gets=6, wait=4 [66.7%], expired=0)
```

浏览器突发 6 个 SOCKS5 CONNECT 时, adaptive pool 已缩到 target=2, 只
有 2 条 tunnel 现成, 剩 4 条得等 build (770-2000ms 每条握手), **66%
的请求实际排队**. POC 因 pool_size=20 固定不缩, 6 并发时 6 条 tunnel
立刻各分一条, 每条 rate=10 也够 → 用户感受"多流并行"很流畅.

### 修改
`src/proxy/pool.rs::decide_new_target` — 缩容底线从 2 提到 10:
- `const MIN_TARGET_FLOOR: usize = 10;`
- 实际 floor = `MIN_TARGET_FLOOR.min(max_size)`, pool_size < 10 时自动
  降为 max_size (小 pool 场景不会被卡死)

### 效果
- idle 期至少保 10 条常温 tunnel (BDP × 10 × TLS ≈ 5-10 MB RAM, 可接受)
- 常见浏览器最大并发 (Chrome/Firefox 每 host 6-8) 都能立刻分到 tunnel
- 突发 wait_ratio 应从 66% 降到 0-10%
- 高峰后 idle 仍会缩容, 只是不缩到 2 而已 (不影响资源节省的主旨)

### 用户行动
本版无需改 config, 直接部署 alpha.11 即享受. 浏览器多标签开页会明显
不卡, 突发 wait 日志应几乎消失.

未来 (alpha.12+) 可考虑加 tuning.pool_min_floor 配置字段, 让重内存
环境的用户按需调低. 本版先固定 10 观察实测.

## [v0.4.4-alpha.10] - cwnd_gain 20 → 15 跟 POC 对齐 (2026-07-01)

### perf(brutal): cwnd_gain 改回 15, 跟 Python POC 实测一致

alpha.9 砍了 autofallback 后 brutal 真的全程在跑了, 但实测速度仍不
及 Python POC. 全面对比两边 setsockopt 序列发现仅剩两处差异:

|项|POC|Rust alpha.9|备注|
|---|---|---|---|
|brutal cwnd_gain|**15**|20|本版改|
|TCP_NODELAY|未设|set_nodelay(true)|握手期间降低首包延迟, 数据阶段无影响|
|SO_KEEPALIVE|开启|未设|仅死连接检测, 无吞吐影响|

POC `_DEFAULT_CWND_GAIN = 15` 注释写"对齐参考实现". 我在 alpha.5 改成
20 是基于"apernet 内核默认 20"的判断, 但实测 POC 的 15 反而更快.
推测原因: cwnd_gain=2.0× BDP 在高丢包链路上会放大重传成本 — 同时在
途的包多了, 单个丢包会拖累更多窗口前进, 净吞吐反不如 1.5× 紧凑.

修改 (3 处必须同步, 否则 BPF 反馈环会用旧值覆盖):
- `src/proxy/brutal.rs:78`  (set_brutal_rate, accepted socket)
- `src/proxy/brutal.rs:161` (apply_brutal, client outbound)
- `src/proxy/pool.rs:608`   (update_brutal_rate, 动态调节)

不动 NODELAY: 它在 TLS 握手期间是必要的 (小包不被 Nagle 拖延首包延迟).
数据传输阶段, Mirage 应用层 AEAD send 都是大块 (≥ MSS), Nagle 本就不
会缓存它们, NODELAY 设不设没区别. POC 没设只是没人写而已, 不是因为
跟 brutal 冲突.

### alpha.5 → alpha.10 brutal 排错全表 (汇总)

|alpha|改动|结果|
|---|---|---|
|.5|cwnd_gain 15 → 20 (误判 apernet 默认)|无效, 反而是错的|
|.6|加 autofallback (5% 阈值)|本意安全网, 实测误杀 brutal|
|.7|client 关 BPF|跟 brutal 无关, 解 direct outbound 卡死|
|.8|listener 预设算法 (POC 对齐)|关键修复, 让 brutal 真生效|
|.9|砍 autofallback|brutal 全程跑, 不再被切走|
|.10|cwnd_gain 20 → 15 (POC 对齐)|**本版**, 期望追平 POC 速度|

跟 POC 还剩的不影响吞吐的小差异: SO_KEEPALIVE (仅死连接检测). 后续
有需要再加.

## [v0.4.4-alpha.9] - 砍掉 Brutal autofallback, 跟 POC 行为对齐 (2026-06-30)

### fix(brutal): 不再自动从 brutal 切回 BBR

alpha.8 修对了 brutal 应用时机 (listener 预设算法), 实测 brutal 真的
在跑, 但**速度仍达不到 Python POC 水平**. 服务端日志铁证:

```
09:00:17.066  brutal 连接建立, pacing_rate 10 Mbps, cwnd 308
09:00:27.474  WARN Brutal CC unsuitable... retrans 16.3% in 10s window.
              Auto-fallback to BBR.
```

只跑 10 秒, alpha.6 加的 autofallback 监测就因 retrans > 5% 把 brutal
切掉了. 这恰恰违反了 brutal CC 的设计哲学:

> **brutal 的工作原理就是"丢包是噪声, 死磕设定速率, 让上层应用见到稳
> 定吞吐"**. 高 retrans 是 brutal 工作过程中**正常现象**, 不是"不适合"
> 的信号. POC 实测可用就证明这条链路是 brutal-friendly 的, 重传是预期
> 的代价, 净吞吐仍优于 BBR.

修复 (src/proxy/mirage_server/mod.rs:78-93):
- 移除 accept 循环里的 `spawn_fallback_monitor(fd)` 调用
- `set_brutal_rate(fd, rate)` 保留, listener 预设算法名机制不变
- 行为现在 100% 跟 POC 对齐: 设了 brutal_rate_mbps 就硬跑到连接关闭

`spawn_fallback_monitor` 函数本身保留在 brutal.rs (含 TcpInfoExt
struct + getsockopt 包装), 留作未来 `tuning.brutal_autofallback = true`
opt-in 高级选项. 默认不调用, 代码也不删, 因为这套基础设施做对了
(SO_COOKIE 防 fd 复用 / Linux 3.15+ ABI 完整结构), 留着不浪费.

### 用户行动建议
- 不适合 brutal 的链路: 把 config 里 `"brutal_rate_mbps"` 改 0 或删掉
  字段 (server 端会自动 fallback 到系统默认 CC = BBR)
- 适合 brutal 的链路: 默认行为就是对的, 不必动

### alpha.5 → alpha.9 整段 brutal 排错总结

|alpha|改动|结论|
|---|---|---|
|.5|cwnd_gain 15 → 20|对的, 跟 apernet 默认对齐, 保留|
|.6|加 autofallback|本意是安全网, **实际是误杀 brutal**, 本版砍|
|.7|client 关 BPF|跟 brutal 无关, 解 direct outbound 卡死|
|.8|listener 预设算法 (POC 对齐)|关键修复, 让 brutal 真生效|
|.9|砍 autofallback|本版, **正式跟 POC 行为对齐**|

## [v0.4.4-alpha.8] - Brutal CC 应用时机修正 (匹配 Python POC) (2026-06-26)

### fix(brutal): listener 上预设算法名, accepted socket 只补速率

跟 Python POC (/opt/claude/mirage/server.py:349-360) 对比发现关键
应用时序差异:

Python POC:
  1. listener socket 上 setsockopt(TCP_CONGESTION, "brutal")
  2. accept → 子 socket 自动继承 brutal 算法名
  3. accepted socket 上仅 setsockopt(TCP_BRUTAL_PARAMS, rate, ...)

Rust (alpha.7 之前):
  1. listener socket 上不设, 用 kernel 默认 CC (bbr/cubic)
  2. accept → 子 socket = bbr
  3. accepted socket 上 setsockopt(TCP_CONGESTION, "brutal") 中途切换
  4. 然后 setsockopt(TCP_BRUTAL_PARAMS, rate, ...)

中途切换 CC 在 Linux 是合法的, 但 brutal kernel 模块的 init/pacing
状态过渡可能不干净 — 子 socket 已 ESTABLISHED, kernel 默认 pacing
路径已激活, 切到 brutal 后 sk_pacing_status 转换 + brutal 自己的
pacer 之间状态可能不一致, 导致实测吞吐塌方. POC 子 socket 从 SYN-ACK
起就在 brutal 算法下, kernel 状态干净, 跑得很顺.

修复 (src/proxy/brutal.rs + mirage_server/mod.rs):
- 新增 `set_brutal_on_listener(fd)` — 仅设算法名, 在 bind 后第一次
  accept 前调用一次
- 新增 `set_brutal_rate(fd, rate)` — 仅设 TCP_BRUTAL_PARAMS, 给每个
  accepted socket 用
- 保留旧 `apply_brutal(fd, rate)` 给 pool.rs (客户端出站) — 客户端
  是主动 connect, 无 listener 可继承, 只能在 connect 后 apply

### 验证方法

部署后:
```bash
sudo journalctl -u mirage-server --since "2 min ago" | grep "Brutal CC pre-set"
```
应有一行 "Brutal CC pre-set on listener fd=X (will be inherited by
accepted sockets)".

然后 ss -tipn 看 cwnd 走向 — 跟 POC 在同链路上跑应该数据相近.

cwnd_gain 仍保持 20 (apernet 默认), 不改成 Python 的 15 是因为
alpha.4 (15) 和 alpha.5/6 (20) 实测都慢, 真正瓶颈是算法应用时序,
不是 cwnd_gain 取值.

## [v0.4.4-alpha.7] - eBPF SockMap 直连转发问题临时禁用 (2026-06-26)

### fix(install): 客户端 config 默认 ebpf_mode = "off"

实测发现: 客户端访问 direct outbound 网站 (如 .cn 域名走直连) 时,
日志显示 "eBPF SockMap: spliced ... (Zero-copy bypass activated)",
但浏览器无响应, 5-15s 后超时重连, 周而复始。

根因 (代码层): `src/proxy/handler.rs:258-312` 的 direct outbound 路径
里, `EbpfEngine::register_splice()` 把两个 socket 的 cookie 插入
SockHash, 然后 handler 进入 epoll 等 EPOLLRDHUP, **完全不再 Tokio
读写**。问题:
  1. `register_splice()` 的 Ok() 仅代表 map.insert 成功
  2. 不代表 BPF stream_verdict 程序在数据到达时真能正确转发
  3. 一旦 BPF redirect 静默失败 (cookie 时序、kernel 版本 ABI 差异、
     sk_psock 初始化竞争等), 数据全静默丢, 也不会 fallback 回 Tokio

实测确认: 客户端 config 加 `"tuning": { "ebpf_mode": "off" }` 后
direct 立即正常。

短期方案 (本版): install.sh 客户端 config 默认 `ebpf_mode = "off"`,
让用户开箱即用。
长期方案 (待调研): 根治 SockMap stream_verdict 不可靠转发, 可能需要
在 register_splice 后做"健康探测"才标记 ebpf_spliced = true, 或改成
Tokio + BPF 双路监听 (BPF 接管成功则 Tokio 退出, 否则 BPF 旁路只做
统计)。

### 影响
- 本版客户端不享受 BPF zero-copy direct outbound 加速 (但 direct 走
  Tokio 性能也完全够用, 一般用户感知不到差别)
- BPF sock_ops RTT_CB / XDP DNS 等其他 BPF 功能也被一并停用 (它们都
  在 ebpf_mode 总开关下), 客户端动态 brutal 调节失效。但客户端 brutal
  默认本来就关闭, 影响面 ≈ 0
- 服务端不受影响 (服务端本就 auto-skip BPF)

## [v0.4.4-alpha.6] - Brutal CC 自适应回落 + install.sh 文本修正 (2026-06-25)

### feat(brutal): retrans 率超阈值自动 setsockopt 切回 BBR

alpha.5 把 cwnd_gain 从 15 改到 20 之后实测仍慢, ss -tipn 数据显示问
题不在 cwnd_gain 而在链路本身:

- RTT 162-190ms (跨洲)
- retrans 12-15% (链路真在丢包, 不是噪声)
- pacing_rate 5 Mbps (brutal 在按 config 走), delivery_rate 0.5 Mbps
- BBR 在同一链路上能跑满 5 Mbps 因为它感知到 RTT/loss 主动收敛

brutal CC 的设计哲学 ("丢包是噪声, 死磕速率") 与高丢包链路冲突, 死磕
导致重传放大反而吃光带宽. 这是算法本质, 不是 bug.

但服务端不能因此就放弃 brutal — 高 RTT 低丢包的跨洲专线场景 brutal
仍然胜 BBR. 取舍解法: **保留默认开启, 同时跑运行时自适应监测**.

实现 (src/proxy/brutal.rs::spawn_fallback_monitor):
- 每条 brutal-enabled accept socket 起一个轻量 tokio task
- 每 10s 调 getsockopt(TCP_INFO) 读 total_retrans / segs_out
- 单窗口 retrans > 5% 且 segs > 500 (流量足够判断) → setsockopt
  TCP_CONGESTION=bbr 立即切走, log warn 解释原因
- 连续 6 个窗口正常 (1 分钟) 认为链路稳定, 停止监测省 CPU
- 最长 3 分钟无定论也停止
- 用 SO_COOKIE 防 fd 复用错认 (socket 关闭后 fd 可能立即被新连接拿
  到, 仅靠 fd 监测会误改无关 socket)

libc 0.2.186 的 tcp_info 只到 tcpi_total_retrans, 没暴露 segs_out
等 Linux 3.15+ 字段. 自定义 TcpInfoExt 完整 struct (144 字节,
segs_out offset 136, 匹配 Linux upstream ABI), getsockopt 长度匹配,
老内核场景下尾部字段保 0, MIN_SEGS_PER_WINDOW 阈值自然兜底, 安全
降级不需特殊处理.

### fix(install): 误导的 brutal_rate 建议值

旧文本推荐 8-10 Mbps/单连接, 实际是给 100M/1G 链路设的过保守值,
单流 YouTube 直接被 cap. 新文本基于"链路带宽 30-50%"建议, 100M
出口 → 30-50 Mbps, 1G → 300-500. 自适应 fallback 兜底, 设过头
也不会比 BBR 差.

### 升级影响
- 服务端无需手改 config, 重启即享受自适应 brutal
- 用户在不合适的链路 (跨洲 CDN / 国内移动) 部署也不会比 BBR 慢
- 高 RTT 低丢包链路 (跨洲专线) brutal 加速依然有效

## [v0.4.4-alpha.5] - Brutal cwnd_gain 修正 (2026-06-25)

### perf(brutal): cwnd_gain 15 → 20 (匹配 apernet 内核默认)

实际部署反馈, 服务端启用 brutal 后 YouTube 等场景下连接速度反而比关
闭 brutal 慢. 7 组 A/B 对照表 (brutal=0/2/8/20/50, pool=1/5/50) 显示:

- pool 越大越慢 (50 > 5 > 1 → 不是 N 流互挤, 因为单视频流只占 1-2 条)
- E (rate=20, pool=5) ≈ F (rate=50, pool=5) — **rate 不是瓶颈**
- 所有 brutal 启用配置都 < 无 brutal (C)

诊断结论: cwnd_gain 是瓶颈. brutal cwnd = BDP × cwnd_gain / 10. 我们之前
代码里硬塞 `CWND_GAIN_X10 = 15` (= 1.5× BDP), 在低 RTT/高带宽链路 (国
内访问海外 CDN 经常 < 50ms) cwnd 偏紧, ACK 还没回 cwnd 就满, 实际吞
吐 < 设定 rate, 表现就是 E ≈ F (都被 cwnd 卡同一上限). apernet/tcp-brutal
内核模块默认是 `CWND_GAIN_DEFAULT 20` (= 2.0× BDP), 我们对齐.

修改:
- `src/proxy/brutal.rs:73`  CWND_GAIN_X10 15 → 20  (静态 apply_brutal)
- `src/proxy/pool.rs:608`   CWND_GAIN_X10 15 → 20  (动态 update_brutal_rate)

两处必须同步, 否则客户端 BPF 反馈 loop (lib.rs:250-318) 跑起来后会用
旧值覆盖. 此 alpha 仅一行实质改动, 待用户验证后再决定是否进一步暴露
为 advanced 可调字段.

## [v0.4.4-alpha.4] - 安装体验 + 版本治理 (2026-06-24)

### feat(install): 节点 URI 导出 / 导入
- 服务端配置完成后询问公网地址, 生成 `mirage://<url-encoded-pwd>@<host>:<port>?sni=<sni>[&brutal=<mbps>]` 单行节点串, 存到 `/etc/mirage-rs/node-export.txt` (chmod 600) 并在终端打印. 装了 `qrencode` 同时出 UTF8 二维码.
- 客户端 `config_client` 启动加 "粘贴 URI 自动填" / "手动输入" 分支. 同机部署 mode 3 时, URI 默认自动填入本机刚生成的, 一回车复用.
- URL 编解码 UTF-8 安全 (中文密码可用), 6 类非法 URI (空 / 错协议 / 缺端口 / 非数字端口 / 空 SNI / 残缺) 全拒. 不支持 `[::1]` 形 IPv6 主机 (regex 限制), 这种走手动模式.

### feat(install): 监听端口占用检测
- 服务端 port + 客户端 inbound_port 接 `ask_port()` (基于 `ss -tlnH`). 占用即 warn + 显示占用进程名, 用户可选 force-continue. `ss` 不可用 (HAVE_SS=0) 自动跳过, 不阻塞流程.

### chore(version): 三层同步 binary 版本信息
- **L1**: `Cargo.toml` 0.2.3 → 0.4.4-alpha.4. 历史欠账 — 该字段从未更新, 5 个 tag 以来 `mirage --version` 一直输出 "0.2.3".
- **L2**: `build.rs` 跑 `git describe --tags --always --dirty` 注入 `MIRAGE_GIT` env, `src/bin/mirage.rs` 用 `concat!(CARGO_PKG_VERSION, " (", MIRAGE_GIT, ")")` 作为 clap version. 现在输出:
  ```
  mirage-rs 0.4.4-alpha.4 (v0.4.4-alpha.4)
  ```
  dev build 自带 `-dirty`. rerun 钩子 watch `.git/HEAD/refs/heads/refs/tags/index`, commit/staged 都触发 rebuild.
- **L3**: `release.yml` 加 sanity check, tag vXYZ 与 Cargo.toml XYZ 不一致 CI 立刻 fail 并提示先 bump. checkout 加 `fetch-depth: 0` 让 git describe 拿全 tag 历史.

### chore(test): 综合 bug 验证脚本 `scripts/test_bugfixes.sh`
- 覆盖 v0.4.4-alpha.x 6 个 bug (pool 缩容锁死 / Geo 启动时序 / TCP 僵尸 / UDP cancel-safety / DJB2 panic / pool 雪崩). 3 种模式: `quick` 全自动 3 个 / `all` 全套需手动配合 / 指定 bug 号. 末尾自动 PASS/FAIL/SKIP 汇总.

### 升级影响
- 无代码层 bug 修复 (alpha.3 已修齐). 本版纯 DX/UX. 已部署 alpha.3 没有 OOM/panic 实战问题的不必急升.
- 升级后 `mirage --version` 会反映真实版本; 之后的 alpha.5/alpha.6 不会再静默输出 alpha.3 hash.

## [v0.4.4-alpha.3] - 2 个隐蔽生产 bug 修复 (2026-06-23)

### Critical Fixes
- **fix(ebpf): DJB2 哈希算法 Rust 溢出 panic (恶意域名远程崩溃)** — `src/ebpf/mod.rs::update_dns_cache` 的 DJB2 哈希 `hash = ((hash << 5) + hash).wrapping_add(b as u64)` 末尾 wrapping 是对的, 但前面的 `+ hash` 是普通加. Rust debug build (含任何启用 `overflow-checks = true` 的 release) 一旦 u64 溢出就 panic. **攻击者可构造超长恶意域名通过 XDP 触发, 精准 panic 用户态管控平面**. 修复: 改为 `(hash << 5).wrapping_add(hash).wrapping_add(b as u64)`, 全部 wrapping 跟 C 端 dns_xdp.c 的 u64 + 截断语义一致.
- **fix(pool): WarmPool.get() 无超时导致雪崩 OOM** — 旧签名 `pub async fn get(&self) -> Tunnel` infallible, 池子空 + builder 反复连接上游失败时只 log + sleep 1s, **永不调用 notify_one**. 每个 pool.get() 死等, 浏览器请求堆积成百上千 → FD 耗尽 → OOM 进程被 OS 强杀. 修复: 改成 `Result<Tunnel>` + 内部 10s `tokio::time::timeout`. 4 个调用点 (handler/dns/healthcheck/udp_relay) 全部更新, Err 时 log + 优雅 return.

### 实际部署影响
v0.4.4-alpha.2 也带这两个 bug:
- DJB2 panic: 配置了 fakeip + XDP 的客户端, 攻击者发恶意域名 XDP 触发崩溃
- pool 雪崩: 客户端上游服务器宕机 / 网络抽风时, 浏览器多个 tab 同时使用代理 → FD 在分钟级别耗尽

强烈建议从任何 v0.4.x 升 alpha.3.

## [v0.4.4-alpha.2] - 4 个生产级 bug 修复 (2026-06-23)

### Critical Fixes
- **fix(pool): WarmPool 空闲期缩容锁死 (资源燃烧)** — `decide_new_target` 的 `total_gets > 0` 守护误把"高峰后回到 idle"的缩容路径禁用. 高峰把 target 涨到 max_size=40 后用户睡觉流量归零 → target 永久钉死 → builder 维持 40 个 idle TLS 连接 → max_age 到期 sweeper 杀 → builder 又建 → 一整夜烧 CPU 握手. `cur_target > 2` 已是 floor 保护, 删守护即可. 删 2 个误测试, 加 3 个新测试 (含 drain-to-floor 回归).
- **fix(watcher): GeoUpdater 与 ConfigWatcher 启动时序空隙** — `spawn_watcher` 只 watch `config_path`, geo_updater 30s 后下载的 .dat 落地不触发 Router 重建, 所有 geosite/geoip 规则 silent no-op → 用户访问全部 fall back 到 `default_outbound`, 必须手动改 config.json 才能修复. 修复: 同时 watch `geodata_dir`, 不存在时主动 `create_dir_all`. 事件过滤只对 config 文件或 `.dat` 文件触发 reload (避免 .tmp 抖动).
- **fix(tcp_relay): 服务端 TCP 转发僵尸任务泄露 (30 分钟资源燃烧)** — `tokio::join!(upload, download)` 在客户端断网时只让 upload 立刻退出, download 阻塞在 `up_read.read()` 等上游响应直到 1800s 超时. 弱网环境频繁闪断重连 → FD + tokio 协程泄露累积 → 耗尽内存. 修复: 两方共享 `Arc<AtomicI32>(upstream_fd)`, 任一方退出 swap -1 并 `libc::shutdown(SHUT_RDWR)` 强制关闭 upstream socket, 另一方 read/write 立即返回 Err 退出. 不用 select!/abort 是为了避免 cancel mid-write 损坏 AEAD 帧 (见下).
- **fix(udp_relay): tokio::select! cancel-safety 导致 AEAD 帧损坏** — UDP relay 的 `tokio::select!(tunnel_uplink, tunnel_downlink)` 一方完成时暴力 drop 另一方, 若 downlink 正在 `writer.send_data` 半截 (TLS 5B header 已发出去, payload 没写完), 之后外层 `send_close_notify` 又写 alert → 客户端拼接半截帧 + alert 触发 AEAD MAC 校验崩, "bad record mac". 修复: 改用 watch 频道做协作式停止信号, 两 task 都 join (不 select!), select! 仅围绕 cancel-safe 的 read 点 (recv_data / rx.recv), AEAD 写在 select! 外永远不被中途打断.

### 实际部署影响
v0.4.4-alpha.1 的 4 个 bug 都已实际部署可触发:
- pool 缩容锁死: 任何启用 brutal + 流量有早晚峰差异的客户端
- geo 启动时序: 任何首次部署 + 配了 geo 规则的客户端 (重启过的也复现)
- tcp 僵尸泄露: 任何服务端在弱网客户端场景下 (移动用户 / WiFi 不稳)
- udp cancel-safety: 任何启用 UDP relay 的部署 (DNS/QUIC 等)

强烈建议从 v0.4.4-alpha.1 升 alpha.2.

## [v0.4.4-alpha.1] - Active BPF Tunnels Dashboard + BPF struct 扩展 (2026-06-22)

### feat(gui): Active BPF Tunnels 表格 + Brutal CC 指示灯
- Neon Dashboard 新增 "Active BPF Tunnels" 面板, 实时展示每条 BPF 跟踪的 TCP tunnel: Remote 地址 / RTT (ms, < 50 绿 / < 150 黄 / > 150 红) / Retrans 重传 / 趋势箭头 (↑↓→, JS 5 点滚动窗口跟前次比 ±10%).
- 行可点击展开详情: cookie 16-hex / cwnd / data_segs (调试视角).
- 1Hz 轮询 `/api/bpf/tunnels`. LRU 淘汰的 cookie 自动从前端历史 Map GC.
- 顶部状态条新增 "Brutal CC: ACTIVE/STATIC" 指示灯 (跟 eBPF ENGINE 并列). ACTIVE = 任一 tunnel `srtt_us > 0` (sock_ops RTT_CB 已生效).

### BPF struct 扩展 (sockmap.c::tcp_state)
- 加 `remote_ip[4]` (IPv4 在 `[0]`, IPv6 全 4 个 u32) + `remote_port` (u16) + `family` (u16). size: 16 → 36 字节.
- Rust `TcpState` 严格对齐, C/Rust offset_of! 实测一致, sizeof 均 36.
- `mirage_sockops` 沿用"ctx 字段全部 prefetch 到 locals"防御写法 (避免 v0.4.0 那个 verifier "modified ctx ptr" 坑). llvm-objdump 字节码确认无 modified ctx ptr 模式.

### API
- `/api/bpf/tunnels` 新增 `remote` 字段: 格式化成 `"192.0.2.5:443"` / `"[2001:db8::1]:443"` / `"?:?"`. IPv4 字节序: 内核 network byte order u32, 小端机加载后 `b0 = raw & 0xff` 即第一个 octet, 验证 1.2.3.4 解码无误.
- `cookie` 字段从 JSON Number 改成 JSON String 序列化, 避开 JS Number 2^53 精度上限 (理论纰漏, 物理不可触发但 belt-and-suspenders).

### 设计权衡声明 (重要)
当前 BPF `target_ips` 白名单仅登记: 客户端 → mirage 服务器 IP / 服务端 ← 客户端 IP. **不跟踪 upstream 业务连接** (github.com / youtube 等). 因此 Active Tunnels 表格里:
- 客户端: 全部 N 行 remote = mirage 服务器 IP (反映 WarmPool 健康度)
- 服务端: 各客户端 IP (反映谁在连接)

想展示业务目标域名需新增"服务端给每个 upstream 连接也注册 target_ips + 反向关联 cookie"那套, 单独立项.

## [v0.4.3-alpha.1] - 多源 Geo + 骨架重构 + 反馈算法 (2026-06-22)

### ⚠️ Breaking Schema Change (alpha 期硬升级, 无向后兼容)
- **`tuning.geosite_url` + `tuning.geoip_url` 已删除**, 改为 `tuning.geo_sources` 数组. 旧 config 启动会被 serde 拒绝 (unknown field). **必须迁移**, 迁移示例见 README "客户端配置示例".

### feat(geo): 多源 Geo 下载 + via=direct/proxy + 自定义命名
- `tuning.geo_sources: [{name, kind, url, via}]` 数组. 每个 source 独立配置:
  - `name`: 文件保存为 `<name>.dat`, 必须在 sources 内唯一 (重复直接 ERROR 不启动).
  - `kind`: `"geosite"` (域名) 或 `"geoip"` (IP CIDR).
  - `via`: `"direct"` (默认) 或 `"proxy"` (走客户端本地 socks/mixed inbound).
- 国内服务器拉 GitHub 受阻时全部设 `"via": "proxy"` 即可走代理出口.
- 配合 `routing.geo_alias` 起短名: `"geo_alias": {"ls": "loyalsoldier.dat"}` → 规则写 `"geosite": ["ls:cn"]` 自动解析.
- 新增 `tuning.geo_update_days` 配置 (默认 7 天).
- `Cargo.toml`: reqwest features 加 `"socks"`.

### refactor: 骨架重构 (严格行为等价, 0 warning)
- **`src/proxy/mirage_server.rs` (470 行 monolith) → 6 个职责单一子模块** (`mod / handshake / camouflage / control / tcp_relay / udp_relay`). 详见 commit 909cf4e.
- **`src/gui/` → `src/api/` 改名 + `mod.rs` (313 行) 拆 9 个文件** (`mod / state / sampler / handlers/{overview,bpf_tunnels,history,logs,proxies,rules}`). 匹配"API 作为独立模块"的设计意向. 详见 commit e0db37c.
- 后续功能演进 (DNS 转发器完善 / 多源 Geo per-source 配置 / 等) 都能在更清晰的模块边界上扩展.

### feat(pool): WarmPool 反馈式弹性算法 (替代 RPS*3+2 开环)
- 旧算法直接由 RPS 推 target, 高 RPS 时 pool 堆积 → 频繁裁剪触发 close_notify 噪音.
- 新算法 AIAD 闭环, 测三个指标 (wait_events / total_gets / expired_unused) 决策扩缩容.
- 不再做硬裁剪, target 只控制 builder 建货节奏, queue 自然到 max_age 被 sweeper 收掉.
- Manager 周期 2s → 5s. 详见 commit e80adb7.

### feat(ebpf): 服务端自动跳过 eBPF + ebpf_mode 三态配置
- 新增 `tuning.ebpf_mode`: `"auto"` (默认, 跟 CLI 子命令走) / `"force"` / `"off"`.
- 服务端跑 BPF 全部子系统都无价值, auto 模式服务端自动跳过. Alpine 服务端不再需要 `CONFIG_CGROUP_BPF` 内核重编. 详见 commit 1a63838.

### docs(brutal): brutal_rate_mbps 设计哲学
- install.sh 加 23 行教育性提示 + 默认 100 → 8 Mbps. README 新增 "brutal_rate_mbps 的设计哲学" 章节 (取值对比表 1G/100M × 8/10/50/100 Mbps).

## [v0.4.2-alpha.1] - 服务端 eBPF 自动跳过 + WarmPool 反馈算法 (2026-06-22)

### feat(pool): WarmPool 反馈式弹性算法
- 旧 `target = RPS*3+2` 开环算法存在"建-裁震荡"问题, 高 RPS 时频繁裁剪触发 close_notify 噪音.
- 新算法基于实际指标 (wait_events / total_gets / expired_unused) 做 AIAD 闭环:
  - `wait_ratio > 0.2` AND target < max → 扩 20% (最少 +1)
  - `wait_ratio == 0` AND `expired ≥ gets/2` AND target > 2 → 缓慢缩 -1
  - 否则维持
- **不再做硬裁剪** (删除旧 `q.len() > target+2` 那段). target 只控制 builder 建货节奏, queue 自然在 max_age 到期被 sweeper 收掉. close_notify 频率大幅下降.
- Manager 周期 2s → 5s (减噪 + 指标聚合更稳).
- decide_new_target 提取为纯函数, 新增 8 个 unit test 覆盖 idle/pressure/clamp/floor/priority/no-traffic 场景. 总测试数 32 → 40.

### feat(ebpf): 服务端自动跳过 eBPF + ebpf_mode 三态配置
- 服务端跑 eBPF 全部子系统都无价值: sockmap splice 要明文 (服务端入站加密), sockops RTT 没人消费, XDP DNS 只对本地应用有意义, sk_lookup 只劫持本地流量. 之前服务端无条件加载浪费内存/CPU, 还卡 Alpine 用户的 CGROUP_BPF 内核要求.
- CLI 子命令 server/client → `is_server` 参数透传到 `start_proxy`. 服务端默认 (auto 模式) 跳过 eBPF.
- 新增 `tuning.ebpf_mode` 三态:
  - `"auto"` (默认): client 启用, server 跳过
  - `"force"`: 任何情况强制加载 (调试)
  - `"off"`: 任何情况不加载
- README Alpine 章节同步: 服务端 stock `linux-lts` / `linux-virt` 内核可直接用, 不再需要重编内核.

### docs(brutal): brutal_rate_mbps 设计哲学
- 用户反馈默认值 100 Mbps 与 Brutal CC 设计理念背道而驰 — Brutal 是为单连接全速设计, WarmPool 并发多条 brutal 连接各自独立打满设定值, 100 配 pool_size=50 实际需求 5 Gbps, 严重过载.
- install.sh 加 23 行教育性提示 + 默认 100 → 8 Mbps + 超 10 Mbps 时 WARN.
- README 新增 "brutal_rate_mbps 的设计哲学" 章节: 含取值对比表 (8/10/50/100 Mbps × 1G/100M 链路).

## [v0.4.1-alpha.2] - Brutal CC 真·能用了 — TCP_BRUTAL_PARAMS opt 号修正 (2026-06-22)

### Critical Fix (REAL root cause)
- **`TCP_BRUTAL_PARAMS` 常量 23 → 23301**. 标准 Linux 的 `23 = TCP_FASTOPEN`, 内核协议栈先吃掉 setsockopt 不让 brutal 模块看到, TCP_FASTOPEN 在 ESTABLISHED 状态直接返 `-EINVAL`. 实测 `apernet/tcp-brutal` 上游源码确认正确值 `23301` (官方就是为避开 Linux 标准 opt 冲突). 修复两处 (`brutal.rs` + `pool.rs` 动态调节循环).
- **`struct BrutalParams` revert 回 `#[repr(C, packed)]`** (12 字节). 上一版 alpha.1 基于第三方误判把它改成 `#[repr(C)]` (16 字节), 实测拿 `brutal.c` 上游源码确认内核 `struct brutal_params { ... } __packed;` 本就是 packed, sizeof=12. Alpha.1 的"对齐修复"方向错了, alpha.2 一起还原.

### 历史诚实声明
- v0.4.0-alpha.1 ~ v0.4.1-alpha.1 任何启用 `brutal_rate_mbps` 的部署都**从未真正生效**, 因为 opt 号撞 TCP_FASTOPEN. 装了 hysteria-tcp-brutal-dkms 也白装. 静默退回 BBR/Cubic. 用户没发现是因为 `install.sh` 默认 `brutal_rate_mbps=0` 没启用过.
- alpha.2 修完之后, brutal CC 才**真正**第一次工作.

## [v0.4.1-alpha.1] - Fix BrutalParams FFI Alignment + Misleading Log Cleanup (2026-06-22)

### Critical Fix — Brutal CC 从未真正生效过
- **`src/proxy/brutal.rs` + `src/proxy/pool.rs`: `#[repr(C, packed)]` → `#[repr(C)]`**.
  Rust 这边 packed 让 `size_of::<BrutalParams>() = 12`, 但内核 apernet/tcp-brutal 模块的裸 C struct 自然 8 字节对齐 (u64 + u32 + 4B 尾部 padding) → `sizeof = 16`. `setsockopt(optlen=12)` 命中内核 `optlen < sizeof(params) → -EINVAL` 校验, 静默回退到 BBR/Cubic.
- 影响: 任何启用了 `brutal_rate_mbps` 的部署都没真正用上 Brutal CC. 装了 hysteria-tcp-brutal-dkms 模块也白装. 之前用户没报 "TCP_BRUTAL_PARAMS failed" 是因为没人真启用过 (install.sh 默认 0).

### Quality / Log Noise
- 服务端 `first_chunk` 阶段的 `close_notify` 错误降级为 DEBUG (这是 WarmPool Manager 弹性裁剪触发的客户端主动优雅关闭, 不是真错).
- 服务端 `first_chunk` 阶段的 `recv_data timed out!` 降级为 DEBUG (idle warmup 60s reap, 是预期清理).
- WarmPool Manager 主动 evict 过期 tunnel (每 2s 扫一次), 配合客户端 max_age 30-50s 不再等服务端 60s reap.
- GUI: `eBPF ENGINE: ONLINE/OFFLINE` 判定从只看 XDP 改成看 sockmap+sockops 加载状态. 服务端不挂 XDP 但有 sockmap, 之前永远 OFFLINE 误导用户.

## [v0.4.0-alpha.3] - Fix Dead Tunnel Hangs (2026-06-21)

### Critical Fix
- **修复 mixed inbound 走代理"无响应、5 分钟后超时"的诡异 bug**: 服务端 `first_chunk` 超时 5s 和客户端 `Tunnel::max_age_sec` 120-180s 严重错位 → pool 经常发出"客户端以为活着、服务端已 reap"的死 tunnel → handler send_data 写本地 TCP buffer 假成功 → tunnel_reader 永远等不到响应 → 300s 后 handler timeout "gracefully closed".
- 修复: 服务端 5s → **60s**, 客户端 max_age 120-180s → **30-50s 随机**. 两个值必须严格 max_age < first_chunk_timeout, 保证 pool 永不发死 tunnel.
- DOS 论证: first_chunk path 在 token + Poly1305 握手通过后才进入, 60s 不构成 unauth 资源放大; unauth 时段仍由 5s `read_exact tail` 把关.

### Refactor / Test
- `src/proxy/brutal.rs` 共用 helper, pool.rs 删 ~50 行重复 setsockopt 代码 (P1-1 自审项).
- `set_offset_from_server_time` 补 7 个 unit test, 覆盖正/负 offset / 边界 86400 / 异常值不冲掉已有合法值 (P1-2 自审项, 测试 25→32).

## [v0.4.0-alpha.2] - Server-side Brutal CC Actually Works (2026-06-21)

### Fix
- **服务端 brutal_rate_mbps 真接通**: 之前 `InboundConfig::MirageServer` 漏声明这个字段, install.sh 模板里填的值被 serde 静默忽略 → 服务端 accept 的 socket 从未设过 brutal CC. TCP_CONGESTION 是 per-socket per-direction 机制, 服务端这一侧决定下载速度, 比客户端 outbound 重要得多, 之前等于完全没用上.
- 新增 `src/proxy/brutal.rs` 共用 helper, mirage_server 在 accept 后 apply_brutal, 启动时 INFO `Brutal CC enabled for downloads (server→client): N Mbps`.
- 客户端 pool.rs 的动态速率调节保持不动, 后续可再迁服务端.

### Required Action
- 服务端 `config_server.json` 的 `mirage_server` inbound 块需要加 `"brutal_rate_mbps": N` (N 为期望的下载上限, Mbps). 0 或缺省 = 不启用 brutal.
- 服务端机器需装 `hysteria-tcp-brutal-dkms` 内核模块. 没装会 WARN 一次但不影响代理功能 (退回 BBR/Cubic).

## [v0.4.0-alpha.1] - In-band Time Sync + GUI BPF Tunnels API (2026-06-21)

### ⚠️ Breaking Protocol Change (v0.3 ↔ v0.4 不兼容)
- v0.4 服务端会在 crypto channel 建立后立即下发一帧 TIME_SYNC `[0x01][0x01][8B u64 BE]`. v0.3 客户端会把它误读为数据 → 必然挂. **两端必须同时升级**.
- v0.4 客户端撞 v0.3 服务端: 优雅降级 — 3s 超时后 INFO 一条 "proceeding with local time", 仍能工作.

### Protocol: In-band Time Sync (替代 NTP/HTTP 探测)
- 服务端 handshake 完成后通过加密 channel 主动下发自己的 Unix 时间, 客户端写入全局 `TIME_OFFSET`. 0 外部依赖 + 0 指纹 + 自动校正漂移.
- 删除 `src/time_sync.rs` 的 NTP/HTTP 探测代码 (~100 行) 和 `start_time_sync` 后台协程.
- 删除 `chrono` 依赖 (仅旧 HTTP Date 解析用过).
- Token 容忍 ±60s → **±10s**; ReplayCache 桶 5×60s=300s → **3×10s=30s** 窗口.

### GUI: BPF Active Tunnels API
- 新增 `/api/bpf/tunnels` endpoint, 返回 mirage_rtt_map 所有活跃 cookie 的 RTT/cwnd/重传/数据段数.
- `/api/overview` 新增 `tunnel_count` + `brutal_cc_active` 字段.
- 服务端 `mirage_server::start_server` accept 时把客户端 IP 登记到 BPF mirage_target_ips 白名单, 否则 RTT_CB 永远不写 map.

### Deployment Fixes
- **BPF ELF 对齐**: `aya::include_bytes_aligned!` 替代 `include_bytes!` (修 deployment "error parsing ELF data" 三处全部覆盖).
- **CI 加固**: release.yml pin `ubuntu-22.04` (锁 glibc 2.35); 全 target BPF 编译硬验证 (file/readelf/size + post-build ELF magic).
- **sockmap.c verifier 拒绝修复**: extract_ip 把 ctx 字段访问前置到直线代码, 避免 clang 分支合并优化产出 "dereference of modified ctx ptr" 模式.

### UX / Quality
- 服务端不下载 25MB geo 数据 (按 routing.rules 是否引用 geosite/geoip 条件化).
- TCP brutal CC 默认关闭, 配置了 `brutal_rate_mbps` 才尝试启用 (消除大多数用户启动时的 WARN 噪音).
- SockOps 失败时输出具体步骤 (program lookup → type cast → load → cgroup attach), 不再用 catch-all WARN 掩盖真因.
- 非 root 跑客户端时 RTT WARN 降级 INFO + 提示 setcap.
- README 加入内核 ≥ 5.10 兼容性矩阵 + Alpine 内核配置章节 (CGROUP_BPF 等).
- install.sh 客户端默认 `mixed` inbound + 监听 `0.0.0.0`.
- 测试 5 → 25 (新增 tests/test_fake_ip.rs + tests/test_sniff.rs).

## [v0.2.3-alpha] - XDP DNS Acceleration & Fine-Grained CC (2026-06-17)

### XDP DNS Acceleration (Zero-Copy Bypass)
- **NIC-Level Interception**: XDP program (`dns_xdp.c`) binds directly to the NIC via `xdp_interface` config. It hashes incoming DNS QNAMEs (DJB2) and checks an eBPF LRU Cache map.
- **Microsecond Fake-IP Response**: On cache hit, the XDP program modifies MAC/IP/UDP headers and directly injects the Fake-IP answer into the packet via `bpf_xdp_adjust_tail`, calling `XDP_TX` to return the response instantly without traversing the kernel network stack.
- **Decoupled Cache Sync**: XdpEngine has an independent mutex, isolating DNS cache updates from the EbpfEngine's hot paths (sk_skb / sockops / rtt polling). `EbpfEngine` and `XdpEngine` mutexes have been fully decoupled.
- **Fallback Resilience**: Attaches in `DRV_MODE` (native) and gracefully falls back to `SKB_MODE` (generic) for incompatible interfaces (e.g., virtio_net).

### Congestion Control Enhancements
- **Cumulative Loss Rate Mitigation**: Adjusted initial polling of `data_segs_out` with a `u64::MAX` sentinel value to prevent phantom TCP slow-start spikes from triggering unwarranted congestion avoidance drops.
- **Refined Triggers**: Brutal CC congestion mode now exclusively trips when actual packet loss occurs (`loss_rate > 1%`) or significant queuing delay arises (`RTT > 1.5× base`).
- **Configuration Clarity**: `brutal_rate_bps` has been semantically corrected to `brutal_rate_bytes_per_sec` (inclusive of serde alias for backward compatibility).
- **Automated Reproducibility**: `build.rs` natively tracks and compiles `dns_xdp.c` alongside existing map tools.

## [0.3.0-alpha] - 2026-06-18
### ⚠️ Breaking Changes
- `brutal_rate_bps` 和 `brutal_rate_bytes_per_sec` 字段已**移除**。请改用 `brutal_rate_mbps`（单位：Mbps，例如 8 Mbps 配 `"brutal_rate_mbps": 8`）。v0.2.x 配置文件若包含旧字段名将被静默忽略，这会导致 Brutal CC 失效，请务必手动迁移！

### New Features
- **eBPF Transparent Proxy**: Implemented native `sk_lookup` based transparent proxy for kernels >= 5.9.
- **Protocol Sniffing**: TLS SNI and HTTP Host extraction with 2s timeout from transparently hijacked TCP streams without consuming the byte stream.
- **Transparent Inbound**: Added `Transparent` inbound config type that intercepts traffic targeting `fake-ip` blocks directly from the kernel network stack to the user space router.

## [v0.2.2-alpha] - True BDP + Active Tunnel Rate Adjustment (2026-06-17)

### Network-Reactive Brutal CC v2
- **Active Tunnel Brutal Rate Update**: pool maintains `active_fds: HashSet<i32>` of in-flight Pyreality tunnels. RTT-driven dynamic rate adjustment now safely updates **both idle and active tunnels** via batched `spawn_blocking` setsockopt, completely free of RAII-violating async locks to prevent cross-process FD leaks during task aborts.
- **BDP-Derived Congestion Backoff**: dynamic rate correctly uses `cwnd × MSS / RTT` (true BDP estimation in `bytes/sec`) when congestion is detected (RTT > 1.5× base or retrans delta > 0); smooth multiplicative-increase recovery is utilized otherwise.
- **Retransmission-Triggered Backoff**: `total_retrans` increment between polls now flawlessly triggers congestion mode independently of RTT.

## [v0.2.1-alpha] - Network-Reactive Brutal CC (2026-06-17)

### Network-Reactive Brutal CC
- **BPF SOCK_OPS RTT_CB Real-Time Monitoring**: Per-connection SRTT/cwnd/retrans captured via `BPF_SOCK_OPS_RTT_CB_FLAG` in kernel hot path.
- **Dynamic Brutal Rate Adjustment**: User-configurable `brutal_base_rtt_ms` per outbound; pool's idle tunnels dynamically update their TCP_BRUTAL_PARAMS via spawn_blocking when RTT changes significantly, enabling dynamic BDP calculation.
- **IPv4 & IPv6 Sockops Support**: Target IPs elegantly handled with unified family tags in eBPF memory maps.
- **Cgroup Self-Attach Isolation**: Reads `/proc/self/cgroup` to bind `sockops` exclusively to the proxy's own cgroup, preventing system-wide TCP noise and increasing polling speed.

### Known Limitations (v0.2.1)
- Dynamic Brutal rate update currently only applies to idle/new tunnels in the pool; active tunnels keep their initial rate until reconnect.
- Default `brutal_base_rtt_ms` assumes same-city deployment (fallback 50ms); transcontinental nodes should be configured explicitly.

---

## [v0.1.0] - First Official Release (2026-06-15)

### Core Features
- **Pyreality Protocol Implementation**: Fully implemented the Pyreality AEAD protocol with advanced stealth mechanisms (`hello_auth`, timestamp anti-replay, hidden length tags).
- **WarmPool TCP Connection Pool**: Elastic auto-scaling connection pool with SYN-stagger anti-fingerprinting and per-tunnel jitter (120-180s TTL) to prevent thundering-herd reconnect.

### Router Engine (Routing & Diversion)
- **Advanced Conditional Matching**: Added support for advanced logic modes (`mode: "or"`, `mode: "and"`).
- **L2/L3 Routing**: Support for routing via Source MAC Address (`mac`) and Layer-4 Protocol (`protocol: "tcp" | "udp"`).
- **GeoIP / GeoSite Parsing**: High-performance binary parsing for V2Ray `geosite.dat` and `geoip.dat`.
- **Alias Support**: Geodata domain lists now support custom alias naming conventions (e.g., `"geosite:category-ads-all"`).
- **Dynamic Hot-Reloading**: Uses `notify` backend to detect `config.json` changes and swap routing tables instantly via `ArcSwap` without dropping existing TCP streams.

### Web GUI (Built-in Management Panel)
- **Zero Dependency**: The entire frontend SPA (HTML/CSS/JS) is embedded into the Rust binary at compile time via `include_str!`. No external web server needed.
- **Real-Time Traffic Monitor**: Sub-millisecond latency bandwidth monitoring globally tracking upstream and downstream speeds via custom Tokio `AsyncRead` wrapper (`MonitoredReader`).
- **Log Streaming Interface**: Intercepts `tracing` backend logs and exposes them via REST API to a web-based terminal simulator.
- **Node Selection & Status**: Supports parsing `Selector` and `UrlTest` node groups. Fetches and displays median Ping latency dynamically measured by health-check threads.
- **Direct Router Rule Editor**: Web-based raw JSON editor interacting securely with `config.json`, triggering instantaneous engine reloads upon save.

### CI/CD & Build System
- **GitHub Actions Integration**: Cross-compilation scripts established targeting Linux `x86_64` and `aarch64` architectures using `musl` toolchains for standalone static binaries.
- **Cross-Compilation Scripting**: Includes `build_release.sh` using `cross`.

---
## [v0.1.1] - Security & Stability Patch (2026-06-15)

### Security Fixes
- **Slow-loris DDoS Mitigation**: Moved `GLOBAL_UNAUTH` and `IpSlotGuard` rate-limit checks to the very beginning of the unauthenticated connection handler, and enforced a 5-second `timeout` on the fallback `write_all` to prevent zero-window FD exhaustion attacks.
- **CSRF Privilege Escalation Prevention**: Fortified GUI API endpoints by enforcing strict `X-Requested-With: XMLHttpRequest` checks and strictly rejecting requests missing an `Origin` header (unless explicitly identified as CLI tools), closing a critical CSRF vulnerability vector.
- **Constant-Time HMAC Comparison**: Refactored the `poly1305` tag verification in `verify_session_token` to use bitwise XOR accumulation, eliminating theoretical timing attack vectors.

### Stability & Protocol Fixes
- **Double ServerHello Elimination**: Replaced unconditional caching template playback with "Scheme A" (Pure Forwarding). Unauthenticated connections now purely forward the true Apple `ServerHello` from `camouflage_host`, and only fall back to the `HandshakeCache` template if the true host is unreachable. This prevents TLS state-machine violations (unexpected_message RST) when interacting with strict GFW probes.
- **TCP Half-Close Optimization (P2-2)**: Moved `stream.shutdown().await` in `fetch_real_server_hello` to immediately follow the request transmission. This forces the upstream server to send a FIN packet immediately after its response, completely eliminating the 2-second timeout delay previously observed on LAN/loopback environments.
- **TokenReplayCache Optimization**: Replaced `O(N)` bucket removal with `retain()` using a symmetric 300s timestamp sliding window, successfully patching the "backward clock jump" bug. Added `tracing::warn!` logging when bypassing replay checks under extreme DDoS saturation.
- **Telemetry Direction Semantics**: Standardized `is_initiator` tracking in `CryptoReader`/`CryptoWriter` to accurately account for up/down traffic. Documented double-counting behavior on mixed client/server relay nodes.
- **Resource Management**: Implemented `IpSlotGuard` (RAII) to guarantee unauth connection slot cleanup even on sudden task cancellation.
- **Cleanups**: Renamed misleading `BrutalPool` to `WarmPool`. Removed dead `direct_server` config field. Deleted empty Clash API placeholder module.

### Performance & eBPF
- **SIMD Cryptography**: Migrated from RustCrypto `chacha20poly1305` to `ring` for AVX2/SSSE3 hardware acceleration, yielding 2-3x single-core encryption throughput. Also replaced global `rand` lock with `fastrand` thread-local RNG instances.
- **Zero-Copy eBPF Bypass (opt-in)**: eBPF sockmap stream-verdict routing implemented behind `--features ebpf` (kernel ≥ 5.10, default off). Only optimizes Direct outbound paths; Pyreality (encrypted) main flow unaffected. PERCPU_ARRAY stats map, nested epoll(EPOLLRDHUP) for FIN detection, reproducible BPF compilation via `build.rs`.
- **Brutal Congestion Control**: Complete integration of `tcp_brutal` kernel module API (Hysteria2 style). Supports custom `brutal_rate_bps`, explicitly sets `TCP_BRUTAL_PARAMS` (fallback safe via `TCP_CONGESTION` double-verification), and forces 4MB `SO_SNDBUF` with smart `wmem_max` detection.
- **Connection Pool Anti-Thundering-Herd**: Introduced global randomness (Jitter) uniformly distributed between 0-60s on TCP Tunnel TTL expirations to prevent synchronized tunnel teardowns.

*Engineered by Antigravity AI*
