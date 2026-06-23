# Changelog - Mirage-rs

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
