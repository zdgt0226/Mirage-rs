# Changelog - Mirage-rs

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
