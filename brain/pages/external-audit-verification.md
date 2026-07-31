---
id: external-audit-verification
title: "外部审计逐条核实: 术语专业但真伪参半"
category: concept
status: active
created: "2026-07-20T11:43:27"
updated: "2026-08-01T02:11:04"
---

## compiled_truth

## compiled_truth

**观察**:本项目收到过多轮外部代码审计(12 项 / 7 项 / 5 项 / 若干单条),共同特征是
**术语专业、真伪参半、severity 系统性夸大**。稳定命中率约**一半或更低**。

**已证伪的典型**(勿再当 bug 修):
- `splice.rs` "PipeGuard Drop 串包泄漏" —— 引用了一段**根本不存在**的 `Drop` impl。审计会**凭空捏造代码**。
- "探针被转发后能看到目标云厂商 TCP 指纹" —— 转发在应用层,TCP 终结在本机栈。
- "重放缓存可被无令牌 DDoS" —— Poly1305 tag 校验在缓存插入**之前**,前提不成立。
- "ALPN=h2 但首个 app-data 是 1300B 大包" —— 实际两方向首条记录都是小控制记录
  (TCP 先发 `target_header` ~39B;UDP 先发 `[0x00]` ~23B;下行先发 TIME_SYNC ~32B)。
- `rules.rs` "curl UA 豁免 CSRF" —— `User-Agent` 是 Fetch 禁止头,浏览器 JS 无法伪造。

**但核实过程本身有价值**:核第二轮审计时**顺带挖出**真缺陷 —— `dns_xdp` 在内核 ≥6.1 上
加载一直被拒(即用户网关上 XDP 极速 DNS 从未生效),比审计自己列的任何一条都实在。

**方法**:
1. **逐条对着 HEAD 的真实文件核实**,不看措辞看代码;
2. 区分"事实对"与"严重性对"—— 常见形态是事实成立但危害被放大一个量级;
3. 真修的记进 brain,证伪的**也记**(否则下轮审计会再来一遍);
4. 别被 P0 标签带节奏。

## 已核实的审计轮次实例

### 2026-07-23 内核专家模型 (四条, 规律再次印证)

| # | 审计声称 | 核实判定 | 处置 |
|---|---|---|---|
| 1 | DNS DJB2 忽略点分隔符 → 域名碰撞 | ✅ **真 P1** (foo.bar.com == foobar.com 哈希) | 已修: 长度字节入哈希 + 跨端护栏 + 消灭第三份哈希拷贝 |
| 2 | cgroup 自连 "无限死循环 FD 耗尽" | ⚠️ 竞态真, **"无限循环"夸大** (实为一次注定失败的自连, 不递归; 仅 proxy_local) | 已修: origdst 落空即丢弃, 不 fallback 监听端口 |
| 3 | LPM 非原子 "流量瞬断", 建议 ARRAY_OF_MAPS 双缓冲 | ⚠️ 技术对, **severity 夸大**; 建议**不可照搬** (aya 0.13 无 inner-map 高层 API) | 已修但**换方案**: 先加后删 (map=旧∪新超集, 消除漏判), 非双缓冲 |
| 4 | IPv6 硬编码拦截逃逸 | ⚠️ 事实对, 是**已知 IPv4-only 取舍** (见 [[ipv6-v4only-tradeoff]]) | 归 IPv6 全栈 roadmap, 不单独修 |

### 两条可复用教训 (本轮新增)

1. **建议不能照搬 —— 先验依赖能力**: #3 的 ARRAY_OF_MAPS 双缓冲在 aya 0.13 上只有只读
   info 枚举、无操作 API, 硬做要裸 syscall + 换 map 类型, 对 P3 性价比极差。审计给的方案
   往往是"教科书正确"但不匹配本项目栈 —— 落地前先 `find ~/.cargo/registry` 验 API 是否存在。
2. **修复可能暴露隐藏的重复代码**: #1 修哈希时端到端验证器 timeout, 根因是哈希逻辑有
   **三份拷贝** (mod.rs / dns_xdp.c / verify_dns_xdp.rs), 第三份"为了独立而复制"没跟上。
   教训: "复制以求独立"的代码恰恰在需要同步时不同步; 改共享逻辑后, 全量跑端到端验证器
   (不只单测) 才能抓出漏改的拷贝。


## timeline

- time: 2026-07-20T11:43:27
  kind: decision
  summary: "Created this page: 外部审计逐条核实: 术语专业但真伪参半"
  source: "多轮审计核实记录"
  affects: [external-audit-verification]

- time: 2026-07-20T12:20:56
  kind: decision
  summary: "沉淀多轮外部审计的核实方法论"
  source: "多轮审计核实记录"
  affects: [external-audit-verification]

- time: 2026-07-24T00:52:42
  kind: evidence
  summary: "2026-07-23 内核专家模型审计四条: 1真P1(DNS哈希碰撞已修) + 3'技术对但夸大/已知'; 建议不能照搬(#3双缓冲在aya上不划算, 改先加后删)"
  source: "2026-07-23 审计"
  affects: [external-audit-verification]

- time: 2026-07-24T00:55:30
  kind: decision
  summary: "补 2026-07-23 四条审计实例 + 两条可复用教训 (建议先验依赖能力/修复暴露重复代码)"
  source: "2026-07-23 审计"
  affects: [external-audit-verification]

- time: 2026-07-28T09:14:51
  kind: evidence
  summary: "Gemini 4 条通用警告 (CO-RE/日志阻塞/GeoSite OOM/重载黑洞) 逐条核实: 0 真 bug, 全被现有设计覆盖或机制误判"
  source: "ebpf-src/tc_divert.c, src/monitor.rs, src/router/geo.rs, src/config_watcher.rs"
  affects: [external-audit-verification]

- time: 2026-08-01T02:11:04
  kind: evidence
  summary: "第二轮外部审查 (8 条 P0/P1/P2) 逐条核验结论 (2026-07-31)。修复 5 项 (commit d600b57 + fb628d4): ②DNS resolver tcp://|udp:// 前缀 —— 模板照抄会坏 (remote 分支 split(':') 拆成 host=tcp 查错目标, direct/cn 整条跳过回落公共 DNS), 加 strip_dns_scheme 两分支统一; ④OutboundManager::new 未解析/循环组改返回 Result 非 panic (仅启动路径可达, 热重载保留旧 outbounds); ⑤?token= 限根路径 /, /api/* 只认 header/cookie 防进 URL 日志; ⑥build.rs eBPF 编译 gate 到 feature=ebpf && target_os=linux; ③CSRF 方案 B —— 删 handler 里 is_xhr||UA=curl||Origin 启发式, 重构进 auth_mw 按认证方式分流 (Bearer header 抗 CSRF 免检, Cookie/无 token+变更方法要求同源 Origin/Referer 匹配 Host, GET 不查)。判非问题 2 项: ①Linux-only 模块无 cfg (transparent/splice/transparent_net + signal::unix) —— 代码属实但前提 moot: README/Cargo 无跨平台承诺, crate 本就 Linux-only (aya/eBPF/splice/IP_TRANSPARENT/netlink/nix), 只给 4 模块加 cfg 换不来可移植性, 是另一大 epic; ⑦mojibake 乱码 = 假, 扫过全部 src/templates/build.rs 全合法 UTF-8 零替换字符, 是审查者 Windows 环境按非 UTF-8 码页读 (路径 D:/Projects)。教训: 审查结论必对源码核验, 别照单全收 (③ 说'带 Bearer 被拒'其实无 Origin 时放行; ④说'长跑进程被杀'其实仅启动路径)。"
  source: "8 条审查逐条核验 + 源码 + full cargo test 254 lib 全绿"
  affects: [src/config_watcher.rs, src/proxy/outbound.rs, src/api/mod.rs, build.rs]
