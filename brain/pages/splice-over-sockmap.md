---
id: splice-over-sockmap
title: "直连零拷贝改用 splice(2), 弃 sockmap sk_skb"
category: decision
status: active
created: "2026-07-20T11:43:26"
updated: "2026-07-20T12:14:27"
---

## compiled_truth

**决定**(v0.4.5-alpha.3, `a6535e1`):直连出站的零拷贝从 **sockmap `sk_skb`** 改为 **`splice(2)` + pipe**。
这是一次**反转**——早期架构叙述里 sockmap 是直连快路径的核心。

**理由**:sockmap 路径在目标部署内核上不可靠(`register_listener` 把 `TCP_LISTEN` 塞 SOCKMAP 报 `EINVAL`,
alpha.28 起降级为非致命)。`splice(2)` 在用户态即可完成内核内数据搬运,无 eBPF 依赖、跨内核稳定。

**影响面**:
- `ebpf-src/sockmap.c`/`.elf` 成为历史遗留(`extract_ip` 等已是死代码)。
- 池化管道由 `src/proxy/splice.rs` 管理;`PipeGuard` **没有** `impl Drop` —— 成功走 `finish()` 归池,
  出错/取消走默认 drop 关 fd 销毁管道,**脏管道永不回池**。曾有外部审计凭空捏造一段 `Drop` impl 声称
  "串包泄漏",系误报,见 [[external-audit-verification]]。
- 凡看到旧文档/注释说"直连走 sockmap",都应以本页为准。


## timeline

- time: 2026-07-20T11:43:26
  kind: decision
  summary: "Created this page: 直连零拷贝改用 splice(2), 弃 sockmap sk_skb"
  source: "git a6535e1 (alpha.3)"
  affects: [splice-over-sockmap]

- time: 2026-07-20T12:14:27
  kind: decision
  summary: "捕获 alpha.3 的数据面反转"
  source: git a6535e1
  affects: [splice-over-sockmap]
