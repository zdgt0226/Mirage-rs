---
id: handshake-template-completeness
title: "缓存的 camouflage 模板必须含齐 0x16+0x14+0x17 三型"
category: decision
status: active
tags: [handshake, camouflage, tls, cache]
created: "2026-08-13T23:52:16"
updated: "2026-08-13T23:52:39"
---

## compiled_truth

## 不变量

服务端 `handshake_cache` 缓存/回放给客户端的 camouflage ServerHello 模板, **必须含齐三种 TLS
content-type**: 0x16 (ServerHello/Handshake) + 0x14 (ChangeCipherSpec, TLS1.3 中间盒兼容模式恒发) +
0x17 (加密 ApplicationData)。且帧无截断、无尾部残字节。

## 为什么

客户端 `proxy::pool::read_server_handshake` 循环读 TLS 记录, **必须集齐 0x16+0x14+0x17 三型才返回、
才发 64B fake Client Finished tail**。服务端若回放缺型的残模板, 客户端永等不到 → 不发 tail → 服务端
`read_exact tail timed out`, 握手死。门禁只是让 fetch 端**和客户端要求一样严**, 不新增误杀。

## 曾踩的坑 (commit e309e7e)

`fetch_real_server_hello` 曾**固定只多读 2 帧**, 遇拆帧站/TLS1.2 站缓存出残模板。完整服务端 ↔ 客户端
(含轻量模式, 非轻量特有) 偶发握手超时。沙箱无外网时 fetch 全失败走 `fallback_server_hello` (恒含齐),
故本地测试全绿、长期未复现 —— 真机日志 `read_exact tail timed out` 才暴露。

修法: 纯函数 `template_is_complete` 校验三型齐; fetch 读到齐才停 (封顶 8 帧) + 完整性门禁, 残模板一律
`Err` 回落 fallback, 绝不毒化全局 cache。

关联: [[camouflage-forward-on-auth-fail]] [[no-plaintext-handshake-control]]


## timeline

- time: 2026-08-13T23:52:16
  kind: decision
  summary: "Created this page: 缓存的 camouflage 模板必须含齐 0x16+0x14+0x17 三型"
  source: commit e309e7e
  affects: [handshake-template-completeness]

- time: 2026-08-13T23:52:39
  kind: decision
  summary: "服务端只缓存三型齐的模板, 匹配客户端 tail-gating; 残模板回落 fallback"
  source: brain update-truth
  affects: [handshake-template-completeness]
