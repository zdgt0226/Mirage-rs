---
id: server-dns-over-tcp
title: "服务端可选 DNS-over-TCP 解析 (tuning.dns_tcp_resolver)"
category: decision
status: active
tags: [dns, resolver, tcp, vps, server]
created: "2026-07-27T01:27:55"
updated: "2026-07-27T01:27:55"
---

## compiled_truth

## 问题

服务端解析代理目标域名走 resolver.rs 的 tokio lookup_host = 系统 getaddrinfo (glibc 默认
UDP:53)。出向 **UDP 被封的 VPS** 做服务端时, getaddrinfo 查不了 DNS → 代理域名全解析失败。
(fake-IP 只免了客户端那次 DNS, 服务端建连仍要解析域名。)

## 决定

`tuning.dns_tcp_resolver: "1.1.1.1"` (可选)。设了则**本进程所有域名解析走它、经 TCP:53 查**,
不再用 getaddrinfo。地址无端口默认 53 (复用 [[dns-direct-upstream-tcp]] 的 parse_dns_upstream)。

## 实现

- resolver.rs: 全局 `TCP_RESOLVER: OnceLock<SocketAddr>` (启动 set 一次, 不热重载);
  resolve_cached 分派 —— 有则 resolve_via_tcp, 否则 lookup_host。缓存/信号量/IPv4优先不变。
- 自实现轻量 DNS-over-TCP (无 hickory 依赖): build_dns_query (RD=1 单问题) + parse_answer_ips
  (walk answer 段取 A/AAAA rdata) + skip_name (压缩指针只跳不追, 无环)。并发查 A+AAAA 合并。
- lib.rs start_proxy 读 tuning.dns_tcp_resolver → set_tcp_resolver。
- 验证: 对真实 1.1.1.1 端到端 (example.com→A); 单测 查询构造/A+AAAA解析/截断容错。

零改代码替代 (文档提示): VPS 上 `options use-vc` 强制 glibc 走 TCP。

关联 [[dns-direct-upstream-tcp]] (同一 parse_dns_upstream + tcp_query 理念)、[[chain-proxy-roadmap]]。


## timeline

- time: 2026-07-27T01:27:55
  kind: decision
  summary: "Created this page: 服务端可选 DNS-over-TCP 解析 (tuning.dns_tcp_resolver)"
  source: feat/server-tcp-resolver
  affects: [server-dns-over-tcp]

- time: 2026-07-27T01:27:55
  kind: decision
  summary: "tuning.dns_tcp_resolver 设了则全进程域名解析走 DNS-over-TCP(自实现, 无依赖), 解决出向UDP被封的VPS做服务端时 getaddrinfo(UDP) 解析不了代理目标域名"
  source: brain update-truth
  affects: [server-dns-over-tcp]
