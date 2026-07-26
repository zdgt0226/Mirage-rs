---
id: dns-direct-upstream-tcp
title: "DNS 直连上游: 地址默认端口 53 + 可选 TCP 协议"
category: decision
status: active
tags: [dns, upstream, tcp, config]
created: "2026-07-26T14:35:44"
updated: "2026-07-26T14:35:45"
---

## compiled_truth

## 决定

两处改进 direct/cn DNS 上游配置 (advanced_dns.resolvers):

1. **地址默认端口 53**: 之前 direct 上游用 `address.parse::<SocketAddr>()`, 必须带端口
   (`223.5.5.5:53`); 而 remote 走 split(':') 可省端口 —— 用户觉得突兀。改为 direct 也默认
   53: 新纯函数 `config::parse_dns_upstream(s)` 先试 SocketAddr, 再试裸 IpAddr + 53。
   裸 IPv6 支持 (`2001:...::8888` → :53), 带端口须方括号。
2. **每上游 protocol (udp 默认 / tcp)**: DnsResolver 加 `protocol: DnsProtocol` 字段。
   cached_cn_dns 类型改 `Vec<(SocketAddr, DnsProtocol)>` 携带协议。

## 传输分派 (dns/server.rs::direct_query)

- UDP 上游 → udp_query (并行发全部 + 重传, 已有)。
- TCP 上游 → tcp_query (顺序 failover, TCP 无丢包问题不需并行重传) → tcp_query_one
  (connect + [2B len][报文] RFC 7766 + tx_id/QR 校验, DNS_TCP_TIMEOUT=3s)。
- 混配 udp+tcp (少见) → tokio::select! 并发竞速, 先返回 Some 者胜; 先完成者 None 则
  await 另一个 (pin 复用不重跑)。
- **remote (境外) 上游不受 protocol 影响**: 恒经隧道 tcp_over_tunnel 查。

## 动机

UDP/53 被封或投毒的网络给 direct 上游加 protocol:tcp 走 TCP 解析。属抗审查 DNS 的补充手段
(与 fake-IP 远端解析并存)。

单测: parse_dns_upstream (端口默认/IPv6/非法) · tcp_query_one (假 TCP 上游) · failover ·
direct_query 协议分派 (纯 TCP / 混配竞速 / 空)。install.sh 默认答案去 :53。

关联 [[fakeip-remote-resolution]] (远端解析抗污染)、[[dns-ip-strategy]]、[[dns-static-resolution]]。


## timeline

- time: 2026-07-26T14:35:44
  kind: decision
  summary: "Created this page: DNS 直连上游: 地址默认端口 53 + 可选 TCP 协议"
  source: "feat/dns-hijack 后续 main"
  affects: [dns-direct-upstream-tcp]

- time: 2026-07-26T14:35:45
  kind: decision
  summary: "direct/cn 上游地址无端口默认53(与remote统一); 每上游 protocol udp/tcp, tcp 走 RFC7766 顺序failover, 混配并发竞速; remote 恒隧道TCP不受影响"
  source: brain update-truth
  affects: [dns-direct-upstream-tcp]
