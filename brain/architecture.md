---
slug: architecture
title: System architecture
role: system architecture
updated: "2026-07-20T11:28:54"
---

# System architecture

Mirage-rs 是**单二进制、双角色**(客户端/网关 与 服务端由同一 binary + config 决定)的抗审查代理引擎。
数据面在用户态(Tokio 异步),eBPF 只负责**流量拦截与内核旁路**,不做线速转发。

## 分层

```mermaid
graph TB
    subgraph K["内核 (eBPF, feature = ebpf)"]
        TC["tc_divert.c<br/>tc clsact ingress<br/>sk_lookup+sk_assign 抓裸-IP<br/>LPM direct_cidr 直连放行<br/>内联 MSS clamp"]
        CG["cgroup_connect.c<br/>connect4 重定向本机出向"]
        XDP["dns_xdp.c<br/>XDP 极速 DNS 应答"]
    end
    subgraph U["用户态 (Rust + Tokio)"]
        IN["入站: mixed/socks5 · transparent(TCP) · transparent_udp · dns"]
        RT["router: geo.rs (geosite/geoip .dat) + 规则 → outbound tag"]
        OUT["出站: Direct (splice(2) 零拷贝) · Mirage (加密隧道)"]
        POOL["pool.rs WarmPool 预建隧道<br/>+ net_monitor 链路自愈"]
    end
    subgraph S["服务端角色 (mirage_server/)"]
        HS["handshake 认证 → 通过=隧道 / 失败=camouflage 转发真站"]
        RL["tcp_relay · udp_relay"]
    end
    TC --> IN
    CG --> IN
    IN --> RT --> OUT
    OUT --> POOL -.加密隧道.-> HS --> RL
```

## 模块边界

| 目录 | 职责 |
|---|---|
| `ebpf-src/*.c` + `src/ebpf/` | eBPF 程序与其 Rust 控制面(加载/attach/灌 map/热重载) |
| `src/proxy/` | 入站(mixed/socks5/transparent/transparent_udp)、出站、隧道、连接池、splice |
| `src/proxy/mirage_server/` | 服务端角色:握手认证、伪装转发、TCP/UDP 中继 |
| `src/crypto/` | `tls_raw`(ClientHello 字节级仿真)、`aead`(ChaCha20-Poly1305 分帧)、`hello_auth`(令牌) |
| `src/dns/` | DNS 服务、fake-IP 分配与反查 |
| `src/router/` | geo 分流(v2ray geosite/geoip `.dat` 解析) |
| `src/api/` | Axum Web 看板 + REST |

## 关键不变式

- eBPF 职责**刻意收窄**:只做拦截/重定向,数据搬运在用户态。理由见 [[ebpf-scope-narrowed]]。
- 直连快路径走 `splice(2)`,不经用户态缓冲。见 [[splice-over-sockmap]]。
- 透明路径当前 **IPv4-only**,靠 DNS 层 AAAA 抑制避免泄漏。见 [[ipv6-v4only-tradeoff]]。
