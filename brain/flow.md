---
slug: flow
title: Key flows
role: key flows
updated: "2026-07-20T11:29:20"
---

# Key flows

一条典型请求:LAN 客户端访问被代理域名(透明网关部署形态)。

```mermaid
sequenceDiagram
    participant C as LAN 客户端
    participant G as 网关 (Mirage-rs)
    participant K as 网关内核 (eBPF)
    participant S as 服务端 (VPS)
    participant T as 目标站点

    C->>G: DNS 查询 google.com
    G-->>C: 返回 fake-IP 198.18.x.x (稳定 TTL 300s)
    Note over G: fake_ip.rs 记 fake-IP → 域名 映射
    C->>K: TCP SYN → 198.18.x.x:443 (转发流量)
    Note over K: tc_divert ingress:<br/>命中 direct_cidr? → TC_ACT_OK 直连<br/>否则 sk_lookup 透明 listener + sk_assign + fwmark
    K->>G: 经 ip rule fwmark→local 表投递给透明 listener
    Note over G: local_addr() 取回原始 fake-IP<br/>反查域名 → router 判定 outbound
    alt Direct 出站
        G->>T: splice(2) 零拷贝直连
    else Mirage 出站
        G->>S: 从 WarmPool 取预建隧道 (已完成 TLS 伪装握手+认证)
        Note over G,S: 首帧发 target_header, 之后 ChaCha20-Poly1305 分帧
        S->>T: 服务端**远程解析域名**并连接
        T-->>S: 数据
        S-->>G: 加密回程
    end
    G-->>C: 以原始 fake-IP 为源回包
```

## 要点

- **fake-IP 的意义**:客户端永远拿不到真实 IP,域名随隧道送到服务端**远程解析** —— 不信任本地/墙内 DNS。见 [[fakeip-remote-resolution]]。
- **首 SYN 与已建流走不同分支**:只对首 SYN `sk_assign`,已建流仅打 fwmark。这是踩出来的,见 [[syn-only-sk-assign]]。
- **认证失败不报错**:服务端把连接**转发到真实伪装站**,探针看到的是真站响应。见 [[camouflage-forward-on-auth-fail]]。
- **UDP(QUIC/游戏)**同样经 `tc_divert` → `transparent_udp`,per-flow 决策,Mirage 腿封帧走隧道。
