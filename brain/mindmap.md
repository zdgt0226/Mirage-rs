---
slug: mindmap
title: Feature mindmap
role: feature mindmap
updated: "2026-07-20T11:29:20"
---

# Feature mindmap

```mermaid
mindmap
  root((Mirage-rs))
    透明网关
      tc_divert 抓裸-IP 转发流量
      cgroup/connect4 本机出向
      transparent TCP / transparent_udp
      fake-IP DNS
      MSS clamp
    抗审查/抗识别
      TLS ClientHello 字节级仿真
        Chromium 150
        Firefox 152
        OkHttp/Conscrypt
      握手令牌认证
      auth 失败转发真站 camouflage
      SNI/IP 同 ASN 一致性
      JA4 对照 harness
    传输与性能
      Direct splice(2) 零拷贝
      WarmPool 预建隧道
      TCP Brutal 拥塞控制
      链路自愈 netlink
    分流
      geosite/geoip .dat
      direct_cidr 灌 LPM trie
      规则热重载
    运维
      install.sh 交互向导
      systemd/OpenRC/SysV
      Neon Dashboard + REST
      日志滚动 gzip
```
