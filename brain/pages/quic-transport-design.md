---
id: quic-transport-design
title: "QUIC 传输设计 (吸收 queqiao): erasure-aware 自动 CC 解 Brutal 手填痛点, 反识别层不变"
category: decision
status: active
tags: [transport, congestion, fec, quic, performance, queqiao, roadmap]
created: "2026-08-23T12:10:00"
updated: "2026-08-23T12:10:00"
---

## compiled_truth

Mirage roadmap「UDP mux → QUIC Datagram」epic 的设计. 完整文档 `docs/quic-transport-design.md`
(repo 内, 与 queqiao 源码对照). 参考 [[reference-projects-analysis]] (queqiao=高负载金矿).

## 核心营养 (来自 queqiao internal/)
- **ErasureSender (erasure.go) ⭐ 最高价值** = 包在 BBR 外两处修正: (1) 测 erasure floor (降速也不减的
  独立丢包, 取下包络, ≥100 包前透传) 只把超 floor 部分当拥塞喂 BBR; (2) pacing 除以到达率 (1-p) 防
  BBR 环路自我归零. **免手填达到 Brutal 效果** = 解 Mirage 最大痛点 `tuning.brutal_rate_mbps` 人肉估速.
- **选择性 FEC (fec/rate.go)**: Reed-Solomon, 参数全测量 (Class bulk/interactive, block 受 RTT 上界,
  TargetResidual 故意非零留尾给重传). 仅数据报传输适用, TCP 无意义. Mirage 现无 FEC.
- **共享瓶颈模型 (pathmodel)**: 多 lane 共享 delivery/loss/floor, 新 lane seed 不重付 ramp. 拓扑吻合
  Mirage client→server. UDP mux 现共享隧道但不共享 CC 状态, 应共享.
- **重组+共享内存预算 (multipath/reassembly.go)**: overload 只挂一条流不死锁全部. UDP mux HoL 参考.

## 关键决策: 反识别层不变
queqiao **只做传输性能, 混淆委托 sing-box + 用真 TLS PKI, 明确非匿名网络无 DPI 规避**. Mirage 相反:
**反识别 (fake-TLS) 仍用 Mirage 自己的**, 只搬 queqiao 传输性能内核.

## 硬问题: QUIC 指纹
QUIC 自带 TLS1.3 ClientHello 指纹 (uQUIC 存在正为此), 与 Mirage 现 TCP-fake-TLS 不统一. **倾向: 吸收
算法 (erasure CC/FEC/共享模型) 用在 Mirage 自有 UDP 数据报 mux 上, 不必绑 QUIC 线协议** (避免新指纹面).
"QUIC" 只是路线图名字, 真营养是烂链路传输算法, 与是否用 QUIC 线协议正交. 待真机+威胁模型定.

## 分阶段
P0 数据报 mux 骨架 (复用 fake-TLS 密钥+有序重组) → P1 erasure 自动 CC (最大价值, 真机中美验对照
Brutal) → P2 FEC → P3 共享瓶颈 → P4 保护交互流. 每块真机验 (无中美真机无法本地证).

## 真机实测 (2026-08-23, china-us P0)
China 客户端 172.16.0.162 → US VPS 46.38.157.74, P0 二进制 (`--features quic`), QUIC UDP8443 vs TCP8444 同密码 A/B。
- **路径**: RTT 157ms, **27% 丢包, mdev 1ms** (RTT 极稳 → 独立 erasure 非拥塞, 正是 queqiao 模型路径)。
- **UDP8443 China→US 未被封** (go/no-go 过): QUIC 隧道功能通, 出口 IP 正确 = VPS。
- **吞吐 (50MB, target=VPS 自身 http)**: **QUIC ~20-25 KB/s (120s 超时只下 2-3MB) vs TCP 1.6-2.9 MB/s** ——
  **P0 QUIC 比 TCP 慢 ~100 倍**。印证预测: quinn 默认 loss-responsive CC 在 erasure 上环路自我归零
  (= queqiao 表里 BBR 0.39 Mbit/s 现象)。
- **结论**: P0 证"管道通 + UDP 可达", 但也证 **QUIC 无 erasure CC 在真实烂链路上不可用**。
  **erasure-aware CC (P3, queqiao ErasureSender) 是 QUIC 有价值的前提, 非可选**。指纹仿真 (P1) 与
  性能 (P3) 都要做; 若只想要"更快", P3 才是关键, 甚至可先于 P1。

## How to apply
接此 epic 时先读 `docs/quic-transport-design.md`, 直接研读 queqiao `internal/congestion/erasure.go` +
`internal/fec/rate.go`. 与 Mirage 现 TCP-Brutal 并存不替换 (TCP 仍抗封锁主力, UDP 传输是链路好时更快选项).
