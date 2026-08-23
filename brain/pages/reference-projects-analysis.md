---
id: reference-projects-analysis
title: "参考项目吸收 (dae/landscape/queqiao): 高负载金矿在 queqiao, 反识别无营养"
category: reference
status: active
tags: [reference, performance, congestion, fec, quic, anti-detection]
created: "2026-08-23T11:48:24"
updated: "2026-08-23T11:48:58"
---

## compiled_truth

/opt/reference 三个 clone 项目分析 (2026-08-23), 找反识别 + 高负载营养。

## 反识别: 无营养
dae/landscape 是 eBPF **路由器** (导流量给 sing-box/xray 做混淆); queqiao 是**性能传输** (认证,
非 fake-TLS DPI 规避)。**Mirage 的 fake-TLS + REALITY式 + ClientHello 仿真在反识别轴上已领先这三个**。
要反识别参考得看 xray/sing-box/REALITY, 不是这三个。别再从这三个找反识别灵感。

## 高负载: 几乎全在 queqiao (bojieli/李博杰)
正中 Mirage 中美高丢包用例:
- **ErasureSender 自动定速 CC** ⭐ (internal/congestion/erasure.go): China-US 实测 42% 独立丢包,
  loss-responsive CC 全崩 (Reno 0.13 / BBR 0.39 Mbit/s), 只有 Brutal 拿得到 (13.89) 但要人手填速率。
  ErasureSender = 自动版: ①测 erasure floor (降速不减的丢包) 只把**超出 floor 的部分**当拥塞喂 BBR;
  ②pacing 除以到达率 (1-p) 修 BBR "送速=达速估计" 在丢包信道上走到零的反馈崩溃。→ 不用手填自动
  收敛瓶颈。**解决 Mirage Brutal 要手填 brutal_rate_mbps 的最大痛点**。
- **FEC (Reed-Solomon)** (internal/fec/gf.go 伽罗华域 + window.go/rate.go): 长 RTT 丢包无需往返恢复。
  Mirage 无 FEC。
- **共享瓶颈 CC 模型**: 同 client→gateway 的流共享 delivery/loss/RTT/pacing。Mirage mux 共享隧道
  但不共享 CC 状态。
- **多路复用重组 + 共享内存预算** (internal/multipath/reassembly.go): 非阻塞, overload 只挂一条流
  不死锁。Mirage UDP mux 有 HoL。
⚠️ 这些是**用户态数据报传输 (QUIC) 的东西** —— Mirage 现 fake-TLS-over-TCP + 内核 Brutal 塞不进。
它们正是 Mirage roadmap **「UDP mux→QUIC Datagram」epic 的蓝图** (且为烂链路调好)。见 [[quic-transport-design]]。

## landscape (ThisSeanZhang, Rust+eBPF, 最像的兄弟)
- **per-flow(设备组) 独立 DNS + eBPF map 引导**: 验证 Mirage 刚做的 device profiles 方向, 且提示
  **按设备 DNS** (Mirage profile 现缺 DNS 维度, roadmap 已标 None)。DNS→eBPF map→XDP/TC 线速引导。
- 细粒度 NAT (BT/PT full-cone 例外); Docker 容器重定向 (TProxy 扩展)。

## dae (daeuniverse, Go, eBPF)
Mirage 已借 splice(2)。dae "Real Direct" 内核旁路 ≈ Mirage tc_divert direct_cidr 已做, 对齐。
小点: 本机 UDP 服务端口 must_direct 路由正确性 (Mirage is_direct_dst 硬编码私网兜底)。

## 最大可动手洞见
queqiao ≈ Mirage「UDP mux→QUIC」epic 的参考实现, 解决 Mirage 最大痛点 (Brutal 手填速率→自动)。
做 QUIC 传输直接研读/移植 erasure.go + fec/。


## timeline

- time: 2026-08-23T11:48:24
  kind: decision
  summary: "Created this page: 参考项目吸收 (dae/landscape/queqiao): 高负载金矿在 queqiao, 反识别无营养"
  source: "/opt/reference 三项目源码分析 2026-08-23"
  affects: [reference-projects-analysis]

- time: 2026-08-23T11:48:58
  kind: decision
  summary: "queqiao=高负载金矿(ErasureSender自动定速CC+FEC, 中美烂链路), 是 Mirage UDP mux→QUIC epic 蓝图; landscape 验证 device profiles+提示按设备DNS; dae 已借splice; 反识别三者无营养(Mirage fake-TLS已领先)"
  source: brain update-truth
  affects: [reference-projects-analysis]
