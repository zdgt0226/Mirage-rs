---
slug: background
title: Project background
role: project background
updated: "2026-07-21T09:27:00"
---

# Project background

## 这是什么

Mirage-rs 是一个 **Linux 上的抗审查代理引擎**,用 Rust + Tokio 从早期 Python POC(Shadow-TLS + Reality 血统)全量重写,
并在其上长出**零配置 eBPF 透明网关**能力。同一个二进制按 config 扮演两种角色:

- **服务端**:跑在墙外 VPS,对外表现为一个普通 HTTPS 站点;
- **客户端 / 透明网关**:跑在本机或家用网关,把 LAN 流量透明劫持进隧道。

轻量模式(`lite-server`/`lite-client`)提供"只要能翻墙"的最短路径;服务端还可接 Shadowsocks 上游作中转站。

## 要解决的问题

1. **被动识别**:TLS 指纹、流量时序、SNI/IP 归属不一致等特征会让代理在流量里现形。
2. **主动探测**:审查方直连服务端端口试探,能否与真站不可区分。
3. **部署摩擦**:传统方案要求逐设备配代理、或大量 iptables 规则。目标是 LAN 设备**零配置**接入(改网关+DNS 即可)。

## 目标用户与项目意图(2026-07-21 用户确认)

- **目标用户 = 自建跨境线路的个人/小团队**:有一台墙外 VPS,家里有一台能当网关的 Linux 机器。文档与交互全中文。
- **意图 = 自用起家, 但希望做成"有人用"的开源项目**:不追求商业化, 但**在意被真实用户采用、接受反馈迭代**。
  → 这直接抬高了三件事的权重: **文档质量 / 易用性(install.sh 交互、check/import 等工具)/ 发布质量(版本一致、
    升级须知、CHANGELOG)**。近期大量精力投在轻量模式、安装向导、配置校验工具链上, 正是这个意图的体现。
- **非目标(仍然成立)**: 不做通用受众的 Clash/sing-box 替代品 —— 定位是"自建者的顺手工具", 而非面向不懂技术的大众。

## 明确的非目标

- **不做 Clash API 兼容** —— 走自有 API 路径(`src/api/mod.rs:14` 明确声明)。见 [[no-clash-api]]。
- **不用 DoH/DoT 作为抗审查手段** —— 抗审查靠 fake-IP + 远端解析,而非加密到公共解析器。见 [[no-doh-dot]]。
- **不做线速转发/eBPF 内 NAT** —— eBPF 只做拦截,不接管数据面。见 [[ebpf-scope-narrowed]]。
- **不把 DNS 解析出的真实 IP 灌进 eBPF map 做分流**(Landscape 的核心做法)—— 那要求信任本地 DNS,与抗审查前提冲突。见 [[fakeip-remote-resolution]]。
