---
slug: background
title: Project background
role: project background
updated: "2026-07-20T11:31:44"
---

# Project background

## 这是什么

Mirage-rs 是一个 **Linux 上的抗审查代理引擎**,用 Rust + Tokio 从早期 Python POC(Shadow-TLS + Reality 血统)全量重写,
并在其上长出**零配置 eBPF 透明网关**能力。同一个二进制按 config 扮演两种角色:

- **服务端**:跑在墙外 VPS,对外表现为一个普通 HTTPS 站点;
- **客户端 / 透明网关**:跑在本机或家用网关,把 LAN 流量透明劫持进隧道。

## 要解决的问题

1. **被动识别**:TLS 指纹、流量时序、SNI/IP 归属不一致等特征会让代理在流量里现形。
2. **主动探测**:审查方直连服务端端口试探,能否与真站不可区分。
3. **部署摩擦**:传统方案要求逐设备配代理、或大量 iptables 规则。目标是 LAN 设备**零配置**接入(改网关+DNS 即可)。

## 目标用户

自建跨境线路的个人/小团队 —— 有一台墙外 VPS,家里有一台能当网关的 Linux 机器。文档与交互全中文。

## 明确的非目标

- **不做 Clash API 兼容** —— 走自有 API 路径(`src/api/mod.rs:14` 明确声明)。见 [[no-clash-api]]。
- **不用 DoH/DoT 作为抗审查手段** —— 抗审查靠 fake-IP + 远端解析,而非加密到公共解析器。见 [[no-doh-dot]]。
- **不做线速转发/eBPF 内 NAT** —— eBPF 只做拦截,不接管数据面。见 [[ebpf-scope-narrowed]]。
- **不把 DNS 解析出的真实 IP 灌进 eBPF map 做分流**(Landscape 的核心做法)—— 那要求信任本地 DNS,与抗审查前提冲突。见 [[fakeip-remote-resolution]]。

## ⚠️ 待用户确认(低置信)

以下从 README/代码推断,**未经用户确认**:
- "目标用户"一节属推断(由 install.sh 的部署形态与中文文档反推),可能过窄或过宽。
- 项目是否有**非个人使用**的意图(公开发行/多用户/商业化)未知 —— 现有证据只能看出是自用向的开源项目。
