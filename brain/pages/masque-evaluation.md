---
id: masque-evaluation
title: "MASQUE (Cloudflare) 评估: 不替 WG, fronting 不适自建, QUIC-datagram 帧可借鉴"
category: decision
status: active
tags: [protocol, anti-censorship, quic, masque, wireguard]
created: "2026-08-11T22:07:30"
updated: "2026-08-11T22:31:56"
---

## compiled_truth

用户 2026-08-05 提问: Cloudflare 的 MASQUE 能否作 WireGuard 的补充。评估结论。

**MASQUE = VPN over HTTP/3 (QUIC)**, IETF 标准。CONNECT-UDP (RFC 9298, 代理 UDP) + CONNECT-IP (RFC 9484, 代理裸 IP 包=WG 对位)。跑 H3 上, 对审查者像普通 HTTPS/H3。Cloudflare WARP 即此。

## 两种"补充"解读与判断

**(a) 当干净设备入站, 替/补 WG → 不划算。** MASQUE 客户端稀有(基本只 WARP, Cloudflare 专属), WG 是 OS 原生人人都有。干净设备用法价值=设备装通用 VPN 零翻墙痕迹, WG 普及性碾压。留 WG。见 [[chain-proxy-roadmap]]。

**(b) 当 Mirage 传输层(替 fake-TLS-over-TCP)→ 命门在 CDN fronting。**

## 核心判断: MASQUE 抗审查力来自"骑 Cloudflare"非协议本身

- 真强场景=域名前置: 流量混进 Cloudflare IP 池, 封它=封半个互联网。
- 但 **Mirage 定位是自建个人 VPS**: 自建 MASQUE = QUIC 打到自己 VPS 随机 IP, **无 fronting 优势**, 且"QUIC 到陌生 IP"本身是指纹(GFW 对非白名单 QUIC/443 早有节流/丢包, WARP 在墙内时好时坏即此原因)。
- 骑 Cloudflare 又违背"流量只你看得见"(CF 解密看得见出海流量)+ 要付费/信任 CF 不封你 → 换威胁与信任模型。

## 可吸收的那块

MASQUE 的 CONNECT-UDP/IP + QUIC datagram 帧格式 = roadmap "UDP mux → QUIC Datagram" 想要的: QUIC 不可靠数据报解跨流队头阻塞(mux 终局)+ 标准化线格式。即 MASQUE 解决的传输问题(UDP 原生无 HoL)= 我们 QUIC-datagram 候选; 但其抗审查卖点(fronting)对自建定位不适用。

## 结论

1. 干净设备入站: 留 WG, MASQUE 不补。
2. 传输层替换: 只有愿意真骑 Cloudflare(换威胁/信任模型+付费)才有意义; 自建则相对 Mirage 无增益+多个 QUIC 指纹。
3. 真正可吸收: 把 QUIC-datagram roadmap 做成兼容 MASQUE CONNECT-UDP 帧, 拿无-HoL 传输+标准格式, 不绑 Cloudflare。
4. 待深聊(可选): "Mirage 骑 Cloudflare 前置"作独立路线(不同威胁模型)。

**How to apply**: 做 UDP mux→QUIC Datagram(见 [[udp-capacity-findings]])时参考 MASQUE CONNECT-UDP 帧式; 别为抗审查引 MASQUE/H3(自建无 fronting 增益)。


## timeline

- time: 2026-08-11T22:07:30
  kind: decision
  summary: "Created this page: MASQUE (Cloudflare) 评估: 不替 WG, fronting 不适自建, QUIC-datagram 帧可借鉴"
  source: "用户 2026-08-05 提问 MASQUE 能否补充 WG"
  affects: [masque-evaluation]

- time: 2026-08-11T22:09:40
  kind: decision
  summary: "MASQUE 评估: 干净设备入站不替 WG(普及性输); 传输层替换只在真骑 Cloudflare 时有意义(违背自建定位); QUIC-datagram 帧格式可借鉴给 UDP-mux 终局"
  source: "2026-08-05 分析"
  affects: [masque-evaluation]

- time: 2026-08-11T22:31:56
  kind: decision
  summary: "MASQUE 评估: 干净设备入站不替 WG; 传输层替换只在真骑 Cloudflare 时有意义(违背自建定位); QUIC-datagram 帧可借鉴给 UDP-mux 终局"
  source: "2026-08-05 分析"
  affects: [masque-evaluation]
