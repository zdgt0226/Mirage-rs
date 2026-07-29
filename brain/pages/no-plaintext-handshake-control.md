---
id: no-plaintext-handshake-control
title: "协议控制必须在加密层 —— 不在明文 TLS 握手做手脚 (GREASE 隐蔽通道风险)"
category: decision
status: active
tags: [tls, fingerprint, covert-channel, security, handshake]
created: "2026-07-30T00:10:17"
updated: "2026-07-30T00:10:17"
---

## compiled_truth

**原则**: TLS 握手的**明文阶段** (ClientHello 等) 只干一件事 —— **完美伪装成一次普通 HTTPS 访问**。任何自定义协议控制/认证/模式信号**一律推迟到加密层** (握手完成后的加密隧道内)。

## 为什么不能在明文握手做协议控制 (以 GREASE 隐蔽通道为例)
曾评估用 ClientHello 的 GREASE 槽传 cipher agility 能力信号, 否决。风险:
1. **RFC 8701 取值受限**: GREASE 只能是 16 个 `0x?A?A` 值; 越界/畸形结构 → DPI 立刻识别"异常 ClientHello"。
2. **整体指纹木桶效应**: JA3 会剔除 GREASE, 但 JA4/行为分析/GREASE 出现频率-位置的**统计相关性**仍抓得到; 拟态不全 = 得分低。
3. **主动探测/重放 (最致命)**: 若服务端**因 ClientHello 里的信号改变行为**, GFW 重放该 ClientHello 就能触发同样行为 → 暴露代理。
4. **熵分析**: 频繁变动的 GREASE 偏离区域基线流量 → ML 标异常。

## 我们的做法 (符合最佳实践)
- **ClientHello 一字不改**, 全套 Chrome/Firefox 拟态 (GREASE 合规值+扩展洗牌+key_share/supported_versions/ALPN), 见 [[tls-fingerprint-mimicry]]。
- 一切协商推迟到**加密隧道内**: cipher agility 的 `proto_ver`/`CIPHER_NEGO`/`CIPHER_ACK` 全在 TIME_SYNC 之后的加密帧, 见 [[cipher-agility]]。
- 认证 token 塞 `session_id` (真浏览器也发随机 32B session_id, 已证非指纹, 见 [[session-id-not-a-fingerprint]])。
- **主动探测回退真站**: 认证不过 → 不返回错误, 直接转发到真实伪装站, 服务端行为**不因探测分叉** → 重放拿不到密码就永远只看到真站, 见 [[camouflage-forward-on-auth-fail]]。

## 结论 (2026-07-30, 外部分析佐证)
一份外部分析独立得出同结论 (GREASE 隐蔽通道高风险, 协议控制应在加密层)。**任何新的协议协商/控制需求, 一律走加密层, 绝不碰明文握手。** 这是硬约束。


## timeline

- time: 2026-07-30T00:10:17
  kind: decision
  summary: "Created this page: 协议控制必须在加密层 —— 不在明文 TLS 握手做手脚 (GREASE 隐蔽通道风险)"
  source: created via brain create-page
  affects: [no-plaintext-handshake-control]

- time: 2026-07-30T00:10:17
  kind: decision
  summary: "原则: TLS握手明文阶段零自定义协议控制(GREASE隐蔽通道会被DPI/JA4/重放探测抓); 一切协商/认证推迟到加密层"
  source: brain update-truth
  affects: [no-plaintext-handshake-control]
