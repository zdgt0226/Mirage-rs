---
id: tls-padding-design
title: "TLS Padding 设计 (v1): 抗包长序列 ML, TLS1.3 原生零填充, 两阶段上线"
category: decision
status: active
created: "2026-08-02T01:48:36"
updated: "2026-08-02T01:50:37"
---

## compiled_truth

目标: 抗 GFW 对"握手后包长序列"的 ML 识别 (Phase1 流量塑形第一件, 见 [[roadmap-dependencies]])。属**协议层改动** (改数据帧解析), 后续单独 minor 版本 tag (如 v0.8.0), 不混进 patch。

## 路线 (问答确定)

- **机制 = TLS 1.3 原生零填充**: 现帧格式 [chunk, content_type=0x17] seal 成 TLS1.3 record; padding = 0x17 后追加零字节, 收端从尾剥零再取 content_type。与真实 TLS1.3 padding 字节级一致、不可区分, 不引入任何非标字段。
- **上线 = 两阶段, 无需 proto_ver / 协商**:
  1. 先只改**收端** recv_data: 从 "pop 末字节当 type" 改成 "先 while 末字节==0 循环 pop, 再 pop content_type" (全零则报错, 已有空检查兜)。对现网**零影响** (旧发端不发零 = 照常)。可立即合入。
  2. 全网收端普及后, 再开**发端** padding。
- **范围 = 握手后前 4 条记录**。**含 server 首帧 TIME_SYNC (固定 10 字节)** —— 它走 CryptoWriter 自然落在前 N, padding 后不再固定长, 抹掉这个显眼指纹。
- **方向 = 双向** (client / server 各填自己前 4 条)。
- **长度 = 均匀随机 [0,256] 字节/条** (fastrand)。首版不伪装具体站点分布, 打碎固定模式即可。
- **切分 = 首版不做** (后续增强: 把大写入拆成随机尺寸多 record; UDP 上行已有合帧基础, 反向即拆)。
- **参数 = 保守**: 前 4 条 + 每条 [0,256]。峰值 ~1KB 一次性开销, 大流量无感。

## 关键安全性

结构 [chunk, 0x17, 0x00...] 天然安全: content 自身的尾部零字节在 0x17 **之前**, 剥零只剥 0x17 之后的零, **不误伤** content 尾零。这正是 TLS 1.3 的设计 (content_type 是 content 与 padding 之间的非零分隔标记)。

## 实现点

- 文件: src/crypto/aead.rs (send_data ~146 push 0x17 / recv_data ~284 buffer.pop)。
- 收端: while buffer.last()==Some(0) pop; 再 pop content_type; 空则报错。
- 发端: CryptoWriter 加 records_sent 计数; 前 4 条 seal 前追加 fastrand(0..=256) 个零; 保证 chunk + pad + 1 <= 16384。

## 未选项及理由

- 自定义长度前缀字段: 不如原生优雅, 且要动帧格式。
- 伪真实 Chrome 首包分布: 需采集/拟合 harness, 首版过重 (后续可升级长度模型)。
- 固定块对齐 (SS2022 式): 块本身成一种可识别模式。
- proto_ver 门控协商 (同 cipher agility): 两阶段更平滑, 不必要。


## timeline

- time: 2026-08-02T01:48:36
  kind: decision
  summary: "Created this page: TLS Padding 设计 (v1): 抗包长序列 ML, TLS1.3 原生零填充, 两阶段上线"
  source: "问答式路线确定 + aead.rs 帧格式核实 (recv_data:284 buffer.pop, send_data:146 push 0x17)"
  affects: [tls-padding-design]

- time: 2026-08-02T01:50:37
  kind: decision
  summary: "TLS padding 设计 v1: TLS1.3 原生零填充, 两阶段上线(先收端剥零再发端填充), 前 4 条 record 双向均匀随机 [0,256], 协议层改动待新 minor 版本 tag"
  source: "问答式路线 + aead.rs 帧格式核实"
  affects: [tls-padding-design]
