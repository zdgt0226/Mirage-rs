---
id: routing-rules
title: "路由规则的全部匹配维度与组合语义"
category: concept
status: active
tags: [routing, config]
created: "2026-07-21T09:10:12"
updated: "2026-07-21T09:11:50"
---

## compiled_truth

Mirage 的路由规则维度与 sing-box/Clash 基本对齐, **域名 4 种 + IP 2 种 + 连接属性 4 种 + and/or 组合**。
盘点"缺口"时的结论: 路由这块**没有短板**, 唯一明显缺的是 `process_name`(见末尾)。

## 域名匹配

| 字段 | 匹配方式 |
|---|---|
| `domain_suffix` | 域名后缀, 走 DomainTrie 按 label 逐级(`google.com` 命中 `www.google.com`) |
| `domain_keyword` | 子串包含 |
| `domain_regex` | 正则完整匹配 |
| `geosite` | v2ray/v2fly `geosite.dat` 展开成域名集(含 exact/suffix/regex 类型), 按类目码如 `cn`/`category-ads` |

## IP 匹配

| 字段 | 匹配方式 |
|---|---|
| `ip_cidr` | 手动 CIDR, 目的 IP 落段内 |
| `geoip` | `geoip.dat` 展开成 CIDR 集, 按国家码 |

## 连接属性匹配 (`matches_extra` / `matches_port`)

| 字段 | 匹配方式 |
|---|---|
| `port` | 目的端口在列表中(空 = 不限) |
| `protocol` | `tcp` / `udp` |
| `source_ip_cidr` | 源 IP 落段内(内网设备分流)。req 无 source_ip 时该规则不匹配 |
| `source_mac` | 源 MAC 精确匹配 |

## 组合语义

- **`mode`**: `or`(默认, 任一维度命中即匹配)/ `and`(所有**已配**维度都命中才匹配)。
- **`outbound`**: 命中后走的出站 tag(必填)。
- 多条规则**从上到下顺序**匹配, 首个命中生效; 都不中走 `routing.default_outbound`。
- 规则引用的 outbound 必须存在, 否则该规则永不生效 —— 这类错由 [[external-audit-verification]]
  提到的 `check` / 启动校验(config.rs::semantic_issues)拦下。

## geo 数据的坑 (与本页强相关)

geosite/geoip 是外部 `.dat`, 解析有两处历史 bug 已修, 见 [[geo-dat-parsing-robustness]]:
字段序不能假设、fixed32/64 要跳过而非 break。规则引用 geosite/geoip 时才会触发下载 updater。

## 明确缺的: `process_name`

sing-box 有按**进程名**分流, 这里**没有**。原因: 需要 eBPF/procfs 额外支撑(把连接关联到发起
进程), 属独立工程而非随手可补的维度。若要做, 归到 eBPF 数据面那条线。见 [[ebpf-scope-narrowed]]。


## timeline

- time: 2026-07-21T09:10:12
  kind: decision
  summary: "Created this page: 路由规则的全部匹配维度与组合语义"
  source: "src/router/mod.rs, src/config.rs::RuleConfig"
  affects: [routing-rules]

- time: 2026-07-21T09:11:50
  kind: decision
  summary: "从代码逐条核实路由匹配维度"
  source: src/router/mod.rs
  affects: [routing-rules]
