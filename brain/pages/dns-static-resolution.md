---
id: dns-static-resolution
title: "DNS 静态解析 (advanced_dns.static): 精确+子域, 接管即完全接管"
category: decision
status: active
tags: [dns, static, testing, fakeip]
created: "2026-07-25T23:13:49"
updated: "2026-07-25T23:13:49"
---

## compiled_truth

## 决定

`advanced_dns.static` 提供自定义 DNS 解析 (类 dnsmasq `address=/domain/ip`): 域名 → 一个
或多个 IP。主要动机: **本地测试环境**把测试域名钉到本机/内网 IP。

## 语义 (用户拍板)

- **匹配 = 精确 + 子域, 最长键优先** (dnsmasq 式)。`test.local` 命中 `test.local` 及所有
  子域 `api.test.local` / `a.b.test.local`, 但**不**命中前缀粘连的 `xtest.local`。
- 值单 IP 字符串或数组 (混 v4/v6): A 查询回 v4, AAAA 查询回 v6。
- **接管即完全接管**: 命中域名但查询类型无对应家族 (只配 v4 却查 AAAA)、或非 A/AAAA
  查询 → NODATA 空答复, **绝不放行上游** (否则会拿到真实记录泄漏, 违背"本地接管"意图)。
- **优先级最高**: process_query 最前检查, 在 fake-IP / 路由 / 上游之前。对 DNS 劫持路径
  ([[dns-hijack-lan]]) 同样生效, 因共用 process_query。

## 实现

- config: `AdvancedDnsConfig.static_hosts: HashMap<String, StaticValue>` (StaticValue =
  untagged string-or-array); 预处理成 `cached_static: Vec<(小写域名, Vec<IpAddr>)>` 按域名
  长度降序 (config_watcher 解析 IP + 排序, 非法 IP 告警跳过)。
- server: `static_domain_matches` (纯) + `static_answer(req, qtype, ips)` (纯, 家族选择 +
  NODATA 回退) + `make_aaaa_response` (IPv6 A 记录对应物, 复用 make_fake_ip_response 作 A)。
  三者均有单元测试 (匹配语义 / AAAA 结构 / 家族选择含 NODATA 分支)。

关联 [[dns-hijack-lan]] (共用 process_query, 静态优先于劫持的 fake-IP)、[[fakeip-remote-resolution]]。


## timeline

- time: 2026-07-25T23:13:49
  kind: decision
  summary: "Created this page: DNS 静态解析 (advanced_dns.static): 精确+子域, 接管即完全接管"
  source: "feat/dns-hijack 分支"
  affects: [dns-static-resolution]

- time: 2026-07-25T23:13:49
  kind: decision
  summary: "自定义域名→IP 静态解析: dnsmasq 式精确+子域最长匹配, 命中绕过 fake-IP/路由/上游, 无对应家族回 NODATA 不放行"
  source: brain update-truth
  affects: [dns-static-resolution]
