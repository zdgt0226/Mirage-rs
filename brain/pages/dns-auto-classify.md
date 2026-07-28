---
id: dns-auto-classify
title: "DNS 未分类域名自适应分类 (auto_classify)"
category: decision
status: active
tags: [dns, routing, geoip, fakeip, anti-pollution]
created: "2026-07-29T00:59:15"
updated: "2026-07-29T00:59:15"
---

## compiled_truth

**决定**: 给**未命中任何 routing 规则** (本走 default_outbound) 的"灰域名"加按解析 IP 归属的自适应分流。用户需求 = CDN 就近 + 减少过度代理 (读法B), 而非纯反污染。

## 行为
1. 灰域名先用**国内 DNS** 解析 (快), 看**首个 A 记录** vs GeoIP:
   - IP ∈ CN → 返回国内结果 (直连, 国内 CDN 就近)。**国内 DNS = 最终回落** (GeoIP 判 CN/无法判 → 用国内结果)。
   - IP ∉ CN → 改 **fake-IP** (走隧道远程解析, 免污染, 见 [[fakeip-remote-resolution]]), 且把域名按 **TTL 学习标记海外** → 后续直接 fake-IP。
2. 命中显式规则的域名照旧 (direct/mirage/block, 见 [[routing-rules]])。
3. 非 A 未分类查询: AAAA/HTTPS 回空答复逼客户端用 A (与 fakeip v4-only 一致); 其它类型走国内兜底。

## 铁律 (污染边界)
只作用于**未命中规则**的灰域名。已知被封域名 (google 等) 必须放 routing.rules 明确代理 —— 否则**极少数 CN 段污染**会被误判"国内 CDN→直连", 连到污染 IP 挂掉。已知被封的走不到这一步 (在 geosite:!cn), 故命中概率低; 接受此边界, 不做二次 RST 兜底 (用户选快速响应)。

## 实现
- `router.route_matched(&req) -> Option<OutboundTag>`: 区分"命中显式规则"(Some) vs "落 default"(None)。`route()` = 它的 unwrap_or(default) 包装, 语义/顺序不变 (仍是声明顺序 top-to-bottom first-match)。
- `AutoClassify` (dns/server.rs): CN 段 (`load_geoip_dat(path,"cn")`, geoip.dat 缺失/空→禁用) + 学习缓存 (HashMap<domain, expiry>, TTL + 容量软上限)。挂 `CoreState` (config_watcher build_state 构造); **热重载重建 → 学习缓存重置** (可接受)。
- `first_a_record(resp)`: 解析 DNS 响应首个 A 记录 IPv4 (跳 question + answer name 压缩指针)。
- 配置: `advanced_dns.auto_classify { enabled, ttl=3600, max_entries=8192 }`。

## 顺带
移除死字段 `advanced_dns.rules` (split-DNS match/use, 从未实现, 仅 startup warn) —— check 现报未知字段, 模板删。DNS 分流 = routing.rules 复用 + auto_classify。见 [[external-audit-verification]] 的"死字段"教训。

单测: first_a_record / is_cn / TTL 缓存过期 / 容量封顶 / route_matched None-vs-Some。


## timeline

- time: 2026-07-29T00:59:15
  kind: decision
  summary: "Created this page: DNS 未分类域名自适应分类 (auto_classify)"
  source: created via brain create-page
  affects: [dns-auto-classify]

- time: 2026-07-29T00:59:15
  kind: decision
  summary: "灰域名国内解析→首个A的GeoIP判CN直连/海外fakeip+TTL学习; 复用geoip cn段; 只对未命中规则的域名"
  source: brain update-truth
  affects: [dns-auto-classify]
