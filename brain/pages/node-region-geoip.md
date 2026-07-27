---
id: node-region-geoip
title: "节点区域判定: GeoIP(server IP) 离线判国 + 建组混区域告警"
category: decision
status: active
tags: [geoip, region, load-balance, cli, group]
created: "2026-07-27T23:23:41"
updated: "2026-07-27T23:26:29"
---

## compiled_truth

## 决定

节点区域 = **出口 IP 所在国**。负载均衡/选路应同区域 (混区域出口国不一致, 落地解锁/延迟乱)。
自动判定 A 版: **GeoIP 查 server IP** (离线, 复用已下载 geoip.dat)。

## 实现

- geo.rs: `load_all_geoip(path) -> Vec<(国家码, Vec<IpNet>)>` (泛化 load_geoip_dat, 不过滤 code)
  + `country_for_ip(all, ip)` (首个包含它的国家)。
- CLI: `load_node_geoip(root)` 从 tuning.geodata_dir + geo_sources(kind=geoip).name 定位 geoip.dat;
  `region_for_host(db, host)` (IP 字面量或系统解析首 IP → country_for_ip);
  `mixed_region_warning(root, db)` (mirage 节点跨>1 区域返回告警)。
- test 每节点加 `[国家码]` 列; import --group 建组后混区域 eprintln 告警。

## 限制 (诚实标注)

- 对**直连出口**节点准 (VPS IP 国=出口国)。节点若在**服务端再经上游中转** (SS/WG upstream)
  则 server IP ≠ 真出口, 不准。**主动出口探测** (穿隧道回显 IP + geoip, 即方案 B) 后续加。
- 无 geoip.dat / 未知 IP → 静默降级 (不报区域, 不拦)。

## 验证

单测: 合成 geoip.dat 的 load_all_geoip/country_for_ip (US/CN 段)。e2e 对真 22MB geoip.dat:
test 显示 8.8.8.8[US]/114.114.114.114[CN]; import --group 跨 US/CN/AU 告警。

注: 同区域分组的动机来自负载均衡出站组; subscribe 的 group 告警在 PR#10 分支未合并, 合并后补。


## timeline

- time: 2026-07-27T23:23:41
  kind: decision
  summary: "Created this page: 节点区域判定: GeoIP(server IP) 离线判国 + 建组混区域告警"
  source: feat/node-region
  affects: [node-region-geoip]

- time: 2026-07-27T23:23:41
  kind: decision
  summary: "GeoIP 查节点 server IP 所在国判区域(离线复用 geoip.dat); test 显示[国家码], import --group 混区域告警; 对直连出口准, 中转节点不准(已知限制, 主动出口探测后续); load_all_geoip+country_for_ip 反查"
  source: brain update-truth
  affects: [node-region-geoip]

- time: 2026-07-27T23:26:28
  kind: note
  summary: "同区域分组的动机来自负载均衡组 (load-balance-outbound 页在 PR#11 分支, 合并后互链)"
  source: feat/node-region
  affects: [node-region-geoip]

- time: 2026-07-27T23:26:29
  kind: decision
  summary: "GeoIP 查节点 server IP 所在国判区域(离线复用 geoip.dat); test 显示[国家码], import --group 混区域告警; 对直连出口准, 中转节点不准(已知限制, 主动出口探测后续); load_all_geoip+country_for_ip 反查"
  source: brain update-truth
  affects: [node-region-geoip]
