---
id: udp-capacity-findings
title: "UDP 带机量实测: direct 网关健康, 隧道受 pool_size 封顶"
category: decision
status: active
created: "2026-07-31T02:28:45"
updated: "2026-07-31T02:28:45"
---

## compiled_truth

<current best understanding — replace this with the real content>

## timeline

- time: 2026-07-31T02:28:45
  kind: decision
  summary: "Created this page: UDP 带机量实测: direct 网关健康, 隧道受 pool_size 封顶"
  source: "旁路由 ens192 nstat/ip -s link 实测 + transparent_udp.rs:685 + config.rs:1152 pool_size=16 + scripts/bench_udp_capacity.py"
  affects: [udp-capacity-findings]
