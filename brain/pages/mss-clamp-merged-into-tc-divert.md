---
id: mss-clamp-merged-into-tc-divert
title: "MSS clamp 并入 tc_divert (方案A), 独立 elf 成死代码"
category: decision
status: active
created: "2026-07-20T11:43:27"
updated: "2026-07-30T09:51:51"
---

## compiled_truth

**决定**(`66e0262`,方案A):把 MSS clamp **内联进 `tc_divert.c`**(`clamp_tcp_mss()`),
而不是作为独立 tc 程序挂载。MTU 由 `lib.rs` 自动探测网卡后经 `tc_divert_cfg` map 下发,`max_mss = mtu - 40`。

**为什么要有 MSS clamp**:网关经典坑 —— WAN 若是 PPPoE(1492)或隧道母网,大传输/部分站点会因
PMTU 黑洞卡死("小请求通、大下载卡")。借鉴自 Landscape 的 `xdp_mss`。

**为什么并入而非独立程序**:钳制点必须覆盖**直连转发**(`TC_ACT_OK`)路径,放在同一程序的分流判定**之前**
最直接;独立程序要再挂一次 tc 过滤器、多一份生命周期管理。

**留下的死代码(未清理)**:`ebpf-src/mss_clamp.c` / `mss_clamp.elf` 仍被 `build.rs:45` 编译,
但 `src/` 里**零引用**。注意:`verify_mss_clamp.sh` 验证的是**已内联的**实现,CI 里是绿的 ——
所以"MSS clamp 没做"的说法是**过期信息**,功能早已生效。


## timeline

- time: 2026-07-20T11:43:27
  kind: decision
  summary: "Created this page: MSS clamp 并入 tc_divert (方案A), 独立 elf 成死代码"
  source: "git 66e0262, ebpf-src/tc_divert.c"
  affects: [mss-clamp-merged-into-tc-divert]

- time: 2026-07-20T12:19:59
  kind: decision
  summary: "记录方案A选择及其留下的死代码"
  source: "git 66e0262/03211ef, ebpf-src/tc_divert.c"
  affects: [mss-clamp-merged-into-tc-divert]

- time: 2026-07-30T09:51:51
  kind: note
  summary: "收尾复核(2026-07-30): 功能早生效(内联 clamp_tcp_mss, verify_mss_clamp.sh CI 绿)。此前记的'死代码 ebpf-src/mss_clamp.c/.elf + build.rs:45 编译'已过期——现两文件均不存在, build.rs 无 mss 引用, src 唯一 mss_clamp 是条日志串。README 路线图 MSS clamp 从计划池移入已完成[x]。这条彻底关闭。"
  source: "grep build.rs/src/ebpf-src + README.md 核对"
  affects: [README.md, ebpf-src/tc_divert.c]
