---
id: ebpf-elf-no-commit
title: "eBPF ELF 不入库: --features ebpf 硬要求 clang, 无静默回落"
category: decision
status: active
tags: [ebpf, build, supply-chain]
created: "2026-08-16T09:12:02"
updated: "2026-08-16T09:12:23"
---

## compiled_truth

## 决策

`ebpf-src/*.elf` **不入库**。`--features ebpf` 构建缺 clang → build.rs **硬 panic**, 不再静默
回落到 committed ELF。

## 为什么

曾经 committed 的 sockmap/dns_xdp/tc_divert.elf 落后于 `.c` (git 历史: `.c` 提交晚于 `.elf`):
源码修复 (dns_xdp 域名哈希碰撞 P1 79f7118 / tc_divert 孤儿过滤器黑洞 3eb675b) 不在旧 ELF 里。
build.rs 旧逻辑在 clang 缺失时静默 `include_bytes!` 陈旧 ELF → 悄悄跑带 bug 的 BPF (流量可劫持到
错 IP)。触发窄 (默认无 ebpf 不 include; release CI + ebpf+clang 都重编译) 但真实。

## 为何不用 byte-cmp CI 守卫

不同 clang 版本/strip 级别产出字节差极大 (实测 fresh dns_xdp 196KB vs committed 33KB, 6×),
连 release.yml 自己都复现不出 committed 字节。byte-cmp 守卫会跨环境假报警。故选"根除漂移类"
(删 ELF + 硬要求 clang), 而非"守住字节一致"。

## 现状

- 默认构建 (default=[], 无 ebpf): aya 加载 `#[cfg(feature="ebpf")]` 编译掉, 不 include ELF, 无需 clang。
- `--features ebpf` + clang: build.rs 编到 OUT_DIR (fresh)。缺 clang: 硬 panic 提示。
- release CI: 显式编到 ebpf-src/ 作校验 + cargo build 编到 OUT_DIR; ebpf-src/*.elf 已 gitignore。

关联: [[ebpf-scope-narrowed]] [[external-audit-2026-08]]


## timeline

- time: 2026-08-16T09:12:02
  kind: decision
  summary: "Created this page: eBPF ELF 不入库: --features ebpf 硬要求 clang, 无静默回落"
  source: commit fix/ebpf-elf-drift
  affects: [ebpf-elf-no-commit]

- time: 2026-08-16T09:12:23
  kind: decision
  summary: "committed ELF 删除; --features ebpf 缺 clang 硬 panic 不静默回落; 根除 ELF/源码漂移"
  source: brain update-truth
  affects: [ebpf-elf-no-commit]
