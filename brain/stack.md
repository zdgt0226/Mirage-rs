---
slug: stack
title: Tech stack
role: tech-stack choices
updated: "2026-07-20T11:28:54"
---

# Tech stack

## 语言与运行时

| 域 | 选择 | 理由 |
|---|---|---|
| 语言/运行时 | Rust 2021 + `tokio`(full) | 从 Python POC 全量重写,见 [[rust-rewrite-from-python-poc]] |
| eBPF 加载 | `aya` 0.13.1(可选 feature `ebpf`) | 纯 Rust,无 libbpf/C 工具链依赖;默认 feature 不含,保证无 eBPF 环境可编译 |
| 加密 | `ring`(ChaCha20-Poly1305)+ `poly1305`/`hkdf`/`hmac`/`sha2` | 见 [[ring-for-aead]] |
| Web 看板 | `axum` 0.8 + `tower-http` | 内置 Neon Dashboard,静态资源随 binary |
| 配置 | `serde`/`serde_json` + `notify` 热重载 | JSON 配置 + 文件监听,不上 DB |
| 分流数据 | 自写 protobuf 解析(`router/geo.rs`) | 直接吃 v2ray/v2fly `geosite.dat`/`geoip.dat`,不引 protobuf 运行时 |
| 低层网络 | `libc` + `nix`(socket/net/uio) | `IP_TRANSPARENT`/`IP_RECVORIGDSTADDR`/`splice(2)`/netlink 等裸 syscall |
| 日志 | `tracing` + `tracing-subscriber` + `flate2` | 文件日志按大小滚动 + gzip 归档 |

## 构建

- `build.rs` 自动用 clang 编译 `ebpf-src/*.c` → `.elf`,产物走 `OUT_DIR`(仓库里的 `.elf` 仅为便利副本)。
- 发布 `musl` 静态链接为主(全 Linux 通吃)+ gnu / arm64 变体。
- CI(`.github/workflows/build.yml`)两个 job:`build`(单测)与 **`ebpf-verify`**(netns 内核机制验证器,故意跑在 ubuntu-22.04 / 内核 5.15 以检验"≥5.10 支持"这一声明)。

## 内核要求

透明网关能力需 Linux ≥ 5.10(`sk_lookup`/`sk_assign`/tc clsact);无 eBPF 时仍可作普通 SOCKS/HTTP 代理运行。
