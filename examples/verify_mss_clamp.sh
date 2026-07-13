#!/usr/bin/env bash
# 在独立 netns 里验证 MSS clamp (免动宿主 lo 的 clsact)。
set -e
BIN=./target/debug/examples/verify_mss_clamp
[ -x "$BIN" ] || { echo "先 build: cargo build --example verify_mss_clamp --features ebpf"; exit 1; }
unshare -n bash -c "ip link set lo up; exec '$BIN'"
