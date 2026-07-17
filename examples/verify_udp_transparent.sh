#!/usr/bin/env bash
# 在独立 netns 里验证 sk_lookup UDP 透明代理内核行为 (免把 sk_lookup attach 到宿主 netns)。
#   ① IP_TRANSPARENT 开 → origdst 应报出 fake-IP  (必须通过)
#   ② 对照: IP_TRANSPARENT 关 → 仅信息, 不参与成败
#   ③ 回包源伪造 (IP_TRANSPARENT+FREEBIND)        (必须通过)
# 退出码即结论 (关键 case 不过则非零), 供 CI 用。
set -e
BIN=./target/debug/examples/verify_udp_transparent
[ -x "$BIN" ] || { echo "先 build: cargo build --example verify_udp_transparent --features ebpf"; exit 1; }
# fake-IP 段需可路由, 否则 send_to 在 sk_lookup 之前就 ENETUNREACH。指到 lo 即可 ——
# sk_lookup 在本地投递查 socket 时拦截, 包并不真的需要出去。
unshare -n bash -c "ip link set lo up; ip route add 198.18.0.0/16 dev lo; exec '$BIN'"
