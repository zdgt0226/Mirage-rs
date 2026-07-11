#!/usr/bin/env bash
# 双 netns 拓扑验证 tc-bpf + bpf_sk_assign 裸-IP 拦截。
#   ns_cli(veth0 10.200.0.1) --- ns_gw(veth1 10.200.0.2, 挂 tc_divert)
# client 往 8.8.8.8:9999 发裸-IP UDP(默认路由指向 gw)→ veth1 ingress →
# tc_divert sk_assign → gw 内的透明 socket 收到, origdst=8.8.8.8:9999。
set -e
BIN=./target/debug/examples/verify_tc_divert
[ -x "$BIN" ] || { echo "先 build: cargo build --example verify_tc_divert --features ebpf"; exit 1; }

cleanup() { ip netns del ns_gw 2>/dev/null || true; ip netns del ns_cli 2>/dev/null || true; }
trap cleanup EXIT
cleanup

ip netns add ns_cli
ip netns add ns_gw
ip link add veth0 netns ns_cli type veth peer name veth1 netns ns_gw

ip netns exec ns_cli ip link set lo up
ip netns exec ns_cli ip link set veth0 up
ip netns exec ns_cli ip addr add 10.200.0.1/24 dev veth0
ip netns exec ns_cli ip route add default via 10.200.0.2 dev veth0

ip netns exec ns_gw ip link set lo up
ip netns exec ns_gw ip link set veth1 up
ip netns exec ns_gw ip addr add 10.200.0.2/24 dev veth1
ip netns exec ns_gw sysctl -qw net.ipv4.ip_forward=1
ip netns exec ns_gw sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec ns_gw sysctl -qw net.ipv4.conf.veth1.rp_filter=0
# TPROXY 配方: 被 sk_assign 的包 (BPF 打 fwmark 1) → local 路由表 → ip_local_deliver
ip netns exec ns_gw ip route add local default dev lo table 100
ip netns exec ns_gw ip rule add fwmark 1 lookup 100

: > /sys/kernel/debug/tracing/trace 2>/dev/null || true

# gw 侧: attach tc_divert + 透明 socket, 等 3s recv
ip netns exec ns_gw "$BIN" &
GW=$!
sleep 1.5

# client 侧: 先发直连段 1.1.1.1 (应被内核直连丢弃), 再发 8.8.8.8 (应被代理)
ip netns exec ns_cli python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"direct-leak?", ("1.1.1.1", 9999))
s.sendto(b"raw-ip-hello", ("8.8.8.8", 9999))
print("  [cli] sent 1.1.1.1 (direct) + 8.8.8.8 (proxy)")
' || true

wait $GW
echo "=== trace (tc_divert) ==="
grep 'tc_divert' /sys/kernel/debug/tracing/trace 2>/dev/null | tail -20 || echo "(空)"
