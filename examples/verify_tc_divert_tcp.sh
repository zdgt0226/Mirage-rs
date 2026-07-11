#!/usr/bin/env bash
# 双 netns 验证透明 TCP 分水岭: client(ns_cli) TCP connect 8.8.8.8:9999 →
# 网关(ns_gw) tc_divert sk_assign → IP_TRANSPARENT listener accept →
# local_addr() 应 == 8.8.8.8:9999。
set -e
BIN=./target/debug/examples/verify_tc_divert_tcp
[ -x "$BIN" ] || { echo "先 build: cargo build --example verify_tc_divert_tcp --features ebpf"; exit 1; }

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
ip netns exec ns_gw ip route add local default dev lo table 100
ip netns exec ns_gw ip rule add fwmark 1 lookup 100

ip netns exec ns_gw "$BIN" &
GW=$!
sleep 1.5

# client: TCP connect 8.8.8.8:9999, 发一行, 短超时 (握手成功即证明分水岭过)
ip netns exec ns_cli python3 -c '
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(("8.8.8.8", 9999))
    s.sendall(b"tcp-transparent-hello")
    print("  [cli] TCP connect + send 成功")
except Exception as e:
    print("  [cli] TCP connect 失败:", e)
' || true

wait $GW
