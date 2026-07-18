#!/usr/bin/env bash
# 验证 XDP 极速 DNS (dns_xdp) 端到端 + 哈希一致性。
#   ns_cli(veth0 10.55.0.1) --- ns_srv(veth1 10.55.0.2, XDP attach)
# 客户端发 test.mirage 的 A 查询到 10.55.0.2:53 → veth1 ingress XDP 拦截 → 查表(命中
# 需 BPF 哈希==用户态哈希) → 改包(交换 MAC/IP/端口 + 追加 answer=fake-IP) → XDP_TX 回客户端。
# 客户端收到 198.18.0.99 即证明: XDP 收发改包整条通 + BPF/用户态哈希逐字节一致。
# 退出码即结论, 供 CI 用。
set -e
BIN=./target/debug/examples/verify_dns_xdp
[ -x "$BIN" ] || { echo "先 build: cargo build --example verify_dns_xdp --features ebpf"; exit 1; }
command -v python3 >/dev/null || { echo "缺 python3"; exit 1; }

cleanup() { kill -9 $SRV 2>/dev/null || true; ip netns del ns_srv 2>/dev/null || true; ip netns del ns_cli 2>/dev/null || true; }
trap cleanup EXIT
ip netns del ns_srv 2>/dev/null || true; ip netns del ns_cli 2>/dev/null || true

ip netns add ns_cli
ip netns add ns_srv
ip link add veth0 netns ns_cli type veth peer name veth1 netns ns_srv

ip netns exec ns_cli ip link set lo up
ip netns exec ns_cli ip link set veth0 up
ip netns exec ns_cli ip addr add 10.55.0.1/24 dev veth0
ip netns exec ns_cli sysctl -qw net.ipv4.conf.all.rp_filter=0
ip netns exec ns_cli sysctl -qw net.ipv4.conf.veth0.rp_filter=0

ip netns exec ns_srv ip link set lo up
ip netns exec ns_srv ip link set veth1 up
ip netns exec ns_srv ip addr add 10.55.0.2/24 dev veth1

echo "== XDP 极速 DNS 端到端验证 =="

# 服务侧: 灌 map + attach XDP, hold 住
ip netns exec ns_srv "$BIN" serve &
SRV=$!
# 等 XDP attach 就绪 (轮询 ip link 上出现 xdp 标记)
for i in $(seq 1 100); do
    ip netns exec ns_srv ip link show veth1 2>/dev/null | grep -qi "xdp" && break
    sleep 0.1
done
ip netns exec ns_srv ip link show veth1 | grep -qi "xdp" || { echo "  ❌ FAIL: XDP 15s 内没 attach 上"; exit 1; }
echo "  [srv] XDP 已挂 veth1"

# 客户端: 发 A 查询, 校验回包是 fake-IP
ip netns exec ns_cli python3 - <<'PY'
import socket, struct, sys
DOMAIN = b'test.mirage'
DST = ('10.55.0.2', 53)
FAKE = bytes([198, 18, 0, 99])

def build_query():
    hdr = struct.pack('!HHHHHH', 0x1234, 0x0100, 1, 0, 0, 0)  # ID, flags(RD, QR=0), qd=1, an/ns/ar=0
    q = b''
    for label in DOMAIN.split(b'.'):
        q += bytes([len(label)]) + label
    q += b'\x00' + struct.pack('!HH', 1, 1)  # QTYPE=A(1), QCLASS=IN(1)
    return hdr + q

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
s.sendto(build_query(), DST)
try:
    data, _ = s.recvfrom(2048)
except Exception as e:
    print("  ❌ FAIL: 4s 内没收到 XDP 响应:", e); sys.exit(1)

flags = struct.unpack('!H', data[2:4])[0]
ancount = struct.unpack('!H', data[6:8])[0]
ip = data[-4:]
print(f"  [cli] 收到 {len(data)}B, QR={flags>>15}, ancount={ancount}, RDATA={'.'.join(map(str,ip))}")
if (flags & 0x8000) and ancount >= 1 and ip == FAKE:
    print("  ✅ PASS: XDP 拦截 DNS 回 fake-IP 198.18.0.99 → 收发改包整条通 + BPF/用户态哈希一致")
    sys.exit(0)
else:
    print("  ❌ FAIL: 响应不符 (XDP 未命中=哈希不一致? 或未改包?)"); sys.exit(1)
PY
