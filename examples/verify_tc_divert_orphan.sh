#!/usr/bin/env bash
# 验证 tc_divert 孤儿过滤器安全网 (v0.5.0): listener 不在 → 已建流 TCP 不打 fwmark。
#
#   ns_cli(veth0 10.200.0.1) --- ns_gw(veth1 10.200.0.2, 挂 tc_divert)
#
# 判据直接数"被打上 mark 1 的包"—— 即 BPF 的判定结果本身 (nft prerouting 计数器,
# tc ingress 在 netfilter prerouting 之前跑, 故这里读到的 mark 就是 BPF 写的)。
# client 发**裸 TCP ACK** (非 SYN) 打 tc_divert.c 的已建流分支; 用 raw socket 是因为
# 正常 connect 只会发 SYN, 走的是另一条 (sk_assign) 路径。
#
#   ① listener 不在 → mark 计数必须为 0  (修复生效; 修复前这里会是 1 → LAN 黑洞)
#   ② listener 活着 → mark 计数必须为 1  (对照组: 门控不能把正常路径一起掐了)
# 退出码即结论, 供 CI 用。
set -e
BIN=./target/debug/examples/verify_tc_divert_orphan
[ -x "$BIN" ] || { echo "先 build: cargo build --example verify_tc_divert_orphan --features ebpf"; exit 1; }
# 前置检查: 缺依赖要报得一眼看懂 (本脚本是唯一用 nft 的验证器 —— CI 的 apt 清单里
# 漏了 nftables 时, set -e 只会甩出一句 "nft: command not found" 就退, 很难查)。
command -v nft >/dev/null || { echo "缺 nft (装 nftables 包): 本验证器用 nft 计数器数被打 mark 的包"; exit 1; }
command -v python3 >/dev/null || { echo "缺 python3: 用来发裸 TCP ACK"; exit 1; }

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

# mark 计数器. priority -150 = mangle prerouting, 在 tc ingress 之后。
ip netns exec ns_gw nft add table ip t
ip netns exec ns_gw nft add chain ip t pre '{ type filter hook prerouting priority -150; }'
ip netns exec ns_gw nft add rule ip t pre meta mark 1 counter comment '"marked"'
# 到达计数器: 没有它, ① 的"mark 数=0"会在包**根本没到**时假通过 (路由断了也算 0)。
ip netns exec ns_gw nft add rule ip t pre ip daddr 8.8.8.8 tcp dport 9999 counter comment '"arrived"'

# 从 ns_cli 发一个到 8.8.8.8:9999 的裸 TCP ACK (非 SYN → 命中已建流分支)。
send_ack() {
    ip netns exec ns_cli python3 - <<'PY'
import socket, struct
src, dst = "10.200.0.1", "8.8.8.8"
sport, dport = 12345, 9999
# TCP 头: ACK 置位, SYN 不置 → tc_divert.c 的 (th->syn && !th->ack) 不成立 → 已建流分支
tcp = struct.pack("!HHIIBBHHH", sport, dport, 1000, 2000, 5 << 4, 0x10, 8192, 0, 0)
pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
data = pseudo + tcp
if len(data) % 2:
    data += b"\x00"
s = 0
for i in range(0, len(data), 2):
    s += (data[i] << 8) + data[i + 1]
s = (s >> 16) + (s & 0xFFFF)
s = ~((s >> 16) + s) & 0xFFFF
tcp = tcp[:16] + struct.pack("!H", s) + tcp[18:]
sk = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
sk.sendto(tcp, (dst, 0))
PY
}

# 按 comment 取对应规则的 packets 数
count_of() {
    ip netns exec ns_gw nft list chain ip t pre \
        | grep "comment \"$1\"" | grep -oE 'counter packets [0-9]+' | grep -oE '[0-9]+$' | head -1
}

# 读增量, 不用 `nft reset counters` —— 它只重置**具名 counter 对象**, 重置不了规则里
# 内联的 counter (会静默无效果, 计数一路累加 → case 之间互相污染出假通过)。
MARKED_BASE=0
ARRIVED_BASE=0
snapshot() { MARKED_BASE=$(count_of marked); ARRIVED_BASE=$(count_of arrived); }
mark_delta()    { echo $(( $(count_of marked)  - MARKED_BASE  )); }
arrived_delta() { echo $(( $(count_of arrived) - ARRIVED_BASE )); }

echo "== tc_divert 孤儿过滤器安全网验证 =="
fail=0

# ── ① 孤儿态: 过滤器挂着, listener 不存在 ────────────────────────────────
ip netns exec ns_gw "$BIN" attach
snapshot
send_ack
sleep 0.3
n=$(mark_delta); a=$(arrived_delta)
echo "  [①] listener 不在 → 到达 prerouting 的包 = $a (期望 ≥1), 其中被打 mark = $n (期望 0)"
if [ "${a:-0}" -lt 1 ]; then
    echo "      ❌ FAIL: 包没到 prerouting —— 本 case 无效 (拓扑/路由问题, 不是修复生效)"
    fail=1
elif [ "$n" = "0" ]; then
    echo "      ✅ PASS: 孤儿过滤器不再打 mark, 包走正常转发 (LAN 不会黑洞)"
else
    echo "      ❌ FAIL: 孤儿过滤器仍在打 mark → fwmark→local 会把 LAN 流量黑洞掉"
    fail=1
fi

# ── ② 对照组: listener 活着, mark 必须照打 ──────────────────────────────
ip netns exec ns_gw "$BIN" listen &
LP=$!
sleep 1
snapshot
send_ack
sleep 0.3
n=$(mark_delta); a=$(arrived_delta)
kill -9 $LP 2>/dev/null || true
echo "  [②] listener 活着 → 到达 = $a (期望 ≥1), 其中被打 mark = $n (期望 1)"
if [ "${a:-0}" -lt 1 ]; then
    echo "      ❌ FAIL: 包没到 prerouting —— 本 case 无效 (拓扑/路由问题)"
    fail=1
elif [ "$n" = "1" ]; then
    echo "      ✅ PASS: 正常路径未受影响 (sk_lookup 门控没误伤)"
else
    echo "      ❌ FAIL: listener 活着却不打 mark → 已建流投递不到代理, 门控误伤正常路径"
    fail=1
fi

exit $fail
