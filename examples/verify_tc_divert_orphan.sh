#!/usr/bin/env bash
# 验证 tc_divert 孤儿过滤器安全网 (v0.5.0): listener 没了 → 已建流 TCP 不打 fwmark,
# 免得配合 fwmark→local 的 ip rule 把 LAN 的非直连 TCP 黑洞掉。
#
#   ns_cli(veth0 10.200.0.1) --- ns_gw(veth1 10.200.0.2, 挂 tc_divert)
#
# 用**真实连接**驱动 (不再造合成裸 ACK —— 见 .rs 头注释: 合成包在 5.15 上表现不同):
#   ② listener 活着: 客户端建真连接 + 发数据 → 已建流包被打 mark  (marking 正常)
#   ① 杀掉 listener: 客户端后续包 (重传) 打已建流分支 → 门控查不到 listener → 不打 mark
# 判据数"被打 mark 1 的包"(nft prerouting 计数器, tc ingress 在其之前跑 → 读到的
# mark 即 BPF 写的)。退出码即结论, 供 CI 用。
set -e
BIN=./target/debug/examples/verify_tc_divert_orphan
[ -x "$BIN" ] || { echo "先 build: cargo build --example verify_tc_divert_orphan --features ebpf"; exit 1; }
command -v nft >/dev/null || { echo "缺 nft (装 nftables 包): 本验证器用 nft 计数器数被打 mark 的包"; exit 1; }
command -v python3 >/dev/null || { echo "缺 python3: 用来跑客户端"; exit 1; }

FLAG=$(mktemp -u /tmp/orph_connected.XXXXXX)      # 客户端建连成功的信号文件
DROP=$(mktemp -u /tmp/orph_droplisten.XXXXXX)     # 触发 listener 关闭 LISTEN socket
cleanup() {
    kill -9 $LP $CP 2>/dev/null || true
    rm -f "$FLAG" "$DROP" "$CLI_PY"
    ip netns del ns_gw 2>/dev/null || true
    ip netns del ns_cli 2>/dev/null || true
}
trap cleanup EXIT
ip netns del ns_gw 2>/dev/null || true; ip netns del ns_cli 2>/dev/null || true

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
# TPROXY 配方: 被打 fwmark 1 的包 → local 路由表 → ip_local_deliver
ip netns exec ns_gw ip route add local default dev lo table 100
ip netns exec ns_gw ip rule add fwmark 1 lookup 100

# mark 计数器 (priority -150 = mangle prerouting, 在 tc ingress 之后)
ip netns exec ns_gw nft add table ip t
ip netns exec ns_gw nft add chain ip t pre '{ type filter hook prerouting priority -150; }'
ip netns exec ns_gw nft add rule ip t pre meta mark 1 counter comment '"marked"'
# 到达计数器: 没有它, "mark=0" 会在包**根本没到**时假通过。
ip netns exec ns_gw nft add rule ip t pre ip daddr 8.8.8.8 tcp dport 9999 counter comment '"arrived"'

count_of() {
    ip netns exec ns_gw nft list chain ip t pre \
        | grep "comment \"$1\"" | grep -oE 'counter packets [0-9]+' | grep -oE '[0-9]+$' | head -1
}
# 读增量, 不用 `nft reset counters` (它只重置具名 counter 对象, 重置不了规则内联的)。
MARKED_BASE=0; ARRIVED_BASE=0
snapshot() { MARKED_BASE=$(count_of marked); ARRIVED_BASE=$(count_of arrived); }
mark_delta()    { echo $(( $(count_of marked)  - MARKED_BASE  )); }
arrived_delta() { echo $(( $(count_of arrived) - ARRIVED_BASE )); }

LPORT=19999
wait_gone() {  # 轮询到 :LPORT 上再无 LISTEN
    local i
    for i in $(seq 1 150); do
        ip netns exec ns_gw ss -H -ltn "sport = :$LPORT" 2>/dev/null | grep -q LISTEN || return 0
        sleep 0.1
    done
    return 1
}
wait_listen() {  # 轮询到 :LPORT 进入 LISTEN
    local i
    for i in $(seq 1 150); do
        ip netns exec ns_gw ss -H -ltn "sport = :$LPORT" 2>/dev/null | grep -q LISTEN && return 0
        sleep 0.1
    done
    return 1
}

echo "== tc_divert 孤儿过滤器安全网验证 (真实连接驱动) =="
fail=0

# ── 挂 tc_divert 并 orphan 掉 (进程退出后过滤器仍在) ──────────────────────
ip netns exec ns_gw "$BIN" attach

# ── 起 IP_TRANSPARENT listener (收到 DROP 文件就关 LISTEN socket、保留 child) ──
ip netns exec ns_gw "$BIN" listen "$DROP" &
LP=$!
wait_listen || { echo "  ❌ FAIL: listener 15s 内没进入 LISTEN"; exit 1; }

# ── 客户端: 建真连接到 8.8.8.8:9999, 连上后持续发数据 (忽略错误) ──────────
CLI_PY=$(mktemp /tmp/orph_client.XXXXXX.py)
cat > "$CLI_PY" <<'PY'
import socket, sys, time
flag = sys.argv[1]
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(5)
try:
    s.connect(("8.8.8.8", 9999))   # SYN→sk_assign→透明listener; 完成握手即证明 marking 正常
    open(flag, "w").close()        # 通知 shell: 已建连
except Exception as e:
    print("  [cli] connect 失败:", e); sys.exit(1)
s.settimeout(0.5)
# 持续发 (杀 listener 后这些包 + 重传打已建流分支 → 用来验不被 mark)
for _ in range(200):
    try:
        s.send(b"x")
    except Exception:
        pass                       # 服务端死后 send 报错也继续, 靠内核重传兜底
    time.sleep(0.15)
PY
ip netns exec ns_cli python3 "$CLI_PY" "$FLAG" &
CP=$!

# 等客户端确认建连 (握手完成 = 已建流包在 listener 活着时确实被 mark+投递了)
for i in $(seq 1 100); do [ -e "$FLAG" ] && break; sleep 0.1; done
[ -e "$FLAG" ] || { echo "  ❌ FAIL: 客户端 10s 内没建成连接 (sk_assign/握手断?)"; exit 1; }

# ── ② listener 活着 → 已建流包被 mark ───────────────────────────────────
snapshot
sleep 1.5                          # 客户端此间持续发数据
n=$(mark_delta); a=$(arrived_delta)
echo "  [②] listener 活着 → 到达 = $a (期望 ≥1), 其中被 mark = $n (期望 ≥1)"
if [ "${a:-0}" -lt 1 ]; then
    echo "      ❌ FAIL: 无包到达 (拓扑/路由问题, 本 case 无效)"; fail=1
elif [ "${n:-0}" -ge 1 ]; then
    echo "      ✅ PASS: 已建流包被打 mark (marking 正常, 门控没误伤活着的 listener)"
else
    echo "      ❌ FAIL: listener 活着却不打 mark → 门控误伤正常路径"; fail=1
fi

# ── 关掉 LISTEN socket 复现孤儿态 (过滤器还在、LISTEN 没了、child 保留) ────
# 不杀进程: child 存活 → 客户端流不被 RST → 持续发包, 修复版/bug版都有已建流包可测。
touch "$DROP"
wait_gone || { echo "  ❌ FAIL: LISTEN socket 15s 内没关闭"; exit 1; }

# ── ① LISTEN 没了 → 已建流包不该被 mark ─────────────────────────────────
snapshot
sleep 2                            # 客户端持续发, 全打已建流分支
n=$(mark_delta); a=$(arrived_delta)
echo "  [①] LISTEN 没了 → 到达 = $a (期望 ≥1), 其中被 mark = $n (期望 0)"
if [ "${a:-0}" -lt 1 ]; then
    echo "      ❌ FAIL: 关 LISTEN 后无包到达 (没验到已建流分支, 本 case 无效)"; fail=1
elif [ "${n:-0}" = "0" ]; then
    echo "      ✅ PASS: 孤儿过滤器不再打 mark, 包走正常转发 (LAN 不会黑洞)"
else
    echo "      ❌ FAIL: 孤儿过滤器仍打 mark → fwmark→local 会把 LAN 流量黑洞掉"; fail=1
fi

exit $fail
