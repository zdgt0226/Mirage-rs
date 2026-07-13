#!/usr/bin/env bash
# 验证 cgroup/connect4 本机出向重定向。cgroup v2 (非 netns), 建子 cgroup 只影响
# 测试 client, 不动全局。listener(本例进程) 不进该 cgroup, 免自身连接被改写。
set -e
BIN=./target/debug/examples/verify_cgroup_connect
[ -x "$BIN" ] || { echo "先 build: cargo build --example verify_cgroup_connect --features ebpf"; exit 1; }

CG=/sys/fs/cgroup/mirage_test
cleanup() { rmdir "$CG" 2>/dev/null || true; }
trap cleanup EXIT
cleanup
mkdir -p "$CG"

MIRAGE_CG="$CG" "$BIN" &
GW=$!
sleep 1.5

# client 放进 cgroup 后 connect 198.18.0.13:443 (应被 connect4 改写进 127.0.0.1:19999)
python3 -c '
import os, socket
open("'"$CG"'/cgroup.procs","w").write(str(os.getpid()))
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3)
try:
    s.connect(("198.18.0.13", 443))
    s.sendall(b"hi")
    print("  [cli] connect 成功 (被透明改写)")
except Exception as e:
    print("  [cli] connect 失败:", e)
' || true

wait $GW
