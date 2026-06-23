#!/usr/bin/env bash
# Mirage-rs v0.4.4-alpha.3 综合 bug 修复验证脚本.
#
# 运行机器: 客户端 (大部分测试). Bug 3 (TCP 僵尸) 需要服务端配合.
#
# 用法:
#   bash scripts/test_bugfixes.sh           # 交互选菜单
#   bash scripts/test_bugfixes.sh all       # 跑全部
#   bash scripts/test_bugfixes.sh quick     # 只跑全自动的 (4/5/6)
#   bash scripts/test_bugfixes.sh 1 4 6     # 指定 bug 号
#
# 配置 (环境变量覆盖):
#   CLIENT_LOG=/tmp/mirage-client.log     客户端日志路径 (Bug 1 需要 DEBUG)
#   SOCKS_PROXY=socks5://127.0.0.1:1080  客户端 SOCKS5 入口
#   SOCKS_HOST=127.0.0.1:1080            裸 host:port (curl --socks5)
#   DNS_PORT=5353                         客户端 DNS inbound 端口
#   GEO_DIR=/etc/mirage-rs/geosite       Geo 数据目录
#   CLIENT_BIN=mirage-rs-amd64-musl       客户端二进制名 (pgrep 用)

set -u

CLIENT_LOG="${CLIENT_LOG:-/tmp/mirage-client.log}"
SOCKS_PROXY="${SOCKS_PROXY:-socks5://127.0.0.1:1080}"
SOCKS_HOST="${SOCKS_HOST:-127.0.0.1:1080}"
DNS_PORT="${DNS_PORT:-5353}"
GEO_DIR="${GEO_DIR:-/etc/mirage-rs/geosite}"
CLIENT_BIN="${CLIENT_BIN:-mirage}"

RESULTS=()

# ─────────── UI helpers ───────────
C_HDR='\033[1;36m'; C_PASS='\033[32m'; C_FAIL='\033[31m'; C_WARN='\033[33m'; C_END='\033[0m'

section() { echo -e "\n${C_HDR}════ $* ════${C_END}"; }
pass()    { RESULTS+=("PASS Bug $1"); echo -e "  ${C_PASS}✓ PASS${C_END}  $2"; }
fail()    { RESULTS+=("FAIL Bug $1"); echo -e "  ${C_FAIL}✗ FAIL${C_END}  $2"; }
skip()    { RESULTS+=("SKIP Bug $1"); echo -e "  ${C_WARN}- SKIP${C_END}  $2"; }
note()    { echo -e "  ${C_WARN}!${C_END}  $*"; }
prompt()  { read -p "  ${1} " ans; echo "$ans"; }

# ─────────── 客户端进程是否在跑 ───────────
client_pid() { pgrep -f "$CLIENT_BIN.*client" | head -1; }

# ════════════════════════════════════════════════════════════════════
# Bug 6: WarmPool 雪崩 (上游死, get() 无超时) — 最易复现, 1 分钟
# ════════════════════════════════════════════════════════════════════
test_bug6() {
    section "Bug 6: WarmPool 雪崩 / 无超时 (上游不可达时不应无限 hang)"
    note "前置: 服务端必须 ★ 关掉 ★"
    if [[ -z "$(client_pid)" ]]; then
        skip 6 "客户端未运行"; return
    fi
    [[ "$(prompt '服务端已关掉了吗? (y 继续 / n 跳过):')" =~ ^[yY] ]] || { skip 6 "用户跳过"; return; }

    note "发 curl 测量耗时 (期望: 10-12 秒返回, 不是 30 秒挂满)"
    local start=$(date +%s)
    curl --max-time 30 -x "$SOCKS_PROXY" -s -o /dev/null https://example.com 2>&1 || true
    local elapsed=$(( $(date +%s) - start ))

    if (( elapsed >= 9 && elapsed <= 14 )); then
        pass 6 "${elapsed}s 内返回, 在 10s 超时窗口内"
    elif (( elapsed >= 25 )); then
        fail 6 "${elapsed}s 才返回, 触发 curl max-time 而非 pool 超时 — bug 仍存在"
    else
        note "${elapsed}s 返回 (上游连得通?)"
        skip 6 "无法判断, 服务端可能没真正关掉"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Bug 5: DJB2 哈希 overflow panic (长域名)
# ════════════════════════════════════════════════════════════════════
test_bug5() {
    section "Bug 5: DJB2 哈希 overflow panic (长域名远程崩溃)"
    if [[ -z "$(client_pid)" ]]; then
        skip 5 "客户端未运行"; return
    fi
    local pid_before=$(client_pid)
    note "客户端 PID=$pid_before. 构造 200 字符长域名查询 DNS"

    local LONG=$(printf 'a%.0s' {1..200}).example.com
    timeout 3 dig "@127.0.0.1" -p "$DNS_PORT" "$LONG" >/dev/null 2>&1 || true
    sleep 1
    local pid_after=$(client_pid)

    if [[ "$pid_before" == "$pid_after" ]]; then
        pass 5 "客户端进程仍在 (PID $pid_after), 未 panic"
    else
        fail 5 "客户端进程消失 (旧 PID $pid_before, 新 PID $pid_after) — 可能 panic 重启"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Bug 4: UDP cancel-safety (kill -9 触发 AEAD 帧损坏)
# ════════════════════════════════════════════════════════════════════
test_bug4() {
    section "Bug 4: UDP relay cancel-safety / AEAD 帧损坏"
    if [[ ! -f "$CLIENT_LOG" ]]; then
        skip 4 "需要客户端日志 $CLIENT_LOG (export CLIENT_LOG=路径)"; return
    fi
    note "发 50 次 UDP-over-SOCKS5 DNS 查询 + kill -9 中断, 监测客户端 log 是否出现 bad record mac"

    local marker_count_before=$(grep -c -E "bad record mac|decryption failed|MAC|TLS alert" "$CLIENT_LOG" 2>/dev/null || echo 0)
    for i in {1..50}; do
        timeout 1 curl --socks5-hostname "$SOCKS_HOST" -s "https://1.1.1.1/dns-query?name=example.com&type=A" \
            -H "accept: application/dns-json" >/dev/null 2>&1 &
        local subpid=$!
        sleep 0.05
        kill -9 $subpid 2>/dev/null || true
    done
    sleep 2
    local marker_count_after=$(grep -c -E "bad record mac|decryption failed|MAC|TLS alert" "$CLIENT_LOG" 2>/dev/null || echo 0)
    local delta=$(( marker_count_after - marker_count_before ))

    if (( delta == 0 )); then
        pass 4 "未出现新的 AEAD 错误日志 (cancel-safety OK)"
    else
        fail 4 "出现 $delta 条新 AEAD 错误日志, 可能 cancel-safety 未修复"
        grep -E "bad record mac|decryption failed" "$CLIENT_LOG" | tail -3 | sed 's/^/      /'
    fi
}

# ════════════════════════════════════════════════════════════════════
# Bug 3: TCP relay 30 分钟僵尸泄露 — 需要服务端 FD 监控配合
# ════════════════════════════════════════════════════════════════════
test_bug3() {
    section "Bug 3: TCP relay 30 分钟僵尸泄露 (服务端 FD 监控)"
    note "服务端机器请提前跑监控 (任选其一):"
    note "  方式 A: watch -n 5 'ls /proc/\$(pgrep -f mirage.*server)/fd | wc -l'"
    note "  方式 B: while true; do echo \"\$(date +%T) FD=\$(ls /proc/\$(pgrep -f mirage.*server)/fd|wc -l)\"; sleep 5; done"
    [[ "$(prompt '服务端 FD 监控已起? (y 继续 / n 跳过):')" =~ ^[yY] ]] || { skip 3 "用户跳过"; return; }

    note "客户端发起 100 次 kill -9 curl (模拟弱网闪断), 服务端 FD 应在波动后回落而不是单调上涨"
    for i in {1..100}; do
        timeout 2 curl --max-time 2 -x "$SOCKS_PROXY" -s -o /dev/null https://www.youtube.com 2>&1 &
        local subpid=$!
        sleep 0.2
        kill -9 $subpid 2>/dev/null || true
    done
    wait 2>/dev/null
    note "100 次 churn 已发送. 服务端 FD 在接下来 1 分钟内观察:"
    note "  - 修复后: FD 立刻回落到 baseline (因为 libc::shutdown 让 download 立刻退出)"
    note "  - 修复前: FD 涨 +50/+100 并维持 30 分钟才回落"
    sleep 60
    [[ "$(prompt '服务端 FD 是否在 1 分钟内回落? (y=回落了 / n=还在高位):')" =~ ^[yY] ]] && \
        pass 3 "服务端 FD 在 1 分钟内回落" || fail 3 "FD 未回落, bug 仍存在"
}

# ════════════════════════════════════════════════════════════════════
# Bug 2: GeoUpdater 启动时序空隙 — 需要重启客户端
# ════════════════════════════════════════════════════════════════════
test_bug2() {
    section "Bug 2: GeoUpdater + ConfigWatcher 启动时序"
    note "前置: config 已配 geo_sources + routing 引用 geosite/geoip 规则"
    note "测试流程: 删 .dat 文件 → 重启客户端 → 等 60s 看是否自动 hot-reload"
    [[ "$(prompt '继续? 这会重启客户端 (y/n):')" =~ ^[yY] ]] || { skip 2 "用户跳过"; return; }

    note "删除 $GEO_DIR/*.dat..."
    sudo rm -f "$GEO_DIR"/*.dat 2>/dev/null || rm -f "$GEO_DIR"/*.dat 2>/dev/null || true

    note "请手动重启客户端 (systemctl restart mirage-client 或 kill+再启), 等启动后回车继续"
    prompt "客户端重启完成?"

    if [[ ! -f "$CLIENT_LOG" ]]; then
        skip 2 "无 $CLIENT_LOG"; return
    fi

    note "等 60 秒让 geo_updater 下载 + ConfigWatcher 检测..."
    sleep 60

    local has_watcher=$(grep -E "Also watching geodata dir" "$CLIENT_LOG" | tail -1)
    local has_download=$(grep -E "GeoUpdater: Successfully updated" "$CLIENT_LOG" | tail -1)
    local has_reload=$(grep -E "Watched path .*\.dat changed|Hot-reload successful" "$CLIENT_LOG" | tail -1)

    if [[ -n "$has_watcher" && -n "$has_download" && -n "$has_reload" ]]; then
        pass 2 "watcher 起 + 下载成功 + hot-reload 触发, 全链路 OK"
    else
        fail 2 "链路不完整:"
        [[ -z "$has_watcher" ]]  && echo "      缺 'Also watching geodata dir' 日志"
        [[ -z "$has_download" ]] && echo "      缺 'Successfully updated' 日志"
        [[ -z "$has_reload" ]]   && echo "      缺 'Hot-reload successful' 日志 ← 关键 bug 复现"
    fi
}

# ════════════════════════════════════════════════════════════════════
# Bug 1: WarmPool 空闲期缩容 — 需要 DEBUG 日志 + 5 分钟等待
# ════════════════════════════════════════════════════════════════════
test_bug1() {
    section "Bug 1: WarmPool 空闲期缩容 (需要 DEBUG 日志 + 5 分钟等待)"
    if [[ ! -f "$CLIENT_LOG" ]]; then
        skip 1 "需要客户端 RUST_LOG=debug 启动 + 日志路径"; return
    fi

    note "制造 50 并发流量把 pool target 拉高..."
    for i in {1..50}; do
        curl --max-time 5 -x "$SOCKS_PROXY" -s -o /dev/null https://www.google.com &
    done
    wait
    local peak=$(grep -E "WarmPool Manager: target .* → [0-9]+" "$CLIENT_LOG" | tail -1)
    note "峰值日志: ${peak:-未发现, RUST_LOG 可能不是 debug}"

    note "停止所有流量, 等 5 分钟让 idle 缩容触发..."
    sleep 300

    local shrinks=$(grep -E "WarmPool Manager: target [0-9]+ → [0-9]+" "$CLIENT_LOG" | \
        awk -F'[ →]+' 'NF >= 8 { from=$5; to=$6; if (to < from) print $0 }')

    if [[ -n "$shrinks" ]]; then
        pass 1 "发现缩容日志:"
        echo "$shrinks" | tail -3 | sed 's/^/      /'
    else
        fail 1 "无缩容日志, target 可能仍锁死 (bug 未修)"
    fi
}

# ─────────── 主流程 ───────────
main() {
    local args="${1:-menu}"
    local tests=()

    case "$args" in
        all)   tests=(6 5 4 3 2 1) ;;  # 从快到慢
        quick) tests=(6 5 4) ;;         # 全自动的 3 个
        menu)
            echo
            echo "Mirage-rs v0.4.4-alpha.3 bug 修复验证"
            echo "  快速 (Bug 6/5/4, 全自动 ~5 分钟)        : quick"
            echo "  全套 (含 Bug 1/2/3, 需手动 ~10 分钟)    : all"
            echo "  指定 (空格分隔 bug 号, 例 '6 4')        : 自由输入"
            local sel=$(prompt "选择 (默认 quick):")
            sel="${sel:-quick}"
            case "$sel" in
                quick) tests=(6 5 4) ;;
                all)   tests=(6 5 4 3 2 1) ;;
                *)     tests=($sel) ;;
            esac
            ;;
        *) tests=("$@") ;;
    esac

    for t in "${tests[@]}"; do
        case "$t" in
            1) test_bug1 ;;
            2) test_bug2 ;;
            3) test_bug3 ;;
            4) test_bug4 ;;
            5) test_bug5 ;;
            6) test_bug6 ;;
            *) echo "未知 bug 号: $t" ;;
        esac
    done

    section "汇总"
    for r in "${RESULTS[@]}"; do
        case "$r" in
            PASS*) echo -e "  ${C_PASS}${r}${C_END}" ;;
            FAIL*) echo -e "  ${C_FAIL}${r}${C_END}" ;;
            SKIP*) echo -e "  ${C_WARN}${r}${C_END}" ;;
        esac
    done

    local fail_count=$(printf '%s\n' "${RESULTS[@]}" | grep -c '^FAIL' || true)
    [[ "$fail_count" -gt 0 ]] && exit 1 || exit 0
}

main "$@"
