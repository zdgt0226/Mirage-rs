#!/usr/bin/env bash
# install.sh UI helper 单元护甲 (old-coder gauntlet: B1-B4)。
# 零依赖纯 bash。source install.sh (靠 source-guard 不跑 main) 后断言 UI 函数。
# 失败退非零。用法: bash tests/install_ui_test.sh
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INSTALL_SH="${SCRIPT_DIR}/install.sh"
ESC=$'\033'

PASS=0 FAIL=0
ok_()   { PASS=$((PASS+1)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
bad_()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n     want: %q\n     got:  %q\n' "$1" "${2-}" "${3-}"; }
eq_()   { if [[ "$2" == "$3" ]]; then ok_ "$1"; else bad_ "$1" "$3" "$2"; fi; }   # name expected actual
has_()  { if [[ "$2" == *"$3"* ]]; then ok_ "$1"; else bad_ "$1" "*$3*" "$2"; fi; }
no_()   { if [[ "$2" != *"$3"* ]]; then ok_ "$1"; else bad_ "$1" "NOT *$3*" "$2"; fi; }
# 在 pty 下 (即 -t 2 为真) 取 _init_color 算出的 USE_COLOR, 使 NO_COLOR 成为唯一变量。
# 非 tty 环境下 USE_COLOR 恒 0, NO_COLOR 分支测不出真伪, 故必须借 pty 隔离。
pty_color() { script -qec "bash -c 'source \"$INSTALL_SH\"; printf %s \"\$USE_COLOR\"'" /dev/null 2>/dev/null | tr -d '\r\n'; }

# ── B3: source-guard (先验, 因为其余测试都靠 source 安全性) ──────────────
# 安全: 绝不 source 会跑真 main 的东西。用中和 main 的临时副本证明 guard 效果 + 控制可红。
section_b3() {
    echo "[B3] source-guard"
    local tmp_guard tmp_noguard
    tmp_guard=$(mktemp); tmp_noguard=$(mktemp)
    # 中和副本: 无害 main + install.sh 的真实 guard 块
    cat > "$tmp_guard" <<'EOF'
main() { echo "__MAIN_RAN__"; }
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi
EOF
    # 无 guard 变体 (无条件调) —— 证明检测能红 (负向控制)
    cat > "$tmp_noguard" <<'EOF'
main() { echo "__MAIN_RAN__"; }
main "$@"
EOF
    local out_guard out_noguard
    # shellcheck disable=SC1090
    out_guard=$(source "$tmp_guard" 2>&1)
    # shellcheck disable=SC1090
    out_noguard=$(source "$tmp_noguard" 2>&1)
    has_ "B3.ctrl 负向控制: 无 guard → main 运行 (检测可红)" "$out_noguard" "__MAIN_RAN__"
    no_  "B3.1  guard 存在 → source 不跑 main" "$out_guard" "__MAIN_RAN__"
    rm -f "$tmp_guard" "$tmp_noguard"

    # 真 install.sh: source 后不应有 main 的首行输出, 且 _c 可调
    local real_out
    # shellcheck disable=SC1090
    real_out=$(source "$INSTALL_SH" 2>&1; echo "__SOURCED_OK__")
    has_ "B3.2  真 install.sh source 返回成功" "$real_out" "__SOURCED_OK__"
    no_  "B3.3  真 install.sh source 不跑 main (无 init 探测输出)" "$real_out" "检测到 init 系统"
}

# 把真 install.sh 的函数引进本测试 shell (guard 阻止 main; 随后关 -e 免 set -e 干扰)。
load_install() {
    # shellcheck disable=SC1090
    source "$INSTALL_SH"
    set +e +u +o pipefail
}

# ── B1: _c 颜色自动关闭 (tty / NO_COLOR 感知), 配色值不变 ────────────────
section_b1() {
    echo "[B1] _c 颜色门控"
    eq_ "B1.1  USE_COLOR=1 → _c 加 ANSI"        "$(USE_COLOR=1 _c 32 hi)" "${ESC}[32mhi${ESC}[0m"
    eq_ "B1.2  USE_COLOR=0 → _c 纯文本"          "$(USE_COLOR=0 _c 32 hi)" "hi"
    no_ "B1.2b USE_COLOR=0 → 无 ESC 字节"        "$(USE_COLOR=0 _c 31 X)"  "$ESC"
    # B1.3 NO_COLOR 存在即关 (pty 下 -t 2 为真, 隔离出 NO_COLOR 是唯一决定因素)
    eq_ "B1.3  pty + NO_COLOR=1 → 0"      "$(NO_COLOR=1  pty_color)" "0"
    eq_ "B1.3b pty + NO_COLOR='' → 0"     "$(NO_COLOR="" pty_color)" "0"
    # B1.6 pty + 未设 NO_COLOR → 1 (开色正路的正向检测)
    eq_ "B1.6  pty + 未设 NO_COLOR → 1"   "$(unset NO_COLOR; pty_color)" "1"
    # B1.4 stderr 非 tty → 关 (fd2 指到 /dev/null 即非 tty; 本测试进程本身即非 tty)
    if ( unset NO_COLOR; _init_color 2>/dev/null; [[ "${USE_COLOR:-x}" == 0 ]] ); then ok_ "B1.4  stderr 非 tty → USE_COLOR=0"; else bad_ "B1.4  stderr 非 tty → USE_COLOR=0" 0 "?"; fi
    # B1.5 配色值不变
    eq_ "B1.5a info=36"  "$(USE_COLOR=1 info X 2>&1)"  "${ESC}[36m[*]${ESC}[0m X"
    eq_ "B1.5b ok=32"    "$(USE_COLOR=1 ok X 2>&1)"    "${ESC}[32m[✓]${ESC}[0m X"
    eq_ "B1.5c warn=33"  "$(USE_COLOR=1 warn X 2>&1)"  "${ESC}[33m[!]${ESC}[0m X"
    has_ "B1.5d title=1;35" "$(USE_COLOR=1 title T 2>&1)" "${ESC}[1;35m"
}

# ── B2: ask_choice 默认项标记 (渲染与 IO 分离; 测纯渲染函数) ─────────────
section_b2() {
    echo "[B2] _render_choice 默认标记"
    local out; out=$(USE_COLOR=0 _render_choice "选操作" A B C 2>&1)
    has_ "B2.1  第 1 项标 (默认)"     "$out" "1) A (默认)"
    no_  "B2.2  第 2 项不带 (默认)"   "$(printf '%s\n' "$out" | grep '2)')" "(默认)"
    has_ "B2.3a 选项 3 正常渲染"      "$out" "3) C"
}

# ── B4: info/ok/warn/err/title 格式契约 (回归护甲, USE_COLOR=0 看结构) ───
section_b4() {
    echo "[B4] tag 格式契约"
    eq_ "B4.1a info → [*]"  "$(USE_COLOR=0 info hi 2>&1)"  "[*] hi"
    eq_ "B4.1b ok → [✓]"    "$(USE_COLOR=0 ok hi 2>&1)"    "[✓] hi"
    eq_ "B4.1c warn → [!]"  "$(USE_COLOR=0 warn hi 2>&1)"  "[!] hi"
    local ec; (USE_COLOR=0 err boom 2>/dev/null); ec=$?
    eq_ "B4.2  err 退出码=1"  "$ec" "1"
    eq_ "B4.2b err → [✗]"    "$(USE_COLOR=0 bash -c "source '$INSTALL_SH'; err boom" 2>&1 || true)" "[✗] boom"
    local t; t=$(USE_COLOR=0 title T 2>&1)
    local nlines; nlines=$(printf '%s\n' "$t" | grep -c '═') || true
    eq_ "B4.3  title 有 2 条 ═ 分隔线" "$nlines" "2"
    has_ "B4.3b title 含标题文字" "$t" "T"
}

# ── B5: 服务端上游出口改写 (apply_server_upstream / server_upstream_summary) ──
section_b5() {
    echo "[B5] 服务端上游出口改写"
    command -v python3 >/dev/null 2>&1 || { echo "  SKIP (无 python3)"; return; }
    local d full lite out
    d=$(mktemp -d); full="$d/config_server.json"; lite="$d/lite_server.json"
    cat > "$full" <<'JSON'
{ "inbounds": [
    { "type": "mirage_server", "tag": "t", "port": 443, "password": "p" },
    { "type": "mirage_server", "tag": "q", "port": 443, "password": "p", "transport": "quic" },
    { "type": "socks", "tag": "s", "port": 1080 } ] }
JSON
    printf '{ "port": 443, "password": "p" }\n' > "$lite"
    local ss='{ "type": "shadowsocks", "server": "192.0.2.1", "server_port": 8388, "password": "x", "method": "aes-256-gcm", "udp": "block" }'
    local wg='{ "type": "wireguard", "private_key": "a", "peer_public_key": "b", "endpoint": "198.51.100.1:51820", "address": "10.0.0.2", "mtu": 1420, "udp": "tunnel" }'

    has_ "B5.1  初始无上游 → 直连" "$(server_upstream_summary "$full")" "直连"
    eq_  "B5.2  完整版只改 TCP mirage_server 入站 (1 个)" "$(apply_server_upstream "$full" "$ss")" "1"
    out=$(python3 -c 'import json,sys; ib=json.load(open(sys.argv[1]))["inbounds"]; print([("upstream" in i) for i in ib])' "$full")
    eq_  "B5.3  QUIC / socks 入站不被写入上游" "$out" "[True, False, False]"
    has_ "B5.4  摘要显示 SS 上游" "$(server_upstream_summary "$full")" "Shadowsocks 192.0.2.1:8388"
    eq_  "B5.5  改写后文件权限 600" "$(stat -c %a "$full")" "600"
    apply_server_upstream "$full" "$wg" >/dev/null
    has_ "B5.6  替换为 WG 上游" "$(server_upstream_summary "$full")" "WireGuard 198.51.100.1:51820"
    apply_server_upstream "$full" "" >/dev/null
    has_ "B5.7  空串 → 移除上游恢复直连" "$(server_upstream_summary "$full")" "直连"
    eq_  "B5.8  轻量版写顶层" "$(apply_server_upstream "$lite" "$ss")" "1"
    out=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["upstream"]["server"])' "$lite")
    eq_  "B5.9  轻量版顶层 upstream 落盘" "$out" "192.0.2.1"
    printf '{ "inbounds": [ { "type": "mirage_server", "transport": "quic" } ] }\n' > "$d/q.json"
    apply_server_upstream "$d/q.json" "$ss" >/dev/null 2>&1
    eq_  "B5.10 无可配入站 → 非零退出" "$?" "1"
    no_  "B5.11 无可配入站 → 文件不动" "$(cat "$d/q.json")" "upstream"

    # ── 新增: 迁移旧入站 upstream ──
    apply_server_upstream "$full" "$ss" >/dev/null
    eq_  "B5.12 迁移旧入站 upstream 成功" "$(server_migrate_legacy_upstream "$full")" "1"
    out=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print([("upstream" in i) for i in d["inbounds"]])' "$full")
    eq_  "B5.13 迁移后入站不再包含 upstream" "$out" "[False, False, False]"
    out=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["routing"]["default_outbound"])' "$full")
    eq_  "B5.14 迁移后默认出站不变 (其它入站行为保持)" "$out" "direct"
    out=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["routing"]["rules"][0])' "$full")
    eq_  "B5.14b 迁移为按入站 tag 的前插规则" "$out" "{'inbound': ['t'], 'outbound': 'ss-up'}"

    # ── 新增: 顶层出站增删与规则管理 ──
    local wg_ob='{ "type": "wireguard", "tag": "wg-up", "private_key": "a", "peer_public_key": "b", "endpoint": "198.51.100.1:51820", "address": "10.0.0.2", "mtu": 1420, "udp": "tunnel" }'
    server_add_outbound "$full" "$wg_ob" >/dev/null
    out=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print([o["tag"] for o in d["outbounds"]])' "$full")
    has_ "B5.15 新增 WG 顶层出站成功" "$out" "wg-up"

    server_set_default_outbound "$full" "wg-up" >/dev/null
    out=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["routing"]["default_outbound"])' "$full")
    eq_  "B5.16 设置默认出站成功" "$out" "wg-up"

    local rule='{ "domain_suffix": ["example.com"], "outbound": "wg-up" }'
    server_add_rule "$full" "$rule" >/dev/null
    out=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d["routing"]["rules"]))' "$full")
    eq_  "B5.17 新增分流规则成功 (迁移规则 + 新规则)" "$out" "2"

    server_remove_outbound "$full" "wg-up" >/dev/null
    out=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print([o["tag"] for o in d["outbounds"]])' "$full")
    no_  "B5.18 删除出站成功" "$out" "wg-up"
    out=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(d["routing"]["default_outbound"])' "$full")
    eq_  "B5.19 引用被删出站的 default 自动回退为 direct" "$out" "direct"
    out=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(len(d["routing"]["rules"]))' "$full")
    eq_  "B5.20 引用被删出站的规则自动被清理 (只剩迁移规则)" "$out" "1"

    # ── 新增: 密码与密钥自动生成 ──
    local psk_32
    psk_32=$(generate_wg_psk)
    eq_  "B5.21 generate_wg_psk 生成 32 字节 base64" "${#psk_32}" "44"
    local ss_pw_32 ss_pw_16
    ss_pw_32=$(generate_ss_password 32)
    eq_  "B5.22 generate_ss_password 32 生成 44 字符" "${#ss_pw_32}" "44"
    ss_pw_16=$(generate_ss_password 16)
    eq_  "B5.23 generate_ss_password 16 生成 24 字符" "${#ss_pw_16}" "24"

    # ── stage_and_commit: 校验不过时正式配置一字不动; 通过才替换并留 .bak ──
    local sc="$d/stage.json" fake="$d/fake-check"
    printf '{ "inbounds": [ { "type": "mirage_server", "tag": "t" } ] }\n' > "$sc"
    local before; before=$(cat "$sc")
    printf '#!/bin/sh\nexit 1\n' > "$fake"; chmod +x "$fake"
    BIN_PATH="$fake" stage_and_commit "$sc" server_set_default_outbound "x" >/dev/null 2>&1
    eq_  "B5.24 check 失败 → 返回 2" "$?" "2"
    eq_  "B5.25 check 失败 → 正式配置不变" "$(cat "$sc")" "$before"
    printf '#!/bin/sh\nexit 0\n' > "$fake"
    BIN_PATH="$fake" stage_and_commit "$sc" server_set_default_outbound "x" >/dev/null 2>&1
    eq_  "B5.26 check 通过 → 返回 0" "$?" "0"
    has_ "B5.27 通过后已写入" "$(cat "$sc")" '"default_outbound": "x"'
    eq_  "B5.28 通过后留 .bak 为原内容" "$(cat "$sc.bak")" "$before"
    eq_  "B5.29 无残留临时文件" "$(ls "$d" | grep -c 'stage.json.new')" "0"
    server_add_outbound "$sc" '{ "type": "block", "tag": "direct" }' >/dev/null 2>&1
    eq_  "B5.30 不允许覆盖 direct 出站" "$?" "1"
    server_remove_outbound "$sc" "direct" >/dev/null 2>&1
    eq_  "B5.31 不允许删除 direct 出站" "$?" "1"

    rm -rf "$d"
}

echo "== install.sh UI 护甲 =="
section_b3
load_install
section_b1
section_b2
section_b4
section_b5
echo "----"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
