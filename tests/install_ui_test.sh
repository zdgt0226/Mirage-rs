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
    # B1.3 NO_COLOR 存在即关 (含空串)。子 shell 继承 sourced 的 _init_color; NO_COLOR 供其读取。
    # shellcheck disable=SC2034
    if ( NO_COLOR=1;  _init_color; [[ "${USE_COLOR:-x}" == 0 ]] ); then ok_ "B1.3  NO_COLOR=1 → USE_COLOR=0"; else bad_ "B1.3  NO_COLOR=1 → USE_COLOR=0" 0 "?"; fi
    # shellcheck disable=SC2034
    if ( NO_COLOR=""; _init_color; [[ "${USE_COLOR:-x}" == 0 ]] ); then ok_ "B1.3b NO_COLOR='' (空串) → USE_COLOR=0"; else bad_ "B1.3b NO_COLOR='' → USE_COLOR=0" 0 "?"; fi
    # B1.4 stderr 非 tty → 关 (fd2 指到 /dev/null 即非 tty)
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

echo "== install.sh UI 护甲 =="
section_b3
load_install
section_b1
section_b2
section_b4
echo "----"
printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
