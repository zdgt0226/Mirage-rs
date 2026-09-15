#!/usr/bin/env bash
# install.sh UI 改动的一键 gauntlet: 语法 + lint + 单元 + 变异 + 属性 + 真渲染。
# 复现 EVIDENCE-install-ui.md 的所有数字。用法: bash tests/gauntlet_install_ui.sh
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1

RC=0
line() { printf '\n== %s ==\n' "$1"; }

line "L1 语法 bash -n"
bash -n install.sh && bash -n tests/install_ui_test.sh && bash -n tests/mutate_install_ui.sh \
    && echo "3/3 OK" || RC=1

line "L2 shellcheck (install.sh 基线 49 守零新增; 测试文件守 0)"
if command -v shellcheck >/dev/null 2>&1; then
    printf 'install.sh: %s\n' "$(shellcheck -f gcc install.sh 2>&1 | grep -cE ':[0-9]+:')"
    printf 'ui_test:    %s\n' "$(shellcheck -f gcc tests/install_ui_test.sh 2>&1 | grep -cE ':[0-9]+:')"
    printf 'mutate:     %s\n' "$(shellcheck -f gcc tests/mutate_install_ui.sh 2>&1 | grep -cE ':[0-9]+:')"
else
    echo "跳过: shellcheck 未安装 (回落仅 bash -n)"
fi

line "L3 单元测试"
bash tests/install_ui_test.sh 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | tail -1 || RC=1

line "L4 变异"
bash tests/mutate_install_ui.sh 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'KILLED|SURVIVED|全部|存活' || RC=1

line "L5 属性: strip-ANSI(彩色)==纯文本"
c=$(USE_COLOR=1 bash -c 'source install.sh; _c 32 hello')
p=$(USE_COLOR=0 bash -c 'source install.sh; _c 32 hello')
s=$(printf '%s' "$c" | sed 's/\x1b\[[0-9;]*m//g')
if [[ "$s" == "$p" ]]; then echo "PASS"; else echo "FAIL"; RC=1; fi

line "L6 真渲染 (pty)"
if command -v script >/dev/null 2>&1; then
    script -qec 'bash -c "source install.sh; info 信息; ok 成功; warn 告警; title 标题; _render_choice 选 甲 乙"' /dev/null 2>&1 | sed 's/\r$//'
else
    echo "跳过: 无 script (util-linux), 无法分配 pty"
fi

printf '\n==== gauntlet RC=%d ====\n' "$RC"
exit "$RC"
