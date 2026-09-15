#!/usr/bin/env bash
# 手工变异: 对 install.sh 的 B1/B2 关键逻辑逐个植入已知 bug, 断言 tests/install_ui_test.sh
# 能杀掉每个 (退非零)。用后 git 恢复, restore 可核。
#
# fail-closed: 目标串没匹配上 (变异没改文件) / 变异存活 (测试没杀) / restore 失败 → 硬失败退非零。
# 不变异 source-guard: 那会让 source 跑真 main (危险); guard 由测试的中和副本控制验证。
# 变异目标是 shell 字面片段, 内含 ${...} 是**故意不展开** (原样传给 python 做字面替换)。
# shellcheck disable=SC2016
set -uo pipefail
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" || exit 1

if [[ -n "$(git status --porcelain install.sh)" ]]; then
    echo "ERROR: install.sh 有未提交改动; 变异用 git 恢复, 前置须干净。"; exit 1
fi

FAILS=0

# 字面替换 (python, 避开 sed/perl 元字符); 目标串不存在 → 退 3 (fail-closed)。
apply_mutant() {
    python3 - "$1" "$2" "$3" <<'PY'
import sys
path, a, b = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
if a not in s:
    sys.exit(3)
open(path, "w").write(s.replace(a, b))
PY
}

mutate() {
    local name=$1 desc=$2 from=$3 to=$4 rc
    apply_mutant install.sh "$from" "$to"; rc=$?
    if [[ "$rc" -ne 0 ]]; then
        echo "  ERROR $name: 目标串未匹配 (rc=$rc) — fail-closed"; FAILS=$((FAILS+1))
        git checkout -q -- install.sh; return
    fi
    if git diff --quiet -- install.sh; then
        echo "  ERROR $name: 变异未改动文件 — fail-closed"; FAILS=$((FAILS+1))
        git checkout -q -- install.sh; return
    fi
    if bash tests/install_ui_test.sh >/dev/null 2>&1; then
        echo "  SURVIVED $name: $desc — 测试没杀掉! (suite 有盲点)"; FAILS=$((FAILS+1))
    else
        echo "  KILLED   $name: $desc"
    fi
    git checkout -q -- install.sh
    if ! git diff --quiet -- install.sh; then echo "  ERROR $name: restore 失败"; exit 1; fi
}

echo "== 手工变异 (install.sh B1/B2) =="
mutate M1 "_c 恒上色 (忽略 USE_COLOR)"    '"${USE_COLOR:-1}" == 1'      '1 == 1'
mutate M2 "_init_color 忽略 NO_COLOR"      '-z "${NO_COLOR+x}"'          '-z ""'
mutate M3 "_render_choice 丢默认标记"      'mark=" (默认)"'              'mark=""'
mutate M4 "_render_choice 全项标默认"      '(( i == 0 )) && mark=" (默认)"'  'mark=" (默认)"'
mutate M5 "_c 恒纯文本 (从不上色)"        '"${USE_COLOR:-1}" == 1'      '"${USE_COLOR:-1}" == 2'
echo "----"
if [[ "$FAILS" -eq 0 ]]; then
    echo "全部变异被杀 (suite 非空转)"
else
    echo "$FAILS 个变异存活/出错"
fi
[[ "$FAILS" -eq 0 ]]
