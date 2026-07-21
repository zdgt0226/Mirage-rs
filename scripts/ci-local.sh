#!/usr/bin/env bash
# 本地跑一遍 CI (.github/workflows/build.yml 的镜像)。
#
# 为什么要有它: feature 分支 (如 feat/wireguard) **不触发任何 workflow** —— build.yml 只认
# main 的 push 和指向 main 的 PR。在分支上开发时本地跑是从 0 到 1, 不是替代 CI。
#
# ⚠️ 本地绿 ≠ CI 绿, 有两件事本地**测不到**:
#   1. 内核版本。CI 故意跑 ubuntu-22.04 (内核 5.15) 来检验 README 的 "≥5.10" 声明,
#      本地通常是更新的内核。build.yml 里就记着实例: orphan 验证器本地 6.1 稳定绿、
#      CI 5.15 一路红。本地 eBPF 全绿**证明不了 5.15 能用**。
#   2. 干净环境。本地有热 target/ 和早就装好的系统库, catch 不到"漏声明的依赖"。
# 所以: 本地当快速反馈环, CI 当合并闸门。
#
# 用法:
#   scripts/ci-local.sh          # 全跑 (含 eBPF netns 验证器, 需 root)
#   scripts/ci-local.sh --fast   # 只跑 build/check/test, 跳过 eBPF (不需 root)

set -uo pipefail
cd "$(dirname "$0")/.."

FAST=0
[ "${1:-}" = "--fast" ] && FAST=1

FAILED=()
run_step() {
    local name="$1"; shift
    echo
    echo "── $name ──────────────────────────────────────────"
    if "$@"; then
        echo "✅ $name"
    else
        echo "❌ $name"
        FAILED+=("$name")
    fi
}

echo "内核: $(uname -r)   (CI 用的是 5.15 —— 本地绿不代表 CI 绿)"

# ── job: build ──
run_step "Build"                 cargo build --verbose
run_step "Check with ebpf feature" cargo check --features ebpf --verbose
run_step "Run tests"             cargo test --verbose

# ── job: ebpf-verify ──
if [ "$FAST" = "1" ]; then
    echo
    echo "⏭  跳过 eBPF netns 验证器 (--fast)"
elif [ "$(id -u)" != "0" ]; then
    echo
    echo "⏭  跳过 eBPF netns 验证器: 需要 root (用 sudo 重跑, 或 --fast 明确跳过)"
    FAILED+=("eBPF 验证器未跑 (非 root)")
else
    run_step "Build eBPF examples" cargo build --features ebpf --examples --verbose
    # 与 build.yml 保持一致: 每个验证器单独一步, 失败时一眼看出哪个内核机制断了。
    # 注: verify_tc_divert_orphan.sh 在 CI 里是摘掉的 (5.15 上的测试脚手架竞态),
    # 但本地内核 ≥6.1 上可跑且含双向变异防护, 所以这里跑它。
    run_step "tc_divert — 裸-IP UDP sk_assign + LPM 直连分流" bash examples/verify_tc_divert.sh
    run_step "tc_divert TCP — 透明 local_addr 分水岭"          bash examples/verify_tc_divert_tcp.sh
    run_step "tc_divert 孤儿过滤器 (CI 里摘掉, 本地跑)"          bash examples/verify_tc_divert_orphan.sh
    run_step "cgroup/connect4 — 本机出向重定向 + origdst 还原"   bash examples/verify_cgroup_connect.sh
    run_step "sk_lookup UDP 透明 — origdst + 回包源伪造"        bash examples/verify_udp_transparent.sh
    run_step "XDP 极速 DNS — 收发改包 + 哈希一致"               bash examples/verify_dns_xdp.sh
fi

echo
echo "════════════════════════════════════════════════════"
if [ ${#FAILED[@]} -eq 0 ]; then
    echo "✅ 全部通过"
    echo "   提醒: 本地内核 $(uname -r), CI 是 5.15 —— 合并前仍以 CI 为准。"
    exit 0
fi
echo "❌ 失败 ${#FAILED[@]} 项:"
printf '   - %s\n' "${FAILED[@]}"
exit 1
