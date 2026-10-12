#!/usr/bin/env bash
# ==============================================================================
# phase5-analyze.sh —— Phase-5 复测结果分析器（**只读**）
#
# 对应 docs/plan-phase5-verification.md：§4 判据已预注册，本脚本只做算术与判决，
# 不改判据、不碰测试环境、不联网、不写仓库（临时文件在 mktemp -d，退出即清理）。
#
# 用法：
#   phase5-analyze.sh k      <baseline探针输出> <mirage探针输出> <mirage服务端日志>
#   phase5-analyze.sh tiers  <探针输出4个target> <日志A> <日志B> <日志C>
#   phase5-analyze.sh gap750 <探针输出(authsucc,gap750)> <日志A> <日志B> <日志C>
#   phase5-analyze.sh t3     <探针输出(badauth,authsucc)> <服务端日志>
#   phase5-analyze.sh count  <服务端日志> <匹配模式> <期望条数>
#
# 依赖：bash 4+、awk（**mawk 兼容**，不用 gawk 的 asort/排序扩展）、sort、grep、paste。
# ==============================================================================
set -euo pipefail

USAGE="用法:
  $0 k      <baseline探针> <mirage探针> <mirage日志>      # P5-1 常数 K
  $0 tiers  <探针(4 target)> <日志A> <日志B> <日志C>        # P5-3b 档位模型核对
  $0 gap750 <探针(authsucc gap750)> <日志A> <日志B> <日志C> # P5-3a ①自洽/E9/2b率
  $0 t3     <探针(badauth,authsucc)> <日志>                # P5-4 自校准复算
  $0 count  <日志> <匹配模式> <期望条数>                    # P5-5 回归计数
说明: 探针输出 = probe_close_timing 的 stdout; 日志 = 服务端(MIRAGE_QUIET_MEASURE=1) stdout。"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
export LC_ALL=C

die() { echo "✗ $*" >&2; exit 2; }

# ── 通用工具 ────────────────────────────────────────────────────────────────

# 探针输出里按出现顺序列出 target（去重）
targets_of() {
  awk '/^=== target=/ { t=$0; sub(/^=== target=/,"",t); sub(/ mode=.*$/,"",t)
        if (!(t in seen)) { seen[t]=1; print t } }' "$1"
}

# 抽某 target × 某 label 的逐样本值（顺序不变，一行一个）
samples_of() {
  awk -v wt="$2" -v wl="$3" '
    /^=== target=/ { t=$0; sub(/^=== target=/,"",t); sub(/ mode=.*$/,"",t); cur=t; ins=0; next }
    /^  [A-Za-z_]+: / { lab=$0; sub(/^  /,"",lab); sub(/:.*/,"",lab); ins=(cur==wt && lab==wl); next }
    ins && /^    samples:/ { sub(/^    samples: /,""); for (i=1;i<=NF;i++) print $i; ins=0 }
  ' "$1"
}

# 从日志抽字段（默认全部行；$3 = grep -E 过滤）
log_field() { grep -aE "${3:-.}" "$1" | grep -aoE "$2=[0-9-]+" | sed "s/^$2=//" || true; }
# 同上，但字段可为 `2a/2b/1/0` 这类非纯数字
log_chr()   { grep -aE "${3:-.}" "$1" | grep -aoE "$2=[0-9a-z-]+" | sed "s/^$2=//" || true; }

# 中位数 / 四分位（stdin: 一行一个数）
stats_of() {
  sort -n | awk '{a[NR]=$1} END{
    if (NR==0) { print "n=0 med=nan iqr=nan"; exit }
    med=(NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2
    p25=a[int((NR-1)*0.25)+1]; p75=a[int((NR-1)*0.75)+1]
    printf "n=%d med=%.1f p25=%.1f p75=%.1f iqr=%.1f\n", NR, med, p25, p75, p75-p25 }'
}
med_of() {
  sort -n | awk '{a[NR]=$1} END{ if (NR==0){print "nan"; exit}
    printf "%.1f", (NR%2)?a[(NR+1)/2]:(a[NR/2]+a[NR/2+1])/2 }'
}
# 中位数 bootstrap 95% CI（stdin: 一行一个数；$1 = 重采样次数，默认 2000；固定种子可复现）
boot_median_ci() {
  local iters="${1:-2000}"
  awk -v iters="$iters" '{v[++n]=$1} END{
    if (n==0) { print "ci95=[nan, nan]"; exit }
    srand(20261011)
    for (b=0;b<iters;b++) {
      for (i=1;i<=n;i++) r[i]=v[int(rand()*n)+1]
      for (i=2;i<=n;i++) { x=r[i]; j=i-1; while (j>=1 && r[j]>x) { r[j+1]=r[j]; j-- } r[j+1]=x }
      print (n%2)?r[(n+1)/2]:(r[n/2]+r[n/2+1])/2
    } }' | sort -n |
  awk -v iters="$iters" '{c[NR]=$1} END{ printf "ci95=[%.1f, %.1f]", c[int(iters*0.025)+1], c[int(iters*0.975)+1] }'
}
# Wilson 95% 区间（$1=成功数, $2=总数）
wilson() {
  awk -v k="${1:-0}" -v n="${2:-0}" 'BEGIN{
    if (n<=0) { print "p=nan wilson95=[nan, nan]"; exit }
    z=1.959964; p=k/n; d=1+z*z/n
    c=(p+z*z/(2*n))/d; h=z*sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    printf "p=%.1f%% wilson95=[%.1f%%, %.1f%%]", p*100, (c-h)*100, (c+h)*100 }'
}
# 判据判决：$1=值 $2=PASS阈值 $3=WEAK阈值（按绝对值）
verdict() { awk -v v="$1" -v a="$2" -v b="$3" 'BEGIN{ av=(v<0?-v:v); printf "%s", (av<=a?"PASS":(av<=b?"WEAK":"FAIL")) }'; }
# 条数一致性守卫（R9：实例须专供探针）
need_eq() {
  [ "$1" = "$2" ] || die "$3 计数不一致 ($1 vs $2) —— 见规范 R9/R7（实例非独占流量 / --cap 截断 / 忘 MIRAGE_QUIET_MEASURE=1）"
}
# 非空守卫（防静默给出错误数值）
req_n() { [ "$(n_of "$1")" -gt 0 ] || die "$2 为空 —— 检查日志过滤条件 / MIRAGE_QUIET_MEASURE=1 / 探针是否真跑过"; }
n_of() { printf '%s' "$1" | wc -w | tr -d ' '; }

# 服务端启动日志里的 ① 参数：输出 "mult min_ms max_ms"
guard_params() {
  { grep -am1 "ClientHello 守卫" "$1" || true; } |
    sed -n 's/.*预连 \([0-9]\{1,\}\)×RTT (\(clamp \)\{0,1\}\([0-9]\{1,\}\)~\([0-9]\{1,\}\)ms).*/\1 \3 \4/p' || true
}

# ── P5-1：同连接常数 K ──────────────────────────────────────────────────────
cmd_k() {
  [ $# -eq 3 ] || die "k 需要 3 个参数"
  local base="$1" mpri="$2" mlog="$3"
  local bt mt
  bt="$(targets_of "$base" | head -1)"; mt="$(targets_of "$mpri" | head -1)"
  [ -n "$bt" ] && [ -n "$mt" ] || die "探针输出里找不到 target 段"

  local bc bcm mc mcm rd_raw mrd
  bc="$(samples_of "$base" "$bt" close_ms)";  bcm="$(samples_of "$base" "$bt" connect_ms)"
  mc="$(samples_of "$mpri" "$mt" close_ms)";  mcm="$(samples_of "$mpri" "$mt" connect_ms)"
  rd_raw="$(log_field "$mlog" pc_ready_us 'outcome=fallback')"
  need_eq "$(n_of "$bc")" "$(n_of "$bcm")" "baseline close/connect"
  need_eq "$(n_of "$mc")" "$(n_of "$mcm")" "mirage close/connect"
  need_eq "$(n_of "$mc")" "$(n_of "$rd_raw")" "mirage close / pc_ready_us(outcome=fallback)"
  req_n "$bcm" "baseline connect_ms"; req_n "$mcm" "mirage connect_ms"
  req_n "$rd_raw" "pc_ready_us(outcome=fallback)"
  mrd="$(printf '%s\n' $rd_raw | med_of)"
  # 注: 工具输出的 samples: 行是**排序后**的，且 close 与 connect 各自独立排序，
  # 因此不做逐样本配对，改用"中位数分项"口径（与规范 §P5-1 一致）。
  # 排序配对下的中位数恰等于边际中位数之差，故点估计不变。
  local bzc mzc med_close_b med_close_m
  bzc="$(paste <(printf '%s\n' $bc) <(printf '%s\n' $bcm)  | awk '{printf "%.1f\n", $1-$2}' | med_of)"
  mzc="$(paste <(printf '%s\n' $mc) <(printf '%s\n' $mcm)  | awk '{printf "%.1f\n", $1-$2}' | med_of)"
  med_close_b="$(printf '%s\n' $bc | med_of)"; med_close_m="$(printf '%s\n' $mc | med_of)"
  local zk
  zk="$(awk -v a="$mzc" -v b="$bzc" -v r="$mrd" 'BEGIN{printf "%.1f", (a-r/1000)-b}')"
  local ib im
  ib="$(paste <(printf '%s\n' $bc) <(printf '%s\n' $bcm) | awk '{printf "%.1f\n", $1-$2}' | stats_of | sed 's/.*iqr=//')"
  im="$(paste <(printf '%s\n' $mc) <(printf '%s\n' $mcm) | awk '{printf "%.1f\n", $1-$2}' | stats_of | sed 's/.*iqr=//')"

  echo "== P5-1 同连接常数 K（中位数分项口径）=="
  echo "  baseline target=$bt : p50(close)=${med_close_b}ms  med(close−connect)=${bzc}ms"
  echo "  mirage   target=$mt : p50(close)=${med_close_m}ms  med(close−connect)=${mzc}ms  med(pc_ready)=${mrd}us"
  echo "  K = med(close−connect)_mirage − med(pc_ready) − med(close−connect)_base = ${zk}ms"
  echo "  判据: |K| ≤50 PASS / ≤150 WEAK / >150 FAIL  → $(verdict "$zk" 50 150)"
  echo "  参考(非判据): IQR(close−connect) base=${ib}ms  mirage=${im}ms（排序配对，仅参考）"
}

# ── P5-3b：三档同会话 Δ 与 ready 的模型核对 ─────────────────────────────────
cmd_tiers() {
  [ $# -eq 4 ] || die "tiers 需要 4 个参数"
  local pri="$1"; shift
  local logs=("$@")
  mapfile -t T < <(targets_of "$pri")
  [ "${#T[@]}" -eq 4 ] || die "tiers 需要 4 个 target（baseline + A + B + C），实际 ${#T[@]}"

  local bclose; bclose="$(samples_of "$pri" "${T[0]}" close_ms)"
  local bc;      bc="$(samples_of "$pri" "${T[0]}" connect_ms)"
  need_eq "$(n_of "$bclose")" "$(n_of "$bc")" "baseline close/connect"
  printf '%s\n' $bclose | med_of > "$TMP/base_close"
  paste <(printf '%s\n' $bclose) <(printf '%s\n' $bc) | awk '{printf "%.1f\n", $1-$2}' > "$TMP/zbase"
  local base_close zbase; base_close="$(cat "$TMP/base_close")"; zbase="$(med_of < "$TMP/zbase")"

  echo "== P5-3b 三档同会话（baseline=${T[0]}，p50(close_base)=${base_close}ms, med(Z_base)=${zbase}ms）=="
  local names=(A B C) i decl_d=() ready=() delta=()
  for i in 1 2 3; do
    local lg="${logs[$((i-1))]}"
    local cl rd st
    cl="$(samples_of "$pri" "${T[$i]}" close_ms)"
    rd="$(log_field "$lg" pc_ready_us 'outcome=fallback')"
    need_eq "$(n_of "$cl")" "$(n_of "$rd")" "${names[$((i-1))]} close/pc_ready_us"
    req_n "$rd" "${names[$((i-1))]} pc_ready_us(outcome=fallback)"
    local mc_r; mc_r="$(med_of <<< "$(printf '%s\n' $cl)")"
    local md;   md="$(awk -v a="$mc_r" -v b="$base_close" 'BEGIN{printf "%.1f", a-b}')"
    local mr;   mr="$(printf '%s\n' $rd | awk '{printf "%.1f\n", $1/1000}' | med_of)"
    st="$(printf '%s\n' $rd | awk '{printf "%.1f\n", $1/1000}' | stats_of)"
    delta[$i]="$md"; ready[$i]="$mr"
    echo "  档 ${names[$((i-1))]}: p50(close)=${mc_r}ms  Δ=${md}ms  median(pc_ready)=${mr}ms  [$st]"
    echo "         rtt_us/fire_us: rtt med=$(log_field "$lg" rtt_us 'outcome=fallback' | med_of)us  fire med=$(log_field "$lg" pc_fire_us 'outcome=fallback' | med_of)us"
  done

  local g1 g2 nw
  g1="$(awk -v a="${delta[3]}" -v b="${delta[2]}" -v r3="${ready[3]}" -v r2="${ready[2]}" 'BEGIN{printf "%.1f", (a-b)-(r3-r2)}')"
  g2="$(awk -v a="${delta[2]}" -v b="${delta[1]}" -v r2="${ready[2]}" -v r1="${ready[1]}" 'BEGIN{printf "%.1f", (a-b)-(r2-r1)}')"
  echo "  [核心] (Δ_C−Δ_B) − (ready_C−ready_B) = ${g1}ms   → $(verdict "$g1" 100 200)  (判据 ≤100 PASS / ≤200 WEAK)"
  echo "  [辅助] (Δ_B−Δ_A) − (ready_B−ready_A) = ${g2}ms   → $(verdict "$g2" 100 200)"
  nw="$(awk -v db="${delta[2]}" -v dc="${delta[3]}" -v da="${delta[1]}" 'BEGIN{ printf "%s", ((db<=dc+50) && ((db-da<0?da-db:db-da)<=100)) ? "PASS" : "FAIL" }')"
  echo "  [不劣性] Δ_B ≤ Δ_C+50 且 |Δ_B−Δ_A| ≤100 → ${nw}"
}

# ── P5-3a：authsucc + gap=750（①自洽 / E9 口径 / 2b 率） ─────────────────────
cmd_gap750() {
  [ $# -eq 4 ] || die "gap750 需要 4 个参数"
  local pri="$1"; shift
  local logs=("$@")
  mapfile -t T < <(targets_of "$pri")
  [ "${#T[@]}" -eq 3 ] || die "gap750 需要 3 个 target（A/B/C），实际 ${#T[@]}"

  echo "== P5-3a authsucc gap=750ms =="
  local names=(A B C) i
  for i in 0 1 2; do
    local lg="${logs[$i]}"
    local gp mult mn mx
    gp="$(guard_params "$lg")"
    if [ -n "$gp" ]; then read -r mult mn mx <<< "$gp"; else die "日志 $lg 里没有 'ClientHello 守卫' 行（启动日志缺失）"; fi
    local rd fr rt chr mgap pc
    rd="$(log_field "$lg" pc_ready_us 'authed=1')"
    fr="$(log_field "$lg" pc_fire_us  'authed=1')"
    rt="$(log_field "$lg" rtt_us      'authed=1')"
    chr="$(log_field "$lg" ch_read_us 'authed=1')"
    mgap="$(log_field "$lg" max_gap_us 'authed=1')"
    pc="$(log_chr  "$lg" preconnect  'authed=1')"
    local n; n="$(n_of "$rd")"
    req_n "$rd" "${names[$i]} pc_ready_us(authed=1)"; req_n "$chr" "${names[$i]} ch_read_us"; req_n "$mgap" "${names[$i]} max_gap_us"
    need_eq "$n" "$(n_of "$fr")" "${names[$i]} ready/fire"
    need_eq "$n" "$(n_of "$chr")" "${names[$i]} ready/ch_read"
    need_eq "$n" "$(n_of "$mgap")" "${names[$i]} ready/max_gap"
    need_eq "$n" "$(n_of "$pc")" "${names[$i]} ready/preconnect"
    echo "  档 ${names[$i]}: n=${n}  ①参数 ${mult}×RTT clamp ${mn}~${mx}ms"
    echo "         rtt_us  med=$(printf '%s\n' $rt | med_of)  fire_us med=$(printf '%s\n' $fr | med_of)  ready_us med=$(printf '%s\n' $rd | med_of)"
    echo "         preconnect 分布: $(printf '%s\n' $pc | sort | uniq -c | tr '\n' ' ')"

    # ① 自洽：期望 = (rtt_us==0 ? max : clamp(mult*rtt, min, max))，与 pc_fire_us(/1000) 比
    paste <(printf '%s\n' $rt) <(printf '%s\n' $fr) <(printf '%s\n' $pc) |
      awk -v m="$mult" -v lo="$mn" -v hi="$mx" '
        { want = ($1==0) ? hi : $1*m/1000;
          if (want<lo) want=lo; if (want>hi) want=hi;
          if ($3!="2a") { tot++; if (($2/1000-want)<=10 && ($2/1000)<=hi+5) ok++ } }
        END{ if(tot>0) printf "%d/%d (%.1f%%)", ok+0, tot, 100*(ok+0)/tot; else print "n/a(全部2a)" }' > "$TMP/c1"
    echo "         ①自洽(pc_fire≈clamp, ±10ms 且 ≤max+5): $(cat "$TMP/c1")"

    # E9 口径：ch_read_us ≥ 0.9×750ms 且 max_gap_us ≈ 750±100ms
    local c2a c2b
    c2a="$(printf '%s\n' $chr  | awk '{t++; if($1>=675000) ok++} END{printf "%d/%d", ok+0, t+0}')"
    c2b="$(printf '%s\n' $mgap | awk '{t++; d=$1-750000; if(d<0)d=-d; if(d<=100000) ok++} END{printf "%d/%d", ok+0, t+0}')"
    echo "         E9: ch_read_us≥675ms → ${c2a} ｜ |max_gap−750ms|≤100ms → ${c2b}"

    # 2b 率：分母只算 ready_us < max_gap_us 的样本
    paste <(printf '%s\n' $rd) <(printf '%s\n' $mgap) <(printf '%s\n' $pc) |
      awk '{ if ($1 < $2) { tot++; if ($3=="2b") ok++ } }
           END{ printf "%d/%d", ok+0, tot+0; }' > "$TMP/den"
    local k nn; k="$(cut -d/ -f1 "$TMP/den")"; nn="$(cut -d/ -f2 "$TMP/den")"
    echo "         2b 率 (仅 ready<gap): ${k}/${nn}  $(wilson "$k" "$nn")  判据 ≥95% (Wilson 下界 ≥76%)"
  done
}

# ── P5-4：自校准复算 ────────────────────────────────────────────────────────
cmd_t3() {
  [ $# -eq 2 ] || die "t3 需要 2 个参数"
  local pri="$1" lg="$2"
  local as asn
  as="$( { grep -a 'authed=1' "$lg" || true; } | awk '
    { inj=""; fail=""
      for (i=1;i<=NF;i++) { if ($i ~ /^inj_us=/)  { split($i,a,"="); inj=a[2] }
                            if ($i ~ /^fail_us=/) { split($i,b,"="); fail=b[2] } }
      if (inj!="" && fail!="") { tot++; if (inj+0>0 && inj+0==fail+0) ok++ } }
    END{ printf "%d/%d", ok+0, tot+0 }')"
  asn="$(cut -d/ -f2 <<< "$as")"
  [ "$asn" -gt 0 ] || die "日志里没有 authed=1 的 [CH-GUARD] 行 —— 检查 MIRAGE_QUIET_MEASURE=1 与 authsucc 密码（MIRAGE_PROBE_PASSWORD）"

  # 逐样本成对差（工具打印的"配对样本: +12 -3 ..."行）
  local line
  line="$(grep -am1 "配对样本:" "$pri" || true)"
  [ -n "$line" ] || die "探针输出里找不到 '配对样本:' 行（需 --modes badauth,authsucc --interleave）"
  printf '%s\n' "$line" | sed 's/.*配对样本: //' | tr ' ' '\n' | sed 's/^+//' | grep -aE '^-?[0-9]+$' > "$TMP/dt"

  local n med ci iqr outl
  n="$(wc -l < "$TMP/dt" | tr -d ' ')"
  med="$(med_of < "$TMP/dt")"
  ci="$(boot_median_ci 2000 < "$TMP/dt")"
  iqr="$(stats_of < "$TMP/dt" | sed 's/.*iqr=//')"
  outl="$(awk -v m="$med" -v i="$iqr" '{ if ($1 > m+5*i) printf "%s ", $1 }' "$TMP/dt")"

  echo "== P5-4 自校准复算 =="
  echo "  auto 占比 (inj_us == fail_us > 0, 仅 authed=1): ${as}  判据 ≥95% → $(awk -v s="$as" 'BEGIN{split(s,a,"/"); printf "%s", (a[2]>0 && a[1]/a[2]>=0.95)?"PASS":"FAIL"}')"
  echo "  成对差 Δ_T = authsucc − badauth（首字节）: n=${n}  median=${med}ms  ${ci}  IQR=${iqr}ms"
  echo "  |median| ≤50ms → $(verdict "$med" 50 50)"
  echo "  离群(> median+5×IQR): ${outl:-无}"
  echo "  逐样本 Δ_T: $(tr '\n' ' ' < "$TMP/dt")"
}

# ── P5-5：计数 + Wilson ────────────────────────────────────────────────────
cmd_count() {
  [ $# -eq 3 ] || die "count 需要 3 个参数"
  local lg="$1" pat="$2" want="$3"
  local k; k="$(grep -acE "$pat" "$lg" || true)"
  echo "== 计数 =="
  echo "  匹配 '${pat}': ${k} / 期望 ${want}  $(wilson "$k" "$want")"
  [ "$k" = "$want" ] && echo "  → PASS" || echo "  → FAIL (与期望不符)"
}

# ── 分发 ───────────────────────────────────────────────────────────────────
case "${1:-}" in
  k)      shift; cmd_k "$@" ;;
  tiers)  shift; cmd_tiers "$@" ;;
  gap750) shift; cmd_gap750 "$@" ;;
  t3)     shift; cmd_t3 "$@" ;;
  count)  shift; cmd_count "$@" ;;
  -h|--help|"") printf '%s\n' "$USAGE"; [ -z "${1:-}" ] && exit 2 || exit 0 ;;
  *) printf '%s\n' "$USAGE" >&2; exit 2 ;;
esac
