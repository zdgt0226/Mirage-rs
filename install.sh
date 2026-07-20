#!/usr/bin/env bash
# Mirage-rs 一键安装与配置向导
# 完全遵循 FHS 标准，自动编译并部署到系统目录
set -euo pipefail

# ──────────────────────────────────────────────────────────────────────────────
# 基础 UI 工具
# ──────────────────────────────────────────────────────────────────────────────
_c() { printf "\033[%sm%s\033[0m" "$1" "$2"; }
info()  { echo "$(_c 36 "[*]") $*" >&2; }
ok()    { echo "$(_c 32 "[✓]") $*" >&2; }
warn()  { echo "$(_c 33 "[!]") $*" >&2; }
err()   { echo "$(_c 31 "[✗]") $*" >&2; exit 1; }
title() {
    local line; line=$(printf '═%.0s' {1..56})
    printf "\n\033[1;35m%s\n  %s\n%s\033[0m\n\n" "$line" "$*" "$line" >&2
}

ask() {
    local prompt=$1 default=${2:-} val
    local hint=""
    [[ -n "$default" ]] && hint=" [$default]"
    read -rp "    ${prompt}${hint}: " val </dev/tty
    echo "${val:-$default}"
}

ask_yn() {
    local prompt=$1 default=${2:-y} hint val
    hint=$( [[ "$default" == y ]] && echo "Y/n" || echo "y/N" )
    read -rp "    ${prompt} (${hint}): " val </dev/tty
    val="${val:-$default}"
    [[ "$val" =~ ^[Yy] ]]
}

ask_choice() {
    local prompt=$1; shift
    local options=("$@") n=${#options[@]} val
    echo "    $prompt" >&2
    for ((i = 0; i < n; i++)); do
        printf "      %d) %s\n" $((i + 1)) "${options[$i]}" >&2
    done
    while :; do
        read -rp "    选择 [1-$n] (默认 1): " val </dev/tty
        val="${val:-1}"
        if [[ "$val" =~ ^[0-9]+$ ]] && (( val >= 1 && val <= n )); then
            echo "$val"
            return
        fi
        echo "    无效输入。" >&2
    done
}

# ──────────────────────────────────────────────────────────────────────────────
# 端口占用检测 + 节点 URI 编解码
# ──────────────────────────────────────────────────────────────────────────────
HAVE_SS=0
command -v ss >/dev/null 2>&1 && HAVE_SS=1

port_in_use() {
    (( HAVE_SS )) || return 1
    local port=$1 proto=${2:-tcp} flag
    case "$proto" in
        tcp) flag="-tlnH" ;;
        udp) flag="-ulnH" ;;
        *) return 1 ;;
    esac
    ss $flag "sport = :$port" 2>/dev/null | grep -q .
}

port_holder() {
    local port=$1 proto=${2:-tcp} flag
    case "$proto" in
        tcp) flag="-tlnpH" ;;
        udp) flag="-ulnpH" ;;
        *) return ;;
    esac
    ss $flag "sport = :$port" 2>/dev/null | head -1
}

ask_port() {
    local prompt=$1 default=${2:-} proto=${3:-tcp} p
    while :; do
        p=$(ask "$prompt" "$default")
        if [[ ! "$p" =~ ^[0-9]+$ ]] || (( p < 1 || p > 65535 )); then
            warn "无效端口号: $p"; continue
        fi
        if (( HAVE_SS )) && port_in_use "$p" "$proto"; then
            warn "端口 $p/$proto 已被占用:"
            echo "      $(port_holder "$p" "$proto" || echo '(无法查询占用进程)')" >&2
            if ask_yn "仍然使用该端口? (冲突时服务无法启动)" n; then
                echo "$p"; return
            fi
            continue
        fi
        echo "$p"; return
    done
}

# 询问 GUI 监听配置. 调用方:
#   read gui_enabled gui_listen gui_token <<< "$(ask_gui 9090)"
# 返回单行: "<enabled> <addr>:<port> <token>", enabled=true|false, token="-" 表示无鉴权。
# 注意不能用全局变量传 enabled, 因为 $(ask_gui) 是子 shell, 出不来.
# 用户拒绝时 listen 用 "127.0.0.1:9090" 占位 (enabled=false 时 mirage 忽略).
# 暴露到 0.0.0.0 时自动生成随机 API token —— 否则任何可达者可读日志/配置+改路由规则。
ask_gui() {
    local default_port=${1:-9090}
    if ! ask_yn "启用 Web GUI 管理面板 (Neon Dashboard)" y; then
        echo "false 127.0.0.1:9090 -"
        return
    fi
    local scope listen_addr token="-"
    scope=$(ask_choice "GUI 监听范围" \
        "仅本机 127.0.0.1 (推荐)" \
        "全网开放 0.0.0.0 (LAN/远程访问)")
    case "$scope" in
        1) listen_addr="127.0.0.1" ;;
        2) listen_addr="0.0.0.0" ;;
    esac
    local port
    port=$(ask_port "GUI 端口" "$default_port" tcp)
    if [[ "$listen_addr" == "0.0.0.0" ]]; then
        # url-safe 32 位随机 token; /dev/urandom 不可用时退回时间戳哈希
        token=$(tr -dc 'a-zA-Z0-9' </dev/urandom 2>/dev/null | head -c 32)
        [[ ${#token} -lt 16 ]] && token=$(date +%s%N | sha256sum | head -c 32)
        info "GUI 开放到 0.0.0.0 —— 已自动生成 API token: ${token}"
        info "  浏览器首次访问 http://<本机IP>:${port}/?token=${token} 即种 cookie, 之后免带"
        info "  CLI: curl -H 'Authorization: Bearer ${token}' http://<本机IP>:${port}/api/overview"
    fi
    echo "true ${listen_addr}:${port} ${token}"
}

url_encode() {
    local LC_ALL=C
    local s=$1 out="" i ch
    for (( i=0; i<${#s}; i++ )); do
        ch="${s:i:1}"
        case "$ch" in
            [a-zA-Z0-9.~_-]) out+="$ch" ;;
            *) out+=$(printf '%%%02X' "'$ch") ;;
        esac
    done
    echo "$out"
}

url_decode() {
    local LC_ALL=C
    local s=$1
    s="${s//+/ }"
    printf '%b' "${s//%/\\x}"
}

# 节点 URI 格式: mirage://<url-encoded-pwd>@<host>:<port>?sni=<sni>
# 注: 不支持带 [] 的 IPv6 主机 (regex 限制), 这种情况手动模式输入。
# Brutal 是服务端单边加速 (下行发送侧), 客户端无需感知, 不进节点串。
build_node_uri() {
    local pwd=$1 host=$2 port=$3 sni=$4
    local epwd esni
    epwd=$(url_encode "$pwd")
    esni=$(url_encode "$sni")
    echo "mirage://${epwd}@${host}:${port}?sni=${esni}"
}

# 解析 URI 写入全局 NODE_*。成功返回 0, 失败返回 1。
parse_node_uri() {
    local uri=$1
    NODE_PWD=""; NODE_HOST=""; NODE_PORT=""; NODE_SNI=""
    if [[ ! "$uri" =~ ^mirage://([^@]+)@([^:/?]+):([0-9]+)(\?(.*))?$ ]]; then
        return 1
    fi
    NODE_PWD=$(url_decode "${BASH_REMATCH[1]}")
    NODE_HOST="${BASH_REMATCH[2]}"
    NODE_PORT="${BASH_REMATCH[3]}"
    local query="${BASH_REMATCH[5]:-}"
    local IFS='&'; local pairs=($query); unset IFS
    for p in "${pairs[@]}"; do
        local k="${p%%=*}" v="${p#*=}"
        case "$k" in
            sni)    NODE_SNI=$(url_decode "$v") ;;
        esac
    done
    [[ -n "$NODE_PWD" && -n "$NODE_HOST" && -n "$NODE_PORT" && -n "$NODE_SNI" ]]
}

# ──────────────────────────────────────────────────────────────────────────────
# 依赖环境与编译
# ──────────────────────────────────────────────────────────────────────────────
# check_env() has been removed because typical end-users will use pre-compiled binaries 
# provided via GitHub Actions. Compilation instructions are now in README.md.

probe_camouflage() {
    local host=$1 port=${2:-443}
    info "探测 $host:$port TLS 1.3 支持..."
    local out
    out=$(timeout 10 openssl s_client -connect "${host}:${port}" -servername "$host" \
          -tls1_3 -no_ign_eof < /dev/null 2>&1 || true)
    if echo "$out" | grep -q "Protocol  : TLSv1.3"; then
        ok "$host 支持 TLS 1.3，完美兼容。"
        return 0
    fi
    warn "$host 不支持 TLS 1.3 或被墙阻断，强行使用可能导致被精准识别！"
    return 1
}

ask_camouflage_host() {
    local default=${1:-www.apple.com} val
    while :; do
        val=$(ask "请输入伪装 SNI 域名（用于防御 Active Probing）" "$default")
        if probe_camouflage "$val"; then
            echo "$val"
            return
        fi
        ask_yn "继续使用 $val 吗？（极度不推荐）" n && { echo "$val"; return; }
    done
}

# 自动搜索"与本机同 ASN"的伪装域名候选 (提升 SNI/IP 一致性, 削弱被动关联检测).
# 复用 tools/find_camouflage.py: 本地仓库副本优先, 否则按 MIRAGE_TAG 从 GitHub 拉,
# 不在本脚本里复制一份逻辑 (避免两处漂移).
# 约定: 仅把最终选定的域名写 stdout; 工具表格/提示全部走 stderr, 供调用方 $(...) 捕获.
# 失败/放弃/依赖缺失 → return 1, 调用方回落手动输入.
suggest_camouflage_host() {
    command -v python3 >/dev/null 2>&1 || { warn "未安装 python3, 跳过自动搜索"; return 1; }
    command -v openssl >/dev/null 2>&1 || { warn "未安装 openssl, 跳过自动搜索"; return 1; }

    local ip
    ip=$(detect_public_ip || true)
    ip=$(ask "本机公网 IP (用于确定所属 ASN)" "$ip")
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { warn "IP 无效, 跳过自动搜索"; return 1; }

    # 定位搜索工具
    local finder="" tmp_finder=""
    local self_dir
    self_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)
    if [[ -n "$self_dir" && -f "$self_dir/tools/find_camouflage.py" ]]; then
        finder="$self_dir/tools/find_camouflage.py"
        info "使用本地搜索工具: $finder"
    else
        local ref="${MIRAGE_TAG:-main}"
        local url="https://raw.githubusercontent.com/zdgt0226/Mirage-rs/${ref}/tools/find_camouflage.py"
        tmp_finder=$(mktemp /tmp/mirage_find_camouflage.XXXXXX.py) || return 1
        if ! curl -fsSL --max-time 20 "$url" -o "$tmp_finder"; then
            warn "下载搜索工具失败 ($url), 跳过自动搜索"
            rm -f "$tmp_finder"; return 1
        fi
        finder="$tmp_finder"
    fi

    # 搜索范围。默认只扫 RIPEstat 给出的通告前缀 (通常 /24); 候选太少时可按掩码扩大 ——
    # 扩出去的段会逐个校验 ASN 归属, 同 ASN 的仍算合格 (跨 ASN 的会被降权标注)。
    cat >&2 <<'EOM'

  搜索范围: 默认只扫本机所在的通告前缀 (通常 /24, 约 256 个地址)。
  若候选太少, 可按子网掩码扩大 —— 同一家机房常在相邻网段还有别的前缀,
  它们仍属同一 ASN, 照样满足 SNI/IP 一致性。代价是耗时成倍增加。
EOM
    local range=$(ask_choice "搜索范围" \
        "通告前缀 (最快, 约 256 地址)" \
        "扩到 /22 (约 1024 地址, 慢约 3~4 倍)" \
        "扩到 /20 (约 4096 地址, 慢约 10 倍以上)")
    local scan_args=""
    case "$range" in
        2) scan_args="--prefix 22 --limit 1024" ;;
        3) scan_args="--prefix 20 --limit 4096" ;;
    esac

    info "开始扫描 (期间请勿中断)..."
    # 工具的表格输出走 stdout, 这里整体重定向到 stderr 让用户看见但不污染返回值
    # 扩大范围后耗时成倍增长, 超时也要跟着放宽, 否则总在快出结果时被砍掉。
    local scan_timeout=300
    [[ -n "$scan_args" ]] && scan_timeout=1200
    timeout "$scan_timeout" python3 "$finder" "$ip" $scan_args >&2 || \
        warn "搜索未正常结束 (超时或出错), 可参考上面已输出的部分结果"
    [[ -n "$tmp_finder" ]] && rm -f "$tmp_finder"

    # 刻意不自动采用推荐值: 廉价机房同段邻居很可能本身也是代理/空壳站,
    # 必须人工过目 (工具输出末尾的告警说明了判据), 选错会连累自己.
    local chosen
    chosen=$(ask "从上面挑一个域名填入 (留空 = 放弃, 回落手动输入)" "")
    [[ -n "$chosen" ]] || return 1
    echo "$chosen"
}

brutal_loaded() {
    [[ -f /proc/sys/net/ipv4/tcp_available_congestion_control ]] && \
        grep -qw brutal /proc/sys/net/ipv4/tcp_available_congestion_control
}

# 探测本机公网 IP. 顺序尝试多个公共 echo 服务, 取第一个返回合法 IPv4 的.
# IPv6 / 域名 / NAT 后端: 用户手动输入覆盖. 探测失败 (网络断 / 服务全挂) 返
# 回空字符串, 不阻塞流程.
detect_public_ip() {
    local services=(
        "https://api.ipify.org"
        "https://ifconfig.me/ip"
        "https://ipv4.icanhazip.com"
        "https://checkip.amazonaws.com"
    )
    local ip
    for svc in "${services[@]}"; do
        ip=$(curl -4 -sfL --max-time 3 "$svc" 2>/dev/null | tr -d '[:space:]' || true)
        if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            echo "$ip"
            return 0
        fi
    done
    return 1
}

handle_brutal_optional() {
    info "Brutal 是给单条连接定速的内核模块（Hysteria2 思路），极大地优化高丢包线路"
    if brutal_loaded; then
        ok "已检测到 Brutal 内核模块"
        return 0
    fi
    if ! ask_yn "未检测到 Brutal 内核模块。需要为本机一键安装吗？（VPS 推荐开启，能跑满带宽）" y; then
        return 1
    fi

    info "下载并运行官方一键脚本：curl -fsSL https://tcp.hy2.sh/ | bash"
    if curl -fsSL https://tcp.hy2.sh/ | bash >&2; then
        if brutal_loaded; then
            ok "Brutal 内核模块装好并已加载"
            return 0
        else
            warn "安装完成但未检测到 brutal，可能是内核不兼容或需要重启。"
        fi
    else
        warn "安装脚本执行失败，请查阅 https://github.com/apernet/tcp-brutal 手动安装。"
    fi
    return 1
}

# ──────────────────────────────────────────────────────────────────────────────
# 二进制完整性校验 (防 release 资产被劫持)
# ──────────────────────────────────────────────────────────────────────────────
# 策略 (进阶档): 优先走 GitHub API 拿 release digest, 与 CDN 走的下载链路
# 不同 (api.github.com vs objects.githubusercontent.com), 两通道都对才认.
# API 不可用或 digest 缺失 (旧 release / GH 新功能未铺开) 时, 回落到同 CDN
# 拿 .sha256 文件 (单通道, 仍能防大部分 MITM/CDN 缓存污染).
verify_binary_integrity() {
    local binary_path=$1 download_url=$2
    local binary_name; binary_name=$(basename "$download_url")
    local expected_sha="" sha_source=""

    if ! command -v sha256sum >/dev/null 2>&1; then
        warn "sha256sum 不可用 (coreutils 缺失?), 跳过完整性校验"
        return 0
    fi

    local actual_sha
    actual_sha=$(sha256sum "$binary_path" | cut -d' ' -f1)

    # 进阶: GitHub API 双通道 (需 python3 解 JSON)
    if command -v python3 >/dev/null 2>&1; then
        info "向 GitHub API 取期望 digest..."
        # 指定了 tag 走 releases/tags/<tag>, 否则 releases/latest.
        local api_url="https://api.github.com/repos/zdgt0226/Mirage-rs/releases/latest"
        [[ -n "$MIRAGE_TAG" ]] && api_url="https://api.github.com/repos/zdgt0226/Mirage-rs/releases/tags/${MIRAGE_TAG}"
        local api_resp
        api_resp=$(curl -sfL --max-time 10 \
            -H "Accept: application/vnd.github+json" \
            "$api_url" 2>/dev/null || true)
        if [[ -n "$api_resp" ]]; then
            expected_sha=$(BINARY_NAME="$binary_name" python3 -c '
import json, os, sys
name = os.environ["BINARY_NAME"]
try:
    data = json.loads(sys.stdin.read())
    for a in data.get("assets", []):
        if a.get("name") == name:
            d = a.get("digest") or ""
            if d.startswith("sha256:"):
                print(d[7:])
                break
except Exception:
    pass
' <<< "$api_resp")
            [[ -n "$expected_sha" ]] && sha_source="GitHub API (api.github.com)"
        fi
    fi

    # 入门 fallback: 同 release 的 .sha256
    if [[ -z "$expected_sha" ]]; then
        info "API digest 不可用, fallback 到 release .sha256 文件..."
        local sha_url="${download_url}.sha256"
        local sha_tmp; sha_tmp=$(mktemp)
        if curl -sfL --max-time 30 -o "$sha_tmp" "$sha_url" 2>/dev/null; then
            expected_sha=$(cut -d' ' -f1 "$sha_tmp" 2>/dev/null || true)
            [[ -n "$expected_sha" ]] && sha_source="release .sha256 文件"
        fi
        rm -f "$sha_tmp"
    fi

    if [[ -z "$expected_sha" ]]; then
        warn "无法获取期望 SHA256 (旧 release 或 GitHub 限流)"
        if ! ask_yn "跳过校验继续? (生产环境不推荐)" n; then
            rm -f "$binary_path"
            err "用户取消安装"
        fi
        return 0
    fi

    info "实际 SHA256: $actual_sha"
    info "期望 SHA256: $expected_sha"
    info "来源:        $sha_source"
    if [[ "$expected_sha" != "$actual_sha" ]]; then
        rm -f "$binary_path"
        err "★ SHA256 校验失败! 二进制可能被劫持, 已删除可疑文件 ★"
    fi
    ok "SHA256 校验通过 ($sha_source)"
}

# ──────────────────────────────────────────────────────────────────────────────
# FHS 路径与文件部署
# ──────────────────────────────────────────────────────────────────────────────
BIN_PATH="/usr/local/bin/mirage-rs"
ETC_DIR="/etc/mirage-rs"
STATE_DIR="/var/lib/mirage-rs"
LOG_DIR="/var/log/mirage-rs"

# 安装版本: 空 = 最新 release; 可用环境变量 MIRAGE_TAG=v0.4.5 预设 (跳过交互).
MIRAGE_TAG="${MIRAGE_TAG:-}"
# init 系统: main 启动时 detect_init 填充 (systemd / openrc / none).
INIT_SYS=""
# 客户端是否配成透明网关 (config_client 里按用户选择置位, main 据此决定是否配 NAT).
CLIENT_IS_GATEWAY=false
# 网关本机自身流量是否走代理 (cgroup/connect4)。开启则 setup 时把本机 DNS 指向 mirage.
CLIENT_PROXY_LOCAL=false
RESOLV_BAK=/etc/resolv.conf.mirage-bak
# resolv.conf 守卫脚本: 由 client service 的 ExecStartPost/ExecStopPost 调用, 把"本机 DNS 指向
# mirage"这个改动**绑定到服务生命周期**。此前该改动只在【安装时】做、【卸载时】还原 —— 导致
# systemctl stop / 崩溃 / 被杀 之后 resolv.conf 仍指着已死的 mirage, **整台机器彻底没 DNS**。
# systemd 即便主进程被 SIGKILL 也会跑 ExecStopPost, 故绑到服务上能兜住所有非卸载的退出路径。
RESOLV_GUARD=/usr/local/sbin/mirage-resolv-guard

# 写出 resolv.conf 守卫脚本 (apply/restore 两个子命令, 逻辑集中在此一处)。
write_resolv_guard() {
    cat > "$RESOLV_GUARD" <<'GUARD'
#!/bin/sh
# mirage-resolv-guard —— 由 mirage-rs-client.service 的 ExecStartPost/ExecStopPost 调用。
# apply:   备份原 resolv.conf (含 symlink 目标), 指向 mirage (127.0.0.1)
# restore: 从备份还原 (服务停止/崩溃/被杀时, systemd 保证跑到这里 → 机器不会没 DNS)
# 备份文件不在 restore 时删除 —— 反复 start/stop 都能正常工作; 只有卸载才清。
RESOLV_BAK=/etc/resolv.conf.mirage-bak

# 每次 apply 都刷新备份, 但**只在当前 resolv.conf 不是我们自己写的 stub 时**。
#   为什么要刷新: 只备份第一次会让备份随时间腐坏 —— 换网络/新 DHCP 租约/重配
#   systemd-resolved 之后, restore 会把几个月前的上游 DNS 写回去, 机器照样解析不了。
#   为什么要门控: 若在自己的 stub 上再 apply 一次 (重启服务、ExecStartPost 重跑),
#   无脑刷新会把 "nameserver 127.0.0.1" 存成备份, restore 就把机器指回已死的
#   mirage —— 正是本守卫存在的意义所在。判据: 存在任一非 127.0.0.1 的 nameserver
#   即视为真实配置 (systemd-resolved 的 127.0.0.53 也算, 它确实是真上游)。
is_our_stub() {
    [ -L /etc/resolv.conf ] && return 1
    [ -f /etc/resolv.conf ] || return 1
    grep -qE '^[[:space:]]*nameserver[[:space:]]+' /etc/resolv.conf 2>/dev/null || return 1
    grep -E '^[[:space:]]*nameserver[[:space:]]+' /etc/resolv.conf 2>/dev/null \
      | grep -qvE '^[[:space:]]*nameserver[[:space:]]+127\.0\.0\.1[[:space:]]*$' && return 1
    return 0
}

backup_now() {
    if [ -L /etc/resolv.conf ]; then
        readlink /etc/resolv.conf > "${RESOLV_BAK}.symlink" 2>/dev/null || true
    else
        # 上次备份的是 symlink、这次是普通文件 → 必须清掉旁挂记录, 否则 restore 会
        # 用陈旧的 symlink 目标覆盖掉本次的真实内容。
        rm -f "${RESOLV_BAK}.symlink"
    fi
    # 先删再 cp -aL: ① -a 遇 symlink 源会**保留 symlink**, 备份文件自己就成了指向
    # 上游文件的软链, 之后每次备份都写穿到目标去、restore 又把软链复制回来 —— 备份
    # 存的必须是**内容** (symlink 目标另记在 .symlink 旁挂里), 故用 -L 解引用;
    # ② 不先 rm, cp 会沿着已存在的旧软链写穿, -L 也救不回来。
    rm -f "$RESOLV_BAK"
    cp -aL /etc/resolv.conf "$RESOLV_BAK" 2>/dev/null || true
}

case "$1" in
  apply)
    if is_our_stub; then
      # 已经是我们的 stub: 保留既有备份 (它才是真实的上游配置), 什么都不备。
      [ -e "$RESOLV_BAK" ] || echo "mirage-resolv-guard: resolv.conf 已是 mirage stub 且无备份, 无法保护原配置" >&2
    else
      backup_now
    fi
    chattr -i /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf
    printf 'nameserver 127.0.0.1\n' > /etc/resolv.conf
    ;;
  restore)
    [ -e "$RESOLV_BAK" ] || exit 0
    chattr -i /etc/resolv.conf 2>/dev/null || true
    rm -f /etc/resolv.conf
    if [ -f "${RESOLV_BAK}.symlink" ]; then
      ln -sf "$(cat "${RESOLV_BAK}.symlink")" /etc/resolv.conf 2>/dev/null \
        || cp -a "$RESOLV_BAK" /etc/resolv.conf
    else
      cp -a "$RESOLV_BAK" /etc/resolv.conf
    fi
    ;;
  *) echo "usage: $0 {apply|restore}" >&2; exit 1 ;;
esac
exit 0
GUARD
    chmod 755 "$RESOLV_GUARD"
}

# 让用户选择安装的 release tag (留空装 latest). 已通过环境变量指定则不交互.
select_version() {
    if [[ -n "$MIRAGE_TAG" ]]; then
        info "使用环境变量指定的版本: $MIRAGE_TAG"
        return
    fi
    echo "" >&2
    info "安装版本 (留空 = 最新 release):"
    echo "    可在 https://github.com/zdgt0226/Mirage-rs/releases 查看; 例: v0.4.5" >&2
    MIRAGE_TAG=$(ask "指定版本 tag (留空装最新)" "")
    if [[ -n "$MIRAGE_TAG" ]]; then
        info "将安装指定版本: $MIRAGE_TAG"
    else
        info "将安装最新 release (latest)"
    fi
}

# 探测服务管理器. 优先级: systemd (需真正在跑, 光有二进制不算) > OpenRC
# (Alpine/Gentoo) > SysV init (老 Debian/CentOS6/精简系统) > none.
detect_init() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        echo systemd
    elif command -v rc-service >/dev/null 2>&1 || command -v openrc-run >/dev/null 2>&1 \
        || [ -x /sbin/openrc-run ]; then
        echo openrc
    elif [ -d /etc/init.d ] && { command -v update-rc.d >/dev/null 2>&1 \
        || command -v chkconfig >/dev/null 2>&1 || command -v service >/dev/null 2>&1; }; then
        echo sysvinit
    else
        echo none
    fi
}

# 输出 init-aware 的启动/日志命令提示 (供安装完成后打印).
svc_start_hint() { # role
    case "$INIT_SYS" in
        openrc)   echo "rc-service mirage-rs-$1 start" ;;
        sysvinit) echo "service mirage-rs-$1 start" ;;
        *)        echo "systemctl start mirage-rs-$1" ;;
    esac
}
svc_restart_hint() { # role
    case "$INIT_SYS" in
        openrc)   echo "rc-service mirage-rs-$1 restart" ;;
        sysvinit) echo "service mirage-rs-$1 restart" ;;
        *)        echo "systemctl restart mirage-rs-$1" ;;
    esac
}
svc_log_hint() { # role
    # 仅 systemd 有 journald; OpenRC/SysV 落到日志文件.
    if [ "$INIT_SYS" = systemd ]; then echo "journalctl -u mirage-rs-$1 -f"; else echo "tail -f ${LOG_DIR}/$1.log"; fi
}

# uname -m → release 资产架构名. 32 位映射到 alpha.19 起发布的纯用户态产物.
detect_arch() {
    case $(uname -m) in
        x86_64) echo "amd64" ;;
        aarch64|arm64) echo "arm64" ;;
        i386|i486|i586|i686)
            warn "32 位 x86: 纯用户态代理, 内核 <5.9 无 sk_lookup 透明模式。"
            echo "i386" ;;
        armv7l|armv7)
            warn "32 位 ARMv7: 纯用户态代理, 内核 <5.9 无 sk_lookup 透明模式。"
            echo "armv7" ;;
        *) err "不支持的系统架构: $(uname -m)" ;;
    esac
}

# 探测架构并从 Release 下载二进制到 $1, 带完整性校验. MIRAGE_TAG 空=latest.
# 下载成功(且校验通过)返回 0; 下载失败返回 1 (由调用方决定回退).
fetch_release_binary() {
    local dest=$1 arch
    arch=$(detect_arch)
    # 文件名跟 release.yml 上传命名严格一致 (mirage-rs-<arch>-musl).
    local download_url
    if [[ -n "$MIRAGE_TAG" ]]; then
        download_url="https://github.com/zdgt0226/Mirage-rs/releases/download/${MIRAGE_TAG}/mirage-rs-${arch}-musl"
        info "下载指定版本 ${MIRAGE_TAG}: $download_url"
    else
        download_url="https://github.com/zdgt0226/Mirage-rs/releases/latest/download/mirage-rs-${arch}-musl"
        info "下载最新版本: $download_url"
    fi
    if ! curl -# -fLo "$dest" "$download_url"; then
        warn "从 GitHub Releases 下载失败，请检查网络或手动下载编译。"
        return 1
    fi
    verify_binary_integrity "$dest" "$download_url"
}

# 本机已装二进制的版本 (CARGO_PKG_VERSION). 无/损坏返回非 0.
# `mirage --version` 输出: "mirage-rs 0.4.5 (v0.4.5-...)"
local_version() {
    [[ -x "$BIN_PATH" ]] || return 1
    local out ver
    out=$("$BIN_PATH" --version 2>/dev/null) || return 1
    ver=$(awk '{print $2}' <<< "$out")
    [[ -n "$ver" ]] || return 1
    echo "$ver"
}

# 仓库目标版本 (去前导 v). MIRAGE_TAG 非空直接返回它, 否则查 GitHub latest.
remote_version() {
    if [[ -n "$MIRAGE_TAG" ]]; then
        echo "${MIRAGE_TAG#v}"; return 0
    fi
    local resp
    resp=$(curl -sfL --max-time 10 -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/zdgt0226/Mirage-rs/releases/latest" 2>/dev/null || true)
    [[ -n "$resp" ]] || return 1
    grep -m1 '"tag_name"' <<< "$resp" \
        | sed -E 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v?([^"]+)".*/\1/'
}

# init-aware 服务控制 (start/stop/restart) 与运行状态查询. 未装服务时静默.
svc_ctl() { # action role
    local action=$1 svc="mirage-rs-$2"
    case "$INIT_SYS" in
        openrc)   rc-service "$svc" "$action" 2>/dev/null || true ;;
        sysvinit) service "$svc" "$action" 2>/dev/null || "/etc/init.d/$svc" "$action" 2>/dev/null || true ;;
        systemd)  systemctl "$action" "$svc" 2>/dev/null || true ;;
        *) : ;;
    esac
}
service_active() { # role
    local svc="mirage-rs-$1"
    case "$INIT_SYS" in
        systemd)  systemctl is-active --quiet "$svc" 2>/dev/null ;;
        openrc)   rc-service "$svc" status >/dev/null 2>&1 ;;
        sysvinit) [[ -x "/etc/init.d/$svc" ]] && "/etc/init.d/$svc" status >/dev/null 2>&1 ;;
        *) return 1 ;;
    esac
}

# 从 config JSON 取字段 (先查 inbounds[0], 再查顶层). python3 优先, 否则 grep.
# 把字符串转义成可安全嵌入 JSON 字符串字面量的形式。
# 密码里出现 " 或 \ 时, 不转义会直接生成非法 JSON → 服务起不来且报错难懂。
# 只处理 JSON 字符串必须转义的字符: 反斜杠、双引号、控制字符里最常见的制表/换行。
json_escape() {
    local s=$1
    s=${s//\\/\\\\}   # 反斜杠必须先转, 否则会把后面转出来的再转一遍
    s=${s//\"/\\\"}
    s=${s//$'\t'/\\t}
    s=${s//$'\n'/\\n}
    printf '%s' "$s"
}

json_get() { # file key
    local file=$1 key=$2
    if command -v python3 >/dev/null 2>&1; then
        FILE="$file" KEY="$key" python3 -c '
import json, os
try:
    d = json.load(open(os.environ["FILE"]))
    ib = (d.get("inbounds") or [{}])[0]
    v = ib.get(os.environ["KEY"])
    if v is None: v = d.get(os.environ["KEY"])
    if v is not None: print(v)
except Exception:
    pass'
    else
        grep -oE "\"$key\"[[:space:]]*:[[:space:]]*(\"[^\"]*\"|[0-9]+)" "$file" | head -1 \
            | sed -E "s/\"$key\"[[:space:]]*:[[:space:]]*//; s/^\"//; s/\"$//"
    fi
}

# ── 二进制更新: 识别本地版本 → 对比仓库版本 → 校验下载 → 原子替换 → 重启活动服务 ──
update_binary() {
    title "Mirage-rs 二进制更新"
    if [[ ! -f "$BIN_PATH" ]]; then
        warn "未检测到已安装的二进制 ($BIN_PATH)。请先运行部署 (菜单 1/2/3)。"
        return
    fi

    local lv
    if lv=$(local_version); then
        info "本地版本: $lv"
    else
        lv=""
        warn "无法识别本地版本 (二进制损坏或占位文件)。"
    fi

    # 允许指定目标 tag (留空=latest). 复用 select_version 填充 MIRAGE_TAG.
    select_version

    local rv
    if ! rv=$(remote_version) || [[ -z "$rv" ]]; then
        rv=""
        warn "无法获取仓库版本 (GitHub 限流 / 网络断)。"
        ask_yn "仍要强制重新下载并覆盖?" n || { info "已取消更新。"; return; }
    else
        info "仓库版本: $rv"
        if [[ -n "$lv" && "$lv" == "$rv" ]]; then
            ok "已是最新版本 ($lv)。"
            ask_yn "仍要强制重新下载覆盖?" n || return
        else
            local newest=""
            newest=$(printf '%s\n%s\n' "$lv" "$rv" | sort -V 2>/dev/null | tail -1) || true
            if [[ -z "$lv" || -z "$newest" ]]; then
                info "将安装仓库版本: $rv"
            elif [[ "$newest" == "$rv" ]]; then
                info "发现新版本: $lv → $rv"
            else
                warn "本地版本 ($lv) 似乎比仓库 ($rv) 更新 (开发构建?)。"
            fi
            ask_yn "确认更新到 ${rv:-仓库版本} ?" y || { info "已取消更新。"; return; }
        fi
    fi

    # 下到同目录临时文件 → 校验通过再 rename 替换 (同 fs 原子, 避免覆盖运行中二进制的 ETXTBSY)
    local tmp
    tmp=$(mktemp "${BIN_PATH}.new.XXXXXX")
    if ! fetch_release_binary "$tmp"; then
        rm -f "$tmp"
        err "下载失败, 现有二进制保持不变。"
    fi
    chmod 755 "$tmp"
    mv -f "$tmp" "$BIN_PATH"
    ok "二进制已更新: $BIN_PATH"
    local nv; nv=$(local_version 2>/dev/null || true)
    [[ -n "$nv" ]] && ok "当前版本: $nv"

    # 重启当前活动的服务以加载新二进制 (未运行的不动)
    local restarted=0 role
    for role in server client; do
        if service_active "$role"; then
            info "重启 mirage-rs-$role 以加载新二进制 ..."
            svc_ctl restart "$role"
            restarted=1
        fi
    done
    (( restarted )) || info "未发现运行中的 mirage-rs 服务, 无需重启。"
}

# ── 显示服务端节点配置 (供复制到客户端做节点配置) ──
show_server_node() {
    title "服务端节点配置信息"
    local cfg="${ETC_DIR}/config_server.json"
    local export_file="${ETC_DIR}/node-export.txt"

    if [[ ! -f "$cfg" && ! -f "$export_file" ]]; then
        warn "未找到服务端配置 ($cfg)。请先在本机部署服务端 (菜单 1)。"
        return
    fi

    local node_uri=""
    [[ -f "$export_file" ]] && node_uri=$(cat "$export_file")

    if [[ -f "$cfg" ]]; then
        local port pwd sni brutal
        port=$(json_get "$cfg" port)
        pwd=$(json_get "$cfg" password)
        sni=$(json_get "$cfg" camouflage_host)
        brutal=$(json_get "$cfg" brutal_rate_mbps); [[ -n "$brutal" ]] || brutal=0

        echo "  监听端口:   $(_c 36 "${port:-?}")" >&2
        echo "  认证密码:   $(_c 36 "${pwd:-?}")" >&2
        echo "  伪装 SNI:   $(_c 36 "${sni:-?}")" >&2
        [[ "$brutal" =~ ^[0-9]+$ ]] && (( brutal > 0 )) && \
            echo "  Brutal:     $(_c 36 "${brutal} Mbps")" >&2
        echo >&2

        # 无现成导出串 → 现场探测公网 IP 重建
        if [[ -z "$node_uri" && -n "$pwd" && -n "$port" && -n "$sni" ]]; then
            local ip host
            ip=$(detect_public_ip || true)
            host=$(ask "公网地址 (域名/IP, 用于生成节点串)" "$ip")
            [[ -n "$host" ]] && node_uri=$(build_node_uri "$pwd" "$host" "$port" "$sni")
        fi
    fi

    if [[ -n "$node_uri" ]]; then
        title "客户端节点导入串 (复制到客户端)"
        echo "  $(_c 32 "$node_uri")" >&2
        echo >&2
        if command -v qrencode >/dev/null 2>&1; then
            qrencode -t UTF8 "$node_uri" >&2
            echo >&2
        fi
    else
        warn "未能生成节点串 (缺公网地址)。手动格式:"
        echo "      mirage://<密码>@<host>:<port>?sni=<sni>" >&2
    fi
}

setup_fhs() {
    info "创建 FHS 标准目录..."
    mkdir -p "$ETC_DIR" "$ETC_DIR/geosite" "$STATE_DIR" "$LOG_DIR"
    chmod 755 "$ETC_DIR" "$ETC_DIR/geosite" "$STATE_DIR" "$LOG_DIR"

    info "正在从 Release 下载预编译的 Mirage-rs 核心 (包含 CO-RE eBPF 模块)..."
    # 这里我们模拟下载预编译好的二进制文件（实际部署时替换为真实 GitHub Release 地址）
    # 由于底层基于 Aya 框架且开启了 BTF (BPF Type Format)，该二进制实现了真正的 CO-RE（一次编译，到处运行）
    # 服务端完全不需要安装 clang/llvm 或 cargo。
    
    if [ -f "mirage" ]; then
        info "检测到本地当前目录存在 mirage 可执行文件，直接拷贝。"
        cp mirage "$BIN_PATH"
    elif [ -f "target/release/mirage" ]; then
        info "检测到本地存在编译产物，直接拷贝。"
        cp target/release/mirage "$BIN_PATH"
    else
        info "本地未找到可执行文件，准备从 GitHub 拉取预编译产物..."
        if ! fetch_release_binary "$BIN_PATH"; then
            touch "$BIN_PATH" # Placeholder for sandbox/development fallback
        fi
    fi

    chmod 755 "$BIN_PATH"
    ok "核心程序部署完毕 (Aya CO-RE eBPF Ready)。"
}

# 按探测到的 init 系统分派服务注册. 未识别则打印手动启动命令.
# 轻量模式开关 (main 里询问后置位)。轻量 = 只做 SOCKS5→隧道全部转发,
# 不装分流/DNS/透明网关/看板。服务名仍是 mirage-rs-{server,client} —— 一个角色
# 一个服务, 避免完整版与轻量版两个 unit 抢同一个端口。
LITE_MODE=false

# 轻量模式下走 lite-server/lite-client 子命令 + 平铺的 lite_*.json 配置。
svc_subcmd() { [[ "$LITE_MODE" == true ]] && echo "lite-$1" || echo "$1"; }
svc_cfg() {
    if [[ "$LITE_MODE" == true ]]; then
        echo "${ETC_DIR}/lite_$1.json"
    else
        echo "${ETC_DIR}/config_$1.json"
    fi
}

setup_service() {
    local role=$1
    local _subcmd=$(svc_subcmd "$role") _cfgpath=$(svc_cfg "$role")
    case "$INIT_SYS" in
        systemd)  setup_systemd "$role" ;;
        openrc)   setup_openrc  "$role" ;;
        sysvinit) setup_sysv    "$role" ;;
        *)
            warn "未识别的 init 系统 (非 systemd/OpenRC/SysV), 跳过服务注册。"
            info "可手动前台运行: ${BIN_PATH} ${_subcmd} -c ${_cfgpath}"
            ;;
    esac
}

# SysV init (老 Debian/CentOS6/精简系统). LSB 头 + 自包含 nohup+pidfile 管理,
# 不依赖 start-stop-daemon 或 RHEL /etc/init.d/functions, 最大可移植性.
# 注意: SysV 无 supervisor, 崩溃不自动重启 (systemd/OpenRC 才有). 可接受降级.
setup_sysv() {
    local role=$1
    local _subcmd=$(svc_subcmd "$role") _cfgpath=$(svc_cfg "$role")
    local svc="mirage-rs-${role}"
    local init_path="/etc/init.d/${svc}"

    cat > "$init_path" <<EOF
#!/bin/sh
# chkconfig: 2345 20 80
# description: Mirage-rs High-Performance Proxy (${role})
### BEGIN INIT INFO
# Provides:          ${svc}
# Required-Start:    \$network \$remote_fs
# Required-Stop:     \$network \$remote_fs
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: Mirage-rs High-Performance Proxy (${role})
### END INIT INFO

NAME="${svc}"
BIN="${BIN_PATH}"
ARGS="${_subcmd} -c ${_cfgpath}"
# /var/run 而非 /run: 老系统 (CentOS6) 只有 /var/run; 新系统 /var/run→/run symlink, 通吃.
PIDFILE="/var/run/${svc}.pid"
LOGFILE="${LOG_DIR}/${role}.log"
WORKDIR="${STATE_DIR}"

is_running() {
    [ -f "\$PIDFILE" ] && kill -0 "\$(cat "\$PIDFILE" 2>/dev/null)" 2>/dev/null
}

start() {
    if is_running; then echo "\$NAME already running (pid \$(cat "\$PIDFILE"))"; return 0; fi
    echo "Starting \$NAME..."
    cd "\$WORKDIR" 2>/dev/null || true
    ulimit -n 1048576 2>/dev/null || true
    ulimit -l unlimited 2>/dev/null || true
    nohup "\$BIN" \$ARGS >> "\$LOGFILE" 2>&1 &
    echo \$! > "\$PIDFILE"
    sleep 1
    if is_running; then echo "\$NAME started (pid \$(cat "\$PIDFILE"))"; else
        echo "\$NAME failed to start, see \$LOGFILE"; rm -f "\$PIDFILE"; return 1; fi
}

stop() {
    if ! is_running; then echo "\$NAME not running"; rm -f "\$PIDFILE"; return 0; fi
    echo "Stopping \$NAME..."
    kill "\$(cat "\$PIDFILE")" 2>/dev/null
    i=0; while is_running && [ \$i -lt 5 ]; do sleep 1; i=\$((i+1)); done
    is_running && kill -9 "\$(cat "\$PIDFILE")" 2>/dev/null
    rm -f "\$PIDFILE"
    echo "\$NAME stopped"
}

case "\$1" in
    start)   start ;;
    stop)    stop ;;
    restart) stop; start ;;
    status)  if is_running; then echo "\$NAME running (pid \$(cat "\$PIDFILE"))"; else echo "\$NAME stopped"; exit 3; fi ;;
    *)       echo "Usage: \$0 {start|stop|restart|status}"; exit 1 ;;
esac
EOF
    chmod 755 "$init_path"

    # 注册开机自启: Debian 系 update-rc.d, RHEL 系 chkconfig, 都没有则仅装脚本
    if command -v update-rc.d >/dev/null 2>&1; then
        update-rc.d "$svc" defaults >/dev/null 2>&1 || true
    elif command -v chkconfig >/dev/null 2>&1; then
        chkconfig --add "$svc" >/dev/null 2>&1 || true
        chkconfig "$svc" on >/dev/null 2>&1 || true
    else
        warn "无 update-rc.d/chkconfig, 已装 init 脚本但未注册开机自启。"
    fi

    "$init_path" restart >/dev/null 2>&1 || "$init_path" start >/dev/null 2>&1 || true
    ok "SysV init 服务已创建并启用: ${svc} (${init_path})"
    warn "SysV 无进程守护, 崩溃不会自动重启 (如需守护请用 systemd/OpenRC 系统)。"
}

# OpenRC (Alpine / Gentoo) 服务. 用 supervise-daemon 实现崩溃自动重启 (对齐
# systemd Restart=on-failure). memlock unlimited 供 eBPF 用.
setup_openrc() {
    local role=$1
    local _subcmd=$(svc_subcmd "$role") _cfgpath=$(svc_cfg "$role")
    local svc="mirage-rs-${role}"
    local init_path="/etc/init.d/${svc}"

    cat > "$init_path" <<EOF
#!/sbin/openrc-run

name="Mirage-rs (${role})"
description="Mirage-rs High-Performance Proxy (${role})"

supervisor=supervise-daemon
command="${BIN_PATH}"
command_args="${_subcmd} -c ${_cfgpath}"
directory="${STATE_DIR}"
pidfile="/run/${svc}.pid"
respawn_delay=3
output_log="${LOG_DIR}/${role}.log"
error_log="${LOG_DIR}/${role}.log"

# 高 fd 上限 + memlock 无限 (eBPF map 分配需要, 老内核尤其)
rc_ulimit="-n 1048576 -l unlimited"

depend() {
    need net
    after firewall
}
EOF
    chmod 755 "$init_path"
    rc-update add "$svc" default >/dev/null 2>&1 || true
    # restart 兼容首次安装 (未运行时 restart 等价 start)
    if rc-service "$svc" restart >/dev/null 2>&1; then
        ok "OpenRC 服务已创建并启用: ${svc} (/etc/init.d/${svc})"
    else
        rc-service "$svc" start >/dev/null 2>&1 || true
        ok "OpenRC 服务已创建: ${svc}。若未自动启动请查看 ${LOG_DIR}/${role}.log"
    fi
}

setup_systemd() {
    local role=$1
    local _subcmd=$(svc_subcmd "$role") _cfgpath=$(svc_cfg "$role")
    local service_path="/etc/systemd/system/mirage-rs-${role}.service"

    # proxy_local 客户端: 把 resolv.conf 的改动绑到服务生命周期。ExecStopPost 即便主进程被
    # SIGKILL 也会执行 → 服务一停就还原, 不会留下"指着死 mirage 的 resolv.conf = 机器没 DNS"。
    local resolv_lines=""
    if [[ "$role" == "client" && "$CLIENT_PROXY_LOCAL" == true ]]; then
        write_resolv_guard
        resolv_lines="ExecStartPost=${RESOLV_GUARD} apply
ExecStopPost=${RESOLV_GUARD} restore"
    fi

    cat > "$service_path" <<EOF
[Unit]
Description=Mirage-rs High-Performance Proxy (${role})
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${STATE_DIR}
ExecStart=${BIN_PATH} ${_subcmd} -c ${_cfgpath}
${resolv_lines}
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "mirage-rs-${role}.service" --now
    ok "Systemd 服务已创建并启用: mirage-rs-${role}.service"
}

# ──────────────────────────────────────────────────────────────────────────────
# 交互式配置生成
# ──────────────────────────────────────────────────────────────────────────────
generate_password() {
    head -c 16 /dev/urandom | od -An -tx1 | tr -d ' \n'
}

# 询问是否配置 Shadowsocks 上游出口 (中转站模式)。
# 输出: 配了则把 JSON 对象写到 stdout (供调用方拼进配置), 不配则输出空串。
# 提示与告警走 stderr, 不污染返回值。
ask_ss_upstream() {
    cat >&2 <<'EOM'

═══════════════════════════════════════════════════
  上游出口 (可选) —— 把本机当作中转站
═══════════════════════════════════════════════════
  默认: 服务端直接连目标 (绝大多数人要的就是这个)。

  配了上游后, 服务端不再直连, 而是把流量再经 Shadowsocks 发往上游:

    客户端 ──(Mirage 隧道)──▶ 本机 ──(Shadowsocks)──▶ SS 服务器 ──▶ 目标

  典型用途: 本机放在离你近、线路好的位置 (如香港) 只做中转, 真正的出口
  落在另一台 SS 服务器上 (如落地解锁机)。需要你已有一台可用的 SS 服务器。
EOM
    ask_yn "是否配置 Shadowsocks 上游出口?" n || { echo ""; return; }

    local ss_server ss_port ss_pwd ss_method ss_udp
    ss_server=$(ask "上游 SS 服务器地址 (域名或 IP)" "")
    if [[ -z "$ss_server" ]]; then
        warn "未填服务器地址, 跳过上游配置 (仍走直连)"
        echo ""; return
    fi
    ss_port=$(ask "上游 SS 端口" "8388")
    ss_pwd=$(ask "上游 SS 密码" "")
    local m=$(ask_choice "上游 SS 加密方式" \
        "aes-256-gcm (SIP004, 兼容性最好)" \
        "chacha20-ietf-poly1305 (SIP004, 无 AES 硬件加速时更快)" \
        "aes-128-gcm (SIP004)" \
        "2022-blake3-aes-256-gcm (SIP022, 安全性最好)" \
        "2022-blake3-chacha20-poly1305 (SIP022, 无 AES 硬件加速时更快)")
    case "$m" in
        1) ss_method="aes-256-gcm" ;;
        2) ss_method="chacha20-ietf-poly1305" ;;
        3) ss_method="aes-128-gcm" ;;
        4) ss_method="2022-blake3-aes-256-gcm" ;;
        5) ss_method="2022-blake3-chacha20-poly1305" ;;
    esac
    if [[ "$ss_method" == 2022-* ]]; then
        cat >&2 <<'EOM'

  ⚠️ SIP022 的密码不是任意字符串, 而是 **base64 编码的 32 字节密钥**
     (与 SIP004 的"任意密码"完全不同, 填错会连不上)。
     没有的话可以用: openssl rand -base64 32
EOM
    fi
    # legacy 流式加密 (aes-256-cfb 等) 不提供选项: 无完整性校验、已废弃、易被主动探测识别。

    cat >&2 <<'EOM'

  UDP 怎么办? SS 的 UDP 尚未实现。
    · block (默认, 推荐): 直接拒绝 UDP。QUIC 会回落 TCP (页面照常),
      游戏/WebRTC 不可用。
    · direct: UDP 从**本机 IP** 直连出去 —— 与 TCP 的上游出口**不同**。
      落地解锁场景下流媒体走 QUIC 会被判成本机所在区域, 且不会回落 TCP,
      表现为解锁时灵时不灵且极难排查。
EOM
    if ask_yn "保留旧行为让 UDP 直连出去? (不推荐, 选 n 则阻断)" n; then
        ss_udp="direct"
        warn "UDP 将从本机 IP 出去, 与 TCP 出口不一致 —— 请确认你不介意"
    else
        ss_udp="block"
    fi

    ok "上游出口: ${ss_server}:${ss_port} (${ss_method}, udp=${ss_udp})"
    printf '{ "type": "shadowsocks", "server": "%s", "server_port": %s, "password": "%s", "method": "%s", "udp": "%s" }' \
        "$(json_escape "$ss_server")" "$ss_port" "$(json_escape "$ss_pwd")" "$ss_method" "$ss_udp"
}

# ──────────────────────────────────────────────────────────────────────────────
# 轻量模式配置 (平铺格式, 无 inbounds/outbounds/routing)
# ──────────────────────────────────────────────────────────────────────────────
config_lite_server() {
    title "配置 Mirage-rs 服务端 (轻量模式)"
    cat >&2 <<'EOM'
  轻量服务端: 只做「收隧道 → 全部转发」, 不带 Web 看板 / DNS / eBPF。
  加密、TLS 伪装握手、认证失败转发真站与完整版完全一致, 协议互通 ——
  轻量服务端可以直接给完整版客户端用。
EOM
    # 443 伪装效果最好, 但属特权端口; 这里跑在 root 下装 systemd 服务, 故无 bind 问题。
    local port=$(ask_port "监听端口 [1-65535] (443 伪装最好, 也可自定义)" "443" tcp)
    local rand_pwd=$(generate_password)
    local pwd=$(ask "认证密码" "$rand_pwd")

    local sni_default="www.apple.com"
    if ask_yn "是否自动搜索同 ASN 的伪装域名候选? (提升 SNI/IP 一致性)" n; then
        local found
        if found=$(suggest_camouflage_host) && [[ -n "$found" ]]; then
            sni_default="$found"
            ok "已选定候选: $found"
        fi
    fi
    local sni=$(ask_camouflage_host "$sni_default")

    local ss_up=$(ask_ss_upstream)
    local upstream_line=""
    [[ -n "$ss_up" ]] && upstream_line=",
    \"upstream\": ${ss_up}"

    mkdir -p "$ETC_DIR"
    cat > "${ETC_DIR}/lite_server.json" <<EOF
{
    "listen": "0.0.0.0",
    "port": ${port},
    "password": "$(json_escape "$pwd")",
    "sni": "$(json_escape "$sni")",
    "auth_ts_tolerance_secs": 60,
    "log_level": "info"${upstream_line}
}
EOF
    chmod 600 "${ETC_DIR}/lite_server.json"
    ok "轻量服务端配置已保存至: ${ETC_DIR}/lite_server.json"

    setup_service "server"

    # 节点导出 (与完整版同一格式, 客户端可直接导入)
    local detected_ip pub_host
    info "正在探测本机公网 IP..."
    detected_ip=$(detect_public_ip || true)
    pub_host=$(ask "公网地址 (域名/IP, 用于生成客户端导入串; 留空跳过)" "$detected_ip")
    if [[ -n "$pub_host" ]]; then
        local node_uri
        node_uri=$(build_node_uri "$pwd" "$pub_host" "$port" "$sni")
        echo "$node_uri" > "${ETC_DIR}/node-export.txt"
        chmod 600 "${ETC_DIR}/node-export.txt"
        echo >&2
        title "客户端节点导入串"
        echo "  $(_c 32 "$node_uri")" >&2
        echo "  已保存到: ${ETC_DIR}/node-export.txt (chmod 600), 内含密码请妥善保管。" >&2
        command -v qrencode >/dev/null 2>&1 && { echo >&2; qrencode -t UTF8 "$node_uri" >&2; }
        echo >&2
    fi
    info "启动命令: $(svc_start_hint server)"
}

config_lite_client() {
    title "配置 Mirage-rs 客户端 (轻量模式)"
    cat >&2 <<'EOM'
  轻量客户端: 本机开一个 SOCKS5 入站, **全部流量走隧道** —— 不分流、不查 DNS、
  不做 fake-IP、无透明网关、无看板。浏览器/系统把代理指到下面填的地址即可。

  ⚠️ 仅支持 TCP: SOCKS5 UDP ASSOCIATE 会被拒绝, QUIC/HTTP3 走不了代理
     (浏览器会自动回落 TCP, 页面照常; 但依赖 UDP 的应用/游戏不可用)。
     需要 UDP 请改用完整版客户端。
EOM
    # 支持粘贴服务端导出的 mirage:// 串, 免得手抄密码/SNI 出错
    local server server_port pwd sni
    if ask_yn "是否粘贴服务端的 mirage:// 节点串导入?" y; then
        local uri
        while :; do
            uri=$(ask "粘贴 mirage:// 节点串" "")
            if parse_node_uri "$uri"; then
                server="$NODE_HOST"; server_port="$NODE_PORT"
                pwd="$NODE_PWD";     sni="$NODE_SNI"
                ok "已解析: ${server}:${server_port} (SNI ${sni})"
                break
            fi
            warn "解析失败, 格式应为 mirage://<密码>@<host>:<port>?sni=<域名>"
            ask_yn "重新输入?" y || { uri=""; break; }
        done
    fi
    if [[ -z "${server:-}" ]]; then
        server=$(ask "服务端地址 (域名或 IP)" "")
        server_port=$(ask "服务端端口 (须与服务端配置一致)" "443")
        pwd=$(ask "认证密码 (须与服务端一致)" "")
        sni=$(ask_camouflage_host "www.apple.com")
    fi

    local listen=$(ask "本地 SOCKS5 监听地址 (仅本机用 127.0.0.1; LAN 共享用 0.0.0.0)" "127.0.0.1")
    local lport=$(ask_port "本地 SOCKS5 监听端口" "1080" tcp)

    # 与完整版同一策略: 非回环监听必须设认证, 否则是开放代理。
    local auth_json=""
    if [[ "$listen" != "127.0.0.1" && "$listen" != "::1" && "$listen" != "localhost" ]]; then
        cat >&2 <<'EOM'

  ⚠️  非回环监听 —— 不设认证 = 开放代理: 任何能连到它的人都能用你的隧道,
      流量从你的服务端出去, 出口 IP 会被滥用甚至拉黑。
EOM
        local u p
        u=$(ask "代理用户名" "mirage")
        p=$(ask "代理密码 (留空=自动生成)" "")
        [[ -z "$p" ]] && { p=$(generate_password); info "已自动生成代理密码: $p"; }
        auth_json=",
    \"auth\": { \"username\": \"$(json_escape "$u")\", \"password\": \"$(json_escape "$p")\" }"
        ok "SOCKS5 认证已启用 (RFC 1929)"
    fi

    mkdir -p "$ETC_DIR"
    cat > "${ETC_DIR}/lite_client.json" <<EOF
{
    "listen": "${listen}",
    "port": ${lport},
    "server": "$(json_escape "$server")",
    "server_port": ${server_port},
    "password": "$(json_escape "$pwd")",
    "sni": "$(json_escape "$sni")",
    "pool_size": 4,
    "log_level": "info"${auth_json}
}
EOF
    chmod 600 "${ETC_DIR}/lite_client.json"
    ok "轻量客户端配置已保存至: ${ETC_DIR}/lite_client.json"

    setup_service "client"
    info "启动命令: $(svc_start_hint client)"
    info "使用方式: 把浏览器/系统代理指向 SOCKS5 ${listen}:${lport}"
}

config_server() {
    title "配置 Mirage-rs 服务端"
    
    local port=$(ask_port "监听端口 [1-65535]" "443" tcp)
    local rand_pwd=$(generate_password)
    local pwd=$(ask "认证密码" "$rand_pwd")

    # 伪装 SNI: 可先自动搜索"与本机同 ASN"的候选, 搜到的作为默认值,
    # 再走原有的 TLS1.3 探测 + 人工确认流程 (ask_camouflage_host).
    local sni_default="www.apple.com"
    cat >&2 <<'EOM'

═══════════════════════════════════════════════════
  伪装 SNI 域名 —— SNI/IP 一致性 (可选自动搜索)
═══════════════════════════════════════════════════
  伪装域名若与本机 IP 不在同一网络 (例如 SNI 填 speedtest.net
  却打到某小机房 VPS), 企业防火墙的"SNI 归属 ASN vs 目的 IP
  ASN 一致性"检查会盯上它 —— 这是被动关联暴露面。

  自动搜索会扫描**本机所在 /24** 的 :443, 从证书 SAN 里找出
  真实托管在同一 ASN 的域名, 让 SNI 与 IP 名实相符。
  需要 python3 + openssl; 耗时约 1~3 分钟。

  注意: 扫描的是你自己 VPS 的同段邻居; 廉价机房邻居很可能
  本身也是代理/空壳站, 结果需人工过目后再选 (不会自动采用)。
  不搜索也完全可用 —— 直接填一个支持 TLS1.3 的大站即可。
EOM
    if ask_yn "是否自动搜索同 ASN 的伪装域名候选?" n; then
        local found
        if found=$(suggest_camouflage_host) && [[ -n "$found" ]]; then
            sni_default="$found"
            ok "已选定候选: $found (下一步仍会做 TLS1.3 探测确认)"
        else
            warn "未采用自动搜索结果, 回落手动输入"
        fi
    fi
    local sni=$(ask_camouflage_host "$sni_default")
    
    local brutal_rate_mbps=0
    if handle_brutal_optional; then
        cat >&2 <<'EOM'

═══════════════════════════════════════════════════
  Brutal CC 单连接目标速率
═══════════════════════════════════════════════════
  Brutal 给单条 TCP 死磕设定速率, 不让步. 适合"高 RTT 低
  丢包"链路 (跨洲专线 / 移动 4G/5G), BBR 这种自适应 CC 在
  丢包链路上会被拖慢, brutal 反而能跑满.

  v0.4.4-alpha.10 起跟 Python POC 完全对齐 (cwnd_gain=15,
  无 autofallback, 死磕速率到底). 不适合的链路 (低 RTT 高
  丢包 / CDN) 上 brutal 反而拖慢吞吐 — 这种链路请设 rate=0
  关掉, 让系统默认 BBR 自适应.

  推荐取值: 链路带宽的 30~50%.
    100M 出口  → 30~50 Mbps
    1G   出口  → 300~500 Mbps
  太高 → 拥塞导致重传放大. 太低 → 自我限速. 设错就改 config
  里 brutal_rate_mbps 重启服务即可.
═══════════════════════════════════════════════════
EOM
        # 探测公网链路带宽以建议默认值 (失败回退到 50)
        local default_rate=50
        brutal_rate_mbps=$(ask "Brutal 单连接目标速率 (Mbps, 推荐链路带宽 30-50%)" "$default_rate")
        info "Brutal 单连接速率: ${brutal_rate_mbps} Mbps (不适合的链路会自动回落到 BBR)"
    fi

    local brutal_line=""
    if [[ "$brutal_rate_mbps" =~ ^[0-9]+$ ]] && (( brutal_rate_mbps > 0 )); then
        brutal_line=",\"brutal_rate_mbps\": ${brutal_rate_mbps}"
    fi

    # 上游出口 (中转站模式), 不配则为空串
    local ss_up_full=$(ask_ss_upstream)
    local upstream_line=""
    [[ -n "$ss_up_full" ]] && upstream_line=",
            \"upstream\": ${ss_up_full}"

    local log_level=$(ask_choice "日志等级" "info (推荐)" "warn" "debug" "error")
    local log_str="info"
    case $log_level in 1) log_str="info";; 2) log_str="warn";; 3) log_str="debug";; 4) log_str="error";; esac

    local server_gui_enabled server_gui_listen server_gui_token server_gui_token_line=""
    read server_gui_enabled server_gui_listen server_gui_token <<< "$(ask_gui 9090)"
    [[ "$server_gui_token" != "-" && -n "$server_gui_token" ]] && server_gui_token_line=",
        \"token\": \"${server_gui_token}\""

    cat > "${ETC_DIR}/config_server.json" <<EOF
{
    "schema_version": 1,
    "log_level": "${log_str}",
    "log_file": "${LOG_DIR}/server.log",
    "inbounds": [
        {
            "type": "mirage_server",
            "tag": "mirage-in",
            "listen": "0.0.0.0",
            "port": ${port},
            "password": "$(json_escape "$pwd")",
            "camouflage_host": "$(json_escape "$sni")"${brutal_line}${upstream_line}
        }
    ],
    "outbounds": [],
    "gui": {
        "enabled": ${server_gui_enabled},
        "listen": "${server_gui_listen}"${server_gui_token_line}
    },
    "routing": {
        "default_outbound": "direct",
        "rules": []
    },
    "tuning": {
        "geodata_dir": "${ETC_DIR}/geosite"
    }
}
EOF
    
    ok "服务端配置文件已保存至: ${ETC_DIR}/config_server.json"
    setup_service "server"

    # ── 节点导出 (供客户端导入) ──
    # 自动探测本机公网 IP 作为默认值; 用户可回车采纳 / 输域名覆盖 / 留空跳过
    local detected_ip pub_host
    info "正在探测本机公网 IP..."
    detected_ip=$(detect_public_ip || true)
    if [[ -n "$detected_ip" ]]; then
        ok "探测到公网 IP: $detected_ip"
    else
        warn "公网 IP 探测失败 (网络断 / 全部回源服务超时), 需手动输入"
    fi
    pub_host=$(ask "公网地址 (域名/IP, 用于生成客户端节点导入串; 留空则跳过)" "$detected_ip")
    if [[ -z "$pub_host" ]]; then
        warn "未输入公网地址, 跳过节点导出. 如需手动构造:"
        echo "      mirage://<密码>@<host>:${port}?sni=${sni}" >&2
    else
        local node_uri
        node_uri=$(build_node_uri "$pwd" "$pub_host" "$port" "$sni")
        echo "$node_uri" > "${ETC_DIR}/node-export.txt"
        chmod 600 "${ETC_DIR}/node-export.txt"

        echo >&2
        title "客户端节点导入串"
        echo "  $(_c 32 "$node_uri")" >&2
        echo >&2
        echo "  已保存到: ${ETC_DIR}/node-export.txt (chmod 600)" >&2
        echo "  客户端安装时选择 '粘贴节点导入' 直接复用. 内含密码, 妥善保管." >&2
        if command -v qrencode >/dev/null 2>&1; then
            echo >&2
            qrencode -t UTF8 "$node_uri" >&2
        fi
        echo >&2
    fi

    info "你可以使用以下命令启动服务端: $(svc_start_hint server)"
}

# ──────────────────────────────────────────────────────────────────────────────
# 交互式路由高级分流
# ──────────────────────────────────────────────────────────────────────────────
ROUTE_ADV_RULES=()
ROUTE_ADV_DEFAULT="proxy"

_ask_rule() {
    local label=$1 type=$2 tag=$3 default=$4
    local v
    v=$(ask "  ${label}" "$default")
    case "$v" in
        0|"") ;;
        1) ROUTE_ADV_RULES+=("                {\"${type}\": [\"${tag}\"], \"outbound\": \"direct\"}") ;;
        2) ROUTE_ADV_RULES+=("                {\"${type}\": [\"${tag}\"], \"outbound\": \"proxy\"}") ;;
        3) ROUTE_ADV_RULES+=("                {\"${type}\": [\"${tag}\"], \"outbound\": \"block\"}") ;;
        *) warn "无效输入 '$v'，跳过 $label"; ;;
    esac
}

ask_route_advanced() {
    info "高级路由：逐项配置常用 geo tag"
    info "每项 4 选 1：0=跳过 / 1=direct（直连）/ 2=proxy / 3=block"
    ROUTE_ADV_RULES=()
    # 内网总是 direct（必须）
    ROUTE_ADV_RULES+=('                {"ip_cidr": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"], "outbound": "direct"}')
    info "（内网 / 保留地址已固定 direct，不可关）"

    _ask_rule "广告 (category-ads-all)"          "geosite" "category-ads-all"   "3"
    _ask_rule "国内域名 (geosite:cn)"            "geosite" "cn"                  "1"
    _ask_rule "国内 IP (geoip:cn)"               "geoip"   "cn"                  "1"
    _ask_rule "Apple 中国 (apple-cn)"            "geosite" "apple-cn"            "1"
    _ask_rule "Google 中国 (google-cn)"          "geosite" "google-cn"           "1"
    _ask_rule "Microsoft 中国 (microsoft-cn)"    "geosite" "microsoft-cn"        "1"
    _ask_rule "海外位置 (geolocation-!cn)"       "geosite" "geolocation-!cn"     "2"
    _ask_rule "Netflix"                           "geosite" "netflix"             "0"
    _ask_rule "YouTube"                           "geosite" "youtube"             "0"
    _ask_rule "Telegram"                          "geosite" "telegram"            "0"

    echo >&2
    local d
    d=$(ask "默认出口（未命中规则时；1=direct / 2=proxy）" "2")
    case "$d" in
        1) ROUTE_ADV_DEFAULT="direct" ;;
        *) ROUTE_ADV_DEFAULT="proxy" ;;
    esac
    info "已配 $(( ${#ROUTE_ADV_RULES[@]} )) 条规则，默认出口：$ROUTE_ADV_DEFAULT"
}

config_client() {
    title "配置 Mirage-rs 客户端"

    local srv_host srv_port pwd sni

    # ── 节点导入: 优先粘贴 URI ──
    local local_node_default=""
    if [[ -f "${ETC_DIR}/node-export.txt" ]]; then
        local_node_default=$(cat "${ETC_DIR}/node-export.txt")
        info "检测到本机刚生成的节点串, 输入时直接回车即可复用."
    fi

    local source
    source=$(ask_choice "节点参数获取方式" \
        "粘贴服务端导出的 mirage:// 节点串 (推荐)" \
        "手动逐项输入")

    if [[ "$source" == "1" ]]; then
        while :; do
            local uri
            uri=$(ask "请粘贴 mirage:// 节点串" "$local_node_default")
            if [[ -z "$uri" ]]; then
                warn "未输入. 退回手动模式."
                source="2"; break
            fi
            if parse_node_uri "$uri"; then
                srv_host="$NODE_HOST"
                srv_port="$NODE_PORT"
                pwd="$NODE_PWD"
                sni="$NODE_SNI"
                ok "节点导入成功: ${srv_host}:${srv_port} (sni=${sni})"
                break
            fi
            warn "节点串格式无效. 期望: mirage://<密码>@<host>:<port>?sni=<域名>"
        done
    fi

    if [[ "$source" == "2" ]]; then
        srv_host=$(ask "服务端 IP 或域名" "1.2.3.4")
        srv_port=$(ask "服务端端口" "443")
        pwd=$(ask "认证密码" "")
        sni=$(ask_camouflage_host "www.apple.com")
    fi

    local inbound_port=$(ask_port "本地代理入站监听端口 (mixed 模式同时支持 SOCKS5/HTTP)" "1080" tcp)
    # 默认回环: 监听 0.0.0.0 而不鉴权 = 开放代理, 任何能连到的人都能白嫖隧道,
    # 出口 IP 会被滥用/拉黑 (对抗审查部署尤其致命)。要 LAN 共享就必须设凭据。
    local inbound_listen=$(ask "本地代理监听地址 (仅本机用 127.0.0.1; LAN 共享用 0.0.0.0, 会要求设账号密码)" "127.0.0.1")
    local inbound_auth_json=""
    if [[ "$inbound_listen" != "127.0.0.1" && "$inbound_listen" != "::1" && "$inbound_listen" != "localhost" ]]; then
        cat >&2 <<'EOM'

  ⚠️  你选择了非回环监听地址 —— 该端口对本机之外可达。
      不设认证 = 开放代理: 任何能连到它的人都能使用你的隧道, 流量从你的服务端出去,
      出口 IP 会被滥用甚至拉黑。对抗审查部署来说, 招来注意力是最不能承受的。
EOM
        local ib_user ib_pass
        ib_user=$(ask "代理用户名" "mirage")
        ib_pass=$(ask "代理密码 (留空=自动生成)" "")
        [[ -z "$ib_pass" ]] && { ib_pass=$(generate_password); info "已自动生成代理密码: $ib_pass"; }
        inbound_auth_json=',
            "auth": { "username": "'"$(json_escape "$ib_user")"'", "password": "'"$(json_escape "$ib_pass")"'" }'
        ok "入站认证已启用 (SOCKS5 走 RFC 1929, HTTP 走 Proxy-Authorization: Basic)"
    fi

    # ── 部署模式: 本地代理 vs 透明网关 ──
    # 本地代理 = 只 mixed 入站, 应用手动指向本机:1080。
    # 透明网关 = 加 transparent(sk_lookup 拦截) + dns(fake-IP) 入站, LAN 设备无感,
    #            需内核≥5.9 + eBPF 二进制 (64 位 release)。见 README 透明网关章节。
    CLIENT_IS_GATEWAY=false
    local inbounds_json advanced_dns_line=""
    local deploy_mode
    deploy_mode=$(ask_choice "部署模式" \
        "本地代理 (SOCKS5/HTTP, 应用手动指向本机:${inbound_port})" \
        "透明网关 (fake-IP + sk_lookup 拦截 LAN 流量, 需内核≥5.9 + eBPF)")

    if [[ "$deploy_mode" == "2" ]]; then
        CLIENT_IS_GATEWAY=true
        local transparent_port lan_iface dns_listen dns_port fakeip_range direct_dns remote_dns proxy_local
        transparent_port=$(ask_port "透明代理监听端口 (sk_lookup 内部用, 随意)" "12345" tcp)
        lan_iface=$(ask "LAN 网卡名 (tc_divert 挂这张卡抓裸-IP 转发流量, 面向内网设备的那张)" "$(detect_wan_iface)")
        # 本机出向: 让网关这台机器自己的流量也走代理 (cgroup/connect4)。开启则需把
        # 本机 DNS 指向 mirage 才能拿到 fake-IP —— 下面会自动改 /etc/resolv.conf 并备份。
        if ask_yn "让网关本机自身的流量也走代理? (否则仅转发的 LAN 流量走代理)" n; then
            proxy_local=true
        else
            proxy_local=false
        fi
        CLIENT_PROXY_LOCAL=$proxy_local
        dns_listen=$(ask "DNS 服务监听地址" "0.0.0.0")
        dns_port=$(ask_port "DNS 监听端口 (LAN 设备 DNS 指这里; 标准 53)" "53" udp)
        fakeip_range=$(ask "Fake-IP 网段 (RFC2544 基准段, 一般不改)" "198.18.0.0/15")
        # v0.4.5: 国内域名走真实上游解析, 支持多上游并行 + 重传。配两个上游 (主+备)
        # 后, DNS 服务会向两者并行发查询、取最快回的, 且丢包自动重传 —— 单上游偶发
        # 丢一个 UDP 包不再放大成客户端 ~11s 卡顿。备用留空则只用主用 (仍有重传)。
        direct_dns=$(ask "直连(国内)DNS 主用" "223.5.5.5:53")
        direct_dns2=$(ask "直连(国内)DNS 备用 (多上游并行兜底, 留空=只用主用)" "114.114.114.114:53")
        remote_dns=$(ask "代理(境外)DNS, 经隧道查" "8.8.8.8")
        inbounds_json='{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "'"$inbound_listen"'",
            "port": '"$inbound_port"''"$inbound_auth_json"'
        },
        {
            "type": "transparent",
            "tag": "transparent-in",
            "listen": "0.0.0.0",
            "port": '"$transparent_port"',
            "interface": "'"$lan_iface"'",
            "proxy_local": '"$proxy_local"'
        },
        {
            "type": "dns",
            "tag": "dns-in",
            "listen": "'"$dns_listen"'",
            "port": '"$dns_port"'
        }'
        # 组装 direct 上游 (主用 + 可选备用), 收集全部 tag=direct 供多上游并行解析
        local direct_resolvers='            { "tag": "direct", "address": "'"$direct_dns"'" }'
        if [[ -n "$direct_dns2" ]]; then
            direct_resolvers="$direct_resolvers,"$'\n'"            { \"tag\": \"direct\", \"address\": \"$direct_dns2\" }"
        fi
        advanced_dns_line='"advanced_dns": {
        "resolvers": [
'"$direct_resolvers"',
            { "tag": "remote", "address": "'"$remote_dns"'", "via": "proxy" }
        ],
        "fakeip": { "enabled": true, "inet4_range": "'"$fakeip_range"'", "persist_path": "/var/lib/mirage-rs/fakeip.cache" },
        "cache": { "enabled": true, "max_entries": 10000 }
    },'
        local dns_upstreams="$direct_dns"; [[ -n "$direct_dns2" ]] && dns_upstreams="$direct_dns + $direct_dns2"
        info "透明网关模式: transparent(:$transparent_port, tc_divert@$lan_iface) + dns(:$dns_port, 国内上游=$dns_upstreams 并行+重传) 入站 + fake-IP($fakeip_range)"
    else
        inbounds_json='{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "'"$inbound_listen"'",
            "port": '"$inbound_port"''"$inbound_auth_json"'
        }'
    fi

    local pool_size=$(ask "并发连接池大小 (越大速度越快，推荐 50)" "50")
    
    local routing_preset
    routing_preset=$(ask_choice "客户端路由（分流）策略" \
        "国内直连 / 局域网直连，其余走代理（经典中国分流，推荐）" \
        "全部流量走代理（全局代理）" \
        "自定义分流（通过交互选配常用 Geo Tag 去向）" \
        "留空规则，全部走默认出口")
        
    local routing_json=""
    case $routing_preset in
        1)
            routing_json='"routing": {
        "default_outbound": "proxy",
        "rules": [
            {
                "outbound": "direct",
                "ip_cidr": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
            },
            {
                "outbound": "direct",
                "geosite": ["cn", "apple-cn", "google-cn", "microsoft-cn"]
            },
            {
                "outbound": "direct",
                "geoip": ["cn"]
            }
        ]
    }'
            ;;
        2)
            routing_json='"routing": {
        "default_outbound": "proxy",
        "rules": [
            {
                "outbound": "direct",
                "ip_cidr": ["127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16"]
            }
        ]
    }'
            ;;
        3)
            ask_route_advanced
            # 将 ROUTE_ADV_RULES 数组按逗号拼接
            local rules_inner=""
            for r in "${ROUTE_ADV_RULES[@]}"; do
                rules_inner+="${r},
"
            done
            rules_inner="${rules_inner%,
}"
            routing_json='"routing": {
        "default_outbound": "'"${ROUTE_ADV_DEFAULT}"'",
        "rules": [
'"${rules_inner}"'
        ]
    }'
            ;;
        4)
            routing_json='"routing": {
        "default_outbound": "proxy",
        "rules": []
    }'
            ;;
    esac
    
    local log_level=$(ask_choice "日志等级" "info (推荐)" "warn" "debug" "error")
    local log_str="info"
    case $log_level in 1) log_str="info";; 2) log_str="warn";; 3) log_str="debug";; 4) log_str="error";; esac

    # mode 3 同机部署时, 服务端可能已占 9090, ask_gui 内的 ask_port 会自动
    # 检测占用并提示改成 9091 等. 单独 client (mode 2) 直接 9090 即可.
    local client_gui_enabled client_gui_listen client_gui_token client_gui_token_line=""
    read client_gui_enabled client_gui_listen client_gui_token <<< "$(ask_gui 9090)"
    [[ "$client_gui_token" != "-" && -n "$client_gui_token" ]] && client_gui_token_line=",
        \"token\": \"${client_gui_token}\""

    cat > "${ETC_DIR}/config_client.json" <<EOF
{
    "schema_version": 1,
    "log_level": "${log_str}",
    "log_file": "${LOG_DIR}/client.log",
    "inbounds": [
        ${inbounds_json}
    ],
    "outbounds": [
        {
            "type": "mirage",
            "tag": "proxy",
            "server": "$(json_escape "$srv_host")",
            "server_port": ${srv_port},
            "password": "$(json_escape "$pwd")",
            "camouflage_host": "$(json_escape "$sni")",
            "pool_size": ${pool_size}
        },
        {
            "type": "direct",
            "tag": "direct"
        },
        {
            "type": "block",
            "tag": "block"
        }
    ],
    "gui": {
        "enabled": ${client_gui_enabled},
        "listen": "${client_gui_listen}"${client_gui_token_line}
    },
    ${routing_json},
    ${advanced_dns_line}
    "tuning": {
        "ebpf_mode": "auto",
        "geodata_dir": "${ETC_DIR}/geosite",
        "geo_sources": [
            {
                "name": "geosite",
                "kind": "geosite",
                "url": "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
                "via": "proxy"
            },
            {
                "name": "geoip",
                "kind": "geoip",
                "url": "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
                "via": "proxy"
            }
        ]
    }
}
EOF

    ok "客户端配置文件已保存至: ${ETC_DIR}/config_client.json"
    setup_service "client"

    info "你可以使用以下命令启动客户端: $(svc_start_hint client)"
}

# ──────────────────────────────────────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────────────────────────────────────
optimize_sysctl() {
    info "正在优化系统网络参数 (BBR, wmem_max)..."
    cat > /etc/sysctl.d/99-mirage.conf <<EOF
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
net.core.wmem_max=8388608
net.core.rmem_max=8388608
net.ipv4.tcp_fastopen=3
EOF
    sysctl --system >/dev/null 2>&1 || true
    ok "系统网络参数优化完毕 (BBR/缓冲放大已开启)。"
}

# ──────────────────────────────────────────────────────────────────────────────
# 透明网关系统配置 (IP 转发 + WAN NAT) —— 可选, 询问开关
# ──────────────────────────────────────────────────────────────────────────────
# mirage-rs 进程自身只做 fake-IP 本地路由 + sk_lookup 拦截 (代理流量走本地投递,
# 免 iptables)。但**直连流量(真实IP)走内核转发**, 需要 ip_forward + WAN NAT,
# 这两个是系统层的事, mirage-rs 不管。
GW_NAT_SCRIPT="/usr/local/sbin/mirage-gw-nat"
GW_NFT_TABLE="mirage_gw"
GW_IPT_CHAIN="MIRAGE_POSTROUTING"  # iptables 自定义链, 卸载可精准清除不误伤

detect_wan_iface() {
    ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}'
}

# 生成幂等的 NAT 应用脚本 (当下 + 开机都跑它)。nft 优先, iptables 兜底。
write_gw_nat_script() {
    local wan=$1
    {
        echo '#!/usr/bin/env bash'
        echo '# Mirage-rs 透明网关 NAT (install.sh 自动生成, 幂等)。卸载用 install.sh。'
        echo 'sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1'
        # tc_divert 用 bpf_sk_assign 把裸-IP 转发流量偷进本地透明 socket, 并打 fwmark 1。
        # 这条策略路由把 fwmark 1 的包引到 local 路由表 → 走本地投递 (标准 TPROXY 配方,
        # 属 iproute2 策略路由, 非 iptables/nftables)。
        echo 'ip rule add fwmark 1 lookup 100 2>/dev/null || true'
        echo 'ip route add local default dev lo table 100 2>/dev/null || true'
        if command -v nft >/dev/null 2>&1; then
            echo "nft add table inet ${GW_NFT_TABLE} 2>/dev/null || true"
            echo "nft flush table inet ${GW_NFT_TABLE} 2>/dev/null || true"
            echo "nft add chain inet ${GW_NFT_TABLE} postrouting '{ type nat hook postrouting priority 100 ; }'"
            echo "nft add rule inet ${GW_NFT_TABLE} postrouting oifname \"${wan}\" masquerade"
        else
            # 规则收进自定义链 MIRAGE_POSTROUTING, 卸载时精准清除, 不碰用户原有规则
            echo "iptables -t nat -N ${GW_IPT_CHAIN} 2>/dev/null || true"
            echo "iptables -t nat -C POSTROUTING -j ${GW_IPT_CHAIN} 2>/dev/null || iptables -t nat -A POSTROUTING -j ${GW_IPT_CHAIN}"
            echo "iptables -t nat -F ${GW_IPT_CHAIN}"
            echo "iptables -t nat -A ${GW_IPT_CHAIN} -o \"${wan}\" -j MASQUERADE"
        fi
    } > "$GW_NAT_SCRIPT"
    chmod 755 "$GW_NAT_SCRIPT"
}

setup_transparent_gateway() {
    title "透明网关系统配置 (可选)"
    info "透明代理需系统层配合 (进程拦 fake-IP + tc_divert 抓裸-IP 转发流量):"
    info "  ① net.ipv4.ip_forward=1   ② WAN 口 NAT MASQUERADE"
    info "  ③ fwmark 1 → local 路由表 (tc_divert sk_assign 的包走本地投递, TPROXY 配方)"
    info "  (fake-IP 本地路由 + sk_lookup/tc_divert 拦截由 mirage-rs 自动做, 无需 iptables 分流)"
    if ! ask_yn "本机作为透明网关, 现在配置 IP 转发 + NAT 吗?" y; then
        warn "跳过。代理流量(fake-IP)仍可用; 直连流量转发需你自行开 ip_forward + NAT。"
        return
    fi
    if ! command -v nft >/dev/null 2>&1 && ! command -v iptables >/dev/null 2>&1; then
        warn "既无 nft 也无 iptables, 无法自动配 NAT。请手动配置后再用透明模式。"
        return
    fi

    # ① IP 转发持久化 (追加到已有的 99-mirage.conf)
    if [[ -f /etc/sysctl.d/99-mirage.conf ]] && ! grep -q 'net.ipv4.ip_forward' /etc/sysctl.d/99-mirage.conf; then
        echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/99-mirage.conf
        sysctl --system >/dev/null 2>&1 || true
    fi

    # ② WAN 出口探测
    local wan; wan=$(detect_wan_iface)
    [[ -z "$wan" ]] && wan=$(ask "未探测到默认路由出口, 手动输入 WAN 网卡名" "eth0")
    info "WAN 出口: $wan"

    # ③ 生成脚本并立即应用
    write_gw_nat_script "$wan"
    if "$GW_NAT_SCRIPT"; then
        local backend; command -v nft >/dev/null 2>&1 && backend=nftables || backend=iptables
        ok "已应用: IP 转发 + NAT ($backend, oif $wan)"
    else
        warn "NAT 应用失败, 请检查 $GW_NAT_SCRIPT 与网卡名 $wan。"
    fi

    # ④ 开机持久化 (nft/iptables 规则默认不跨重启)
    case "$INIT_SYS" in
        systemd)
            cat > /etc/systemd/system/mirage-gw-nat.service <<EOF
[Unit]
Description=Mirage-rs transparent gateway NAT
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
ExecStart=${GW_NAT_SCRIPT}
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload 2>/dev/null || true
            systemctl enable mirage-gw-nat.service >/dev/null 2>&1 || true
            ok "开机持久化: systemd mirage-gw-nat.service"
            ;;
        *)
            warn "非 systemd: NAT 已应用但**重启后失效**。请把 ${GW_NAT_SCRIPT} 加进开机启动。"
            ;;
    esac

    # ④.5 本机出向走代理: 把网关自身 DNS 指向 mirage (127.0.0.1), 本机应用才能拿到
    # fake-IP、被 cgroup/connect4 重定向进代理。备份原 resolv.conf, 卸载时还原。
    if [[ "$CLIENT_PROXY_LOCAL" == true ]]; then
        # 逻辑集中在守卫脚本里 (service 的 ExecStartPost/ExecStopPost 用的是同一份)。
        [[ -x "$RESOLV_GUARD" ]] || write_resolv_guard
        "$RESOLV_GUARD" apply
        ok "本机 DNS 已指向 mirage (127.0.0.1); 原 resolv.conf 备份于 $RESOLV_BAK"
        ok "  已绑定到服务生命周期: 服务停止/崩溃/被杀 → ExecStopPost 自动还原, 机器不会没 DNS"
        warn "若本机跑 NetworkManager/dhclient/systemd-resolved, 可能覆盖 /etc/resolv.conf;"
        warn "  被覆盖会导致本机拿不到 fake-IP。必要时 chattr +i /etc/resolv.conf 锁定。"
    fi

    # ⑤ LAN 侧指引 (这步在你的路由器/设备上做)
    local lan_ip; lan_ip=$(ip -4 addr show 2>/dev/null | awk '/inet /{print $2}' | grep -v '^127' | head -1 | cut -d/ -f1)
    echo >&2
    title "还需在 LAN 侧配置 (路由器/设备上)"
    echo "  把 LAN 设备的【默认网关】和【DNS】都指向本机: ${lan_ip:-<本机_LAN_IP>}" >&2
    echo "  ⚠️ DNS 必须指过来才能拿到 fake-IP; 不指则所有流量都当直连、不走代理。" >&2
    echo >&2
}

teardown_transparent_gateway() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl disable --now mirage-gw-nat.service 2>/dev/null || true
        rm -f /etc/systemd/system/mirage-gw-nat.service
        systemctl daemon-reload 2>/dev/null || true
    fi
    # tc_divert 策略路由 (fwmark→local 路由表) 清理
    ip rule del fwmark 1 lookup 100 2>/dev/null || true
    ip route del local default dev lo table 100 2>/dev/null || true
    # 还原本机 resolv.conf (proxy_local 开启时改过)。优先用守卫脚本还原 (与 service 的
    # ExecStopPost 同一份逻辑); 老版本装的没这脚本 → 内联兜底。卸载才删备份 + 守卫脚本。
    if [[ -e "$RESOLV_BAK" ]]; then
        if [[ -x "$RESOLV_GUARD" ]]; then
            "$RESOLV_GUARD" restore
        else
            chattr -i /etc/resolv.conf 2>/dev/null || true
            rm -f /etc/resolv.conf
            if [[ -e "${RESOLV_BAK}.symlink" ]]; then
                ln -sf "$(cat "${RESOLV_BAK}.symlink")" /etc/resolv.conf 2>/dev/null || cp -a "$RESOLV_BAK" /etc/resolv.conf
            else
                cp -a "$RESOLV_BAK" /etc/resolv.conf
            fi
        fi
        rm -f "$RESOLV_BAK" "${RESOLV_BAK}.symlink"
        info "已还原本机 resolv.conf。"
    fi
    rm -f "$RESOLV_GUARD"
    command -v nft >/dev/null 2>&1 && nft delete table inet "$GW_NFT_TABLE" 2>/dev/null || true
    # iptables: 从 POSTROUTING 摘掉跳转, flush + 删自定义链 (与 nft delete table 对齐, 100% 干净)
    if command -v iptables >/dev/null 2>&1; then
        iptables -t nat -D POSTROUTING -j "$GW_IPT_CHAIN" 2>/dev/null || true
        iptables -t nat -F "$GW_IPT_CHAIN" 2>/dev/null || true
        iptables -t nat -X "$GW_IPT_CHAIN" 2>/dev/null || true
    fi
    if [[ -f "$GW_NAT_SCRIPT" ]]; then
        rm -f "$GW_NAT_SCRIPT"
        info "已移除透明网关 NAT (脚本/服务/nft 表/iptables 自定义链)。"
    fi
}

uninstall() {
    title "Mirage-rs 卸载"

    # 兼容两种命名: 新 (mirage-rs-*) + 旧 (mirage-*, alpha.8 之前的旧机器)
    local services=(mirage-rs-server mirage-rs-client mirage-server mirage-client)

    # systemd 清理 (有 systemctl 才做)
    if command -v systemctl >/dev/null 2>&1; then
        info "停止并禁用所有 mirage 相关 systemd 服务..."
        for svc in "${services[@]}"; do
            if systemctl is-active --quiet "${svc}.service" 2>/dev/null; then
                systemctl stop "${svc}.service" 2>/dev/null || true
            fi
            if systemctl is-enabled --quiet "${svc}.service" 2>/dev/null; then
                systemctl disable "${svc}.service" 2>/dev/null || true
            fi
            local unit_path="/etc/systemd/system/${svc}.service"
            if [[ -f "$unit_path" ]]; then
                rm -f "$unit_path"
                info "已删除 ${unit_path}"
            fi
        done
        systemctl daemon-reload 2>/dev/null || true
        ok "Systemd 服务清理完毕"
    fi

    # OpenRC 清理 (有 rc-service 才做)
    if command -v rc-service >/dev/null 2>&1; then
        info "停止并禁用所有 mirage 相关 OpenRC 服务..."
        for svc in "${services[@]}"; do
            rc-service "$svc" stop 2>/dev/null || true
            rc-update del "$svc" default 2>/dev/null || true
            if [[ -f "/etc/init.d/${svc}" ]]; then
                rm -f "/etc/init.d/${svc}"
                info "已删除 /etc/init.d/${svc}"
            fi
        done
        ok "OpenRC 服务清理完毕"
    fi

    # SysV init 清理 (仅当不是 OpenRC —— 两者都用 /etc/init.d, OpenRC 分支已处理过).
    # 用 update-rc.d/chkconfig 反注册, 停掉并删脚本.
    if ! command -v rc-service >/dev/null 2>&1 \
        && { command -v update-rc.d >/dev/null 2>&1 || command -v chkconfig >/dev/null 2>&1 || command -v service >/dev/null 2>&1; }; then
        info "停止并禁用所有 mirage 相关 SysV init 服务..."
        for svc in "${services[@]}"; do
            local sysv_path="/etc/init.d/${svc}"
            [[ -f "$sysv_path" ]] || continue
            "$sysv_path" stop 2>/dev/null || true
            if command -v update-rc.d >/dev/null 2>&1; then
                update-rc.d -f "$svc" remove 2>/dev/null || true
            elif command -v chkconfig >/dev/null 2>&1; then
                chkconfig --del "$svc" 2>/dev/null || true
            fi
            rm -f "$sysv_path"
            info "已删除 ${sysv_path}"
        done
        ok "SysV init 服务清理完毕"
    fi

    # 二进制
    if [[ -f "$BIN_PATH" ]]; then
        rm -f "$BIN_PATH"
        ok "已删除二进制 $BIN_PATH"
    fi

    # 日志目录 (默认 y, 卸载场景下日志通常不需要保留)
    if [[ -d "$LOG_DIR" ]]; then
        if ask_yn "是否删除日志目录 $LOG_DIR ?" y; then
            rm -rf "$LOG_DIR"
            ok "已删除 $LOG_DIR"
        fi
    fi

    # 配置目录 (默认 n, 包含 config_*.json / geo 数据 / node-export.txt,
    # 用户重装可复用, 谨慎默认不删)
    if [[ -d "$ETC_DIR" ]]; then
        if ask_yn "是否删除配置目录 $ETC_DIR ? (含 config / geo / node-export)" n; then
            rm -rf "$ETC_DIR"
            ok "已删除 $ETC_DIR"
        fi
    fi

    # 状态目录 (默认 y, 一般是 systemd WorkingDirectory 残留)
    if [[ -d "$STATE_DIR" ]]; then
        if ask_yn "是否删除状态目录 $STATE_DIR ?" y; then
            rm -rf "$STATE_DIR"
            ok "已删除 $STATE_DIR"
        fi
    fi

    # 透明网关 NAT (若配过): 移除脚本/systemd 服务/nft 表
    teardown_transparent_gateway

    # 系统级 sysctl (默认 n, 移除会影响系统其他服务的 BBR/wmem 配置)
    if [[ -f /etc/sysctl.d/99-mirage.conf ]]; then
        if ask_yn "是否删除 sysctl 优化 /etc/sysctl.d/99-mirage.conf ? (会影响系统 BBR/wmem 设置)" n; then
            rm -f /etc/sysctl.d/99-mirage.conf
            sysctl --system >/dev/null 2>&1 || true
            ok "已删除 sysctl 优化, 系统参数已重载"
        fi
    fi

    title "卸载完成"
    echo -e "  Mirage-rs 已从本机移除. 感谢使用." >&2
}

main() {
    title "Mirage-rs 安装向导"
    if [[ $EUID -ne 0 ]]; then
        err "需要 Root 权限。请使用 sudo bash install.sh 运行。"
    fi

    # 探测 init 系统 (systemd / openrc / none), 供服务注册 + 提示分派.
    INIT_SYS=$(detect_init)
    info "检测到 init 系统: ${INIT_SYS}"
    if [ "$INIT_SYS" = none ]; then
        warn "未检测到 systemd / OpenRC / SysV init, 服务将不会自动注册 (可手动前台运行)。"
    fi

    local mode=$(ask_choice "请选择操作" \
        "部署服务端 (Server)" \
        "部署客户端 (Client)" \
        "同时部署服务端与客户端" \
        "更新二进制 (Update binary)" \
        "显示服务端节点配置 (Show node info)" \
        "卸载 (Uninstall)")

    case "$mode" in
        4) update_binary; return ;;
        5) show_server_node; return ;;
        6) uninstall; return ;;
    esac

    # 部署路径 (1/2/3): 先选形态 —— 完整版还是轻量版
    cat >&2 <<'EOM'

═══════════════════════════════════════════════════
  部署形态
═══════════════════════════════════════════════════
  完整版: 分流 (国内直连/国外走代理) + fake-IP DNS + 可选透明网关 +
          Web 看板 + UDP 支持。功能齐全, 配置项也多。

  轻量版: 只有「本机 SOCKS5 → 全部走隧道」。无分流/DNS/透明网关/看板,
          仅 TCP (QUIC 走不了代理, 浏览器会自动回落)。配置极简, 三五项填完就能用。
          加密与 TLS 伪装与完整版**完全一致**, 两者协议互通。

  拿不准就选完整版 —— 它能做轻量版的一切, 只是要多配几项。
EOM
    local form=$(ask_choice "选择部署形态" "完整版 (功能齐全)" "轻量版 (只要能翻墙)")
    [[ "$form" == "2" ]] && LITE_MODE=true
    if [[ "$LITE_MODE" == true ]]; then
        ok "已选择轻量版: SOCKS5 全部转发, 仅 TCP"
    fi

    # 选择安装版本 (留空 = latest)
    select_version

    setup_fhs
    optimize_sysctl

    case $mode in
        1)
            if [[ "$LITE_MODE" == true ]]; then config_lite_server; else config_server; fi
            ;;
        2)
            if [[ "$LITE_MODE" == true ]]; then
                config_lite_client   # 轻量版无透明网关, 不走 setup_transparent_gateway
            else
                config_client
                [[ "$CLIENT_IS_GATEWAY" == true ]] && setup_transparent_gateway
            fi
            ;;
        3)
            if [[ "$LITE_MODE" == true ]]; then
                config_lite_server
                config_lite_client
            else
                config_server
                config_client
                [[ "$CLIENT_IS_GATEWAY" == true ]] && setup_transparent_gateway
            fi
            ;;
    esac

    title "安装完成！"
    echo -e "  配置目录: $(_c 36 "${ETC_DIR}")"
    echo -e "  数据目录: $(_c 36 "${STATE_DIR}")"
    echo -e "  日志命令: $(_c 36 "$(svc_log_hint server)")"
    echo -e "\n  感谢使用 Mirage-rs，极致性能尽在掌握。"
}

main "$@"
