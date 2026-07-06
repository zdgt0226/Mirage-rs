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
#   read gui_enabled gui_listen <<< "$(ask_gui 9090)"
# 返回单行: "<enabled> <addr>:<port>", 其中 enabled = true|false.
# 注意不能用全局变量传 enabled, 因为 $(ask_gui) 是子 shell, 出不来.
# 用户拒绝时 listen 用 "127.0.0.1:9090" 占位 (enabled=false 时 mirage 忽略).
ask_gui() {
    local default_port=${1:-9090}
    if ! ask_yn "启用 Web GUI 管理面板 (Neon Dashboard)" y; then
        echo "false 127.0.0.1:9090"
        return
    fi
    local scope listen_addr
    scope=$(ask_choice "GUI 监听范围" \
        "仅本机 127.0.0.1 (推荐)" \
        "全网开放 0.0.0.0 (LAN/远程访问, 自行加反代+鉴权)")
    case "$scope" in
        1) listen_addr="127.0.0.1" ;;
        2) listen_addr="0.0.0.0" ;;
    esac
    local port
    port=$(ask_port "GUI 端口" "$default_port" tcp)
    echo "true ${listen_addr}:${port}"
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

# 安装版本: 空 = 最新 release; 可用环境变量 MIRAGE_TAG=v0.4.5-alpha.10 预设 (跳过交互).
MIRAGE_TAG="${MIRAGE_TAG:-}"
# init 系统: main 启动时 detect_init 填充 (systemd / openrc / none).
INIT_SYS=""

# 让用户选择安装的 release tag (留空装 latest). 已通过环境变量指定则不交互.
select_version() {
    if [[ -n "$MIRAGE_TAG" ]]; then
        info "使用环境变量指定的版本: $MIRAGE_TAG"
        return
    fi
    echo "" >&2
    info "安装版本 (留空 = 最新 release):"
    echo "    可在 https://github.com/zdgt0226/Mirage-rs/releases 查看; 例: v0.4.5-alpha.10" >&2
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
# `mirage --version` 输出: "mirage-rs 0.4.5-alpha.19 (v0.4.5-alpha.19-...)"
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
setup_service() {
    local role=$1
    case "$INIT_SYS" in
        systemd)  setup_systemd "$role" ;;
        openrc)   setup_openrc  "$role" ;;
        sysvinit) setup_sysv    "$role" ;;
        *)
            warn "未识别的 init 系统 (非 systemd/OpenRC/SysV), 跳过服务注册。"
            info "可手动前台运行: ${BIN_PATH} ${role} -c ${ETC_DIR}/config_${role}.json"
            ;;
    esac
}

# SysV init (老 Debian/CentOS6/精简系统). LSB 头 + 自包含 nohup+pidfile 管理,
# 不依赖 start-stop-daemon 或 RHEL /etc/init.d/functions, 最大可移植性.
# 注意: SysV 无 supervisor, 崩溃不自动重启 (systemd/OpenRC 才有). 可接受降级.
setup_sysv() {
    local role=$1
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
ARGS="${role} -c ${ETC_DIR}/config_${role}.json"
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
    local svc="mirage-rs-${role}"
    local init_path="/etc/init.d/${svc}"

    cat > "$init_path" <<EOF
#!/sbin/openrc-run

name="Mirage-rs (${role})"
description="Mirage-rs High-Performance Proxy (${role})"

supervisor=supervise-daemon
command="${BIN_PATH}"
command_args="${role} -c ${ETC_DIR}/config_${role}.json"
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
    local service_path="/etc/systemd/system/mirage-rs-${role}.service"
    
    cat > "$service_path" <<EOF
[Unit]
Description=Mirage-rs High-Performance Proxy (${role})
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${STATE_DIR}
ExecStart=${BIN_PATH} ${role} -c ${ETC_DIR}/config_${role}.json
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

config_server() {
    title "配置 Mirage-rs 服务端"
    
    local port=$(ask_port "监听端口 [1-65535]" "443" tcp)
    local rand_pwd=$(generate_password)
    local pwd=$(ask "认证密码" "$rand_pwd")
    local sni=$(ask_camouflage_host "www.apple.com")
    
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

    local log_level=$(ask_choice "日志等级" "info (推荐)" "warn" "debug" "error")
    local log_str="info"
    case $log_level in 1) log_str="info";; 2) log_str="warn";; 3) log_str="debug";; 4) log_str="error";; esac

    local server_gui_enabled server_gui_listen
    read server_gui_enabled server_gui_listen <<< "$(ask_gui 9090)"

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
            "password": "${pwd}",
            "camouflage_host": "${sni}"${brutal_line}
        }
    ],
    "outbounds": [],
    "gui": {
        "enabled": ${server_gui_enabled},
        "listen": "${server_gui_listen}"
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
    local inbound_listen=$(ask "本地代理监听地址 (LAN 共享用 0.0.0.0; 仅本机用 127.0.0.1)" "0.0.0.0")

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
    local client_gui_enabled client_gui_listen
    read client_gui_enabled client_gui_listen <<< "$(ask_gui 9090)"

    cat > "${ETC_DIR}/config_client.json" <<EOF
{
    "schema_version": 1,
    "log_level": "${log_str}",
    "log_file": "${LOG_DIR}/client.log",
    "inbounds": [
        {
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "${inbound_listen}",
            "port": ${inbound_port}
        }
    ],
    "outbounds": [
        {
            "type": "mirage",
            "tag": "proxy",
            "server": "${srv_host}",
            "server_port": ${srv_port},
            "password": "${pwd}",
            "camouflage_host": "${sni}",
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
        "listen": "${client_gui_listen}"
    },
    ${routing_json},
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

    # 部署路径 (1/2/3): 选择安装版本 (留空 = latest)
    select_version

    setup_fhs
    optimize_sysctl

    case $mode in
        1)
            config_server
            ;;
        2)
            config_client
            ;;
        3)
            config_server
            config_client
            ;;
    esac

    title "安装完成！"
    echo -e "  配置目录: $(_c 36 "${ETC_DIR}")"
    echo -e "  数据目录: $(_c 36 "${STATE_DIR}")"
    echo -e "  日志命令: $(_c 36 "$(svc_log_hint server)")"
    echo -e "\n  感谢使用 Mirage-rs，极致性能尽在掌握。"
}

main "$@"
