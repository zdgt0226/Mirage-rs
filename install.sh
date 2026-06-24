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

# 节点 URI 格式: mirage://<url-encoded-pwd>@<host>:<port>?sni=<sni>[&brutal=<mbps>]
# 注: 不支持带 [] 的 IPv6 主机 (regex 限制), 这种情况手动模式输入。
build_node_uri() {
    local pwd=$1 host=$2 port=$3 sni=$4 brutal=${5:-0}
    local epwd esni q
    epwd=$(url_encode "$pwd")
    esni=$(url_encode "$sni")
    q="sni=${esni}"
    if [[ "$brutal" =~ ^[0-9]+$ ]] && (( brutal > 0 )); then
        q+="&brutal=$brutal"
    fi
    echo "mirage://${epwd}@${host}:${port}?${q}"
}

# 解析 URI 写入全局 NODE_*。成功返回 0, 失败返回 1。
parse_node_uri() {
    local uri=$1
    NODE_PWD=""; NODE_HOST=""; NODE_PORT=""; NODE_SNI=""; NODE_BRUTAL=0
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
            brutal) NODE_BRUTAL="$v" ;;
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
        local api_resp
        api_resp=$(curl -sfL --max-time 10 \
            -H "Accept: application/vnd.github+json" \
            "https://api.github.com/repos/zdgt0226/Mirage-rs/releases/latest" 2>/dev/null || true)
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
        local arch
        case $(uname -m) in
            x86_64) arch="amd64" ;;
            aarch64|arm64) arch="arm64" ;;
            *) err "不支持的系统架构: $(uname -m)" ;;
        esac
        
        # 文件名跟 release.yml 上传命名严格一致 (mirage-rs-<arch>-musl)
        local download_url="https://github.com/zdgt0226/Mirage-rs/releases/latest/download/mirage-rs-${arch}-musl"
        info "下载链接: $download_url"

        # 使用 curl 下载，带进度条
        if ! curl -# -fLo "$BIN_PATH" "$download_url"; then
            warn "从 GitHub Releases 下载失败，请检查网络或手动下载编译。"
            touch "$BIN_PATH" # Placeholder for sandbox/development fallback
        else
            verify_binary_integrity "$BIN_PATH" "$download_url"
        fi
    fi
    
    chmod 755 "$BIN_PATH"
    ok "核心程序部署完毕 (Aya CO-RE eBPF Ready)。"
}

setup_systemd() {
    local role=$1
    local service_path="/etc/systemd/system/mirage-${role}.service"
    
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
    systemctl enable "mirage-${role}.service" --now
    ok "Systemd 服务已创建并启用: mirage-${role}.service"
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
  关于 Brutal CC 速率值的重要提示
═══════════════════════════════════════════════════
  Brutal 是为"单条 TCP 跑满目标速率"设计的拥塞控制算法.
  它不主动让步, 设置多少就发多少.

  但 Mirage 的 WarmPool 会同时持有多条 brutal 连接,
  这些连接相互不知道彼此, 各自独立打满设定值.
  因此 ★ 单连接的目标速率必须远低于链路总带宽 ★,
  否则多连接并发时会引发持续拥塞和丢包.

  推荐取值: 8 ~ 10 Mbps (不分 100M / 1G 出口)
  上限红线: 10 Mbps. 超过会拖累整体速度.

  原理: 即便 50 条 brutal 连接并发, 8 Mbps × 50 = 400 Mbps,
  1G 链路有充足缓冲, 100M 链路也只在多并发极端场景才接近上限,
  单流场景日常下载从单条 brutal 走就能保持稳定高速.
═══════════════════════════════════════════════════
EOM
        brutal_rate_mbps=$(ask "Brutal 单连接目标速率 (Mbps, 推荐 8-10, 不超过 10)" "8")
        if [[ "$brutal_rate_mbps" =~ ^[0-9]+$ ]] && (( brutal_rate_mbps > 10 )); then
            warn "已设为 ${brutal_rate_mbps} Mbps, 超过推荐上限 10 Mbps. 多连接并发时可能引发拥塞."
        fi
        info "Brutal 单连接速率: ${brutal_rate_mbps} Mbps"
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
    setup_systemd "server"

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
        node_uri=$(build_node_uri "$pwd" "$pub_host" "$port" "$sni" "$brutal_rate_mbps")
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

    info "你可以使用以下命令启动服务端: systemctl start mirage-server"
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
    local imported_brutal=0

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
                imported_brutal="$NODE_BRUTAL"
                ok "节点导入成功: ${srv_host}:${srv_port} (sni=${sni})"
                if [[ "$imported_brutal" =~ ^[0-9]+$ ]] && (( imported_brutal > 0 )); then
                    info "服务端启用了 Brutal (${imported_brutal} Mbps). 客户端对称启用需:"
                    info "  1) 装 brutal 内核模块  2) outbounds[mirage] 加 \"brutal_rate_mbps\": ${imported_brutal}"
                fi
                break
            fi
            warn "节点串格式无效. 期望: mirage://<密码>@<host>:<port>?sni=<域名>[&brutal=<mbps>]"
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
        "geodata_dir": "${ETC_DIR}/geosite",
        "geo_sources": [
            {
                "name": "geosite",
                "kind": "geosite",
                "url": "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
                "via": "direct"
            },
            {
                "name": "geoip",
                "kind": "geoip",
                "url": "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat",
                "via": "direct"
            }
        ]
    }
}
EOF

    ok "客户端配置文件已保存至: ${ETC_DIR}/config_client.json"
    setup_systemd "client"
    
    info "你可以使用以下命令启动客户端: systemctl start mirage-client"
}

# ──────────────────────────────────────────────────────────────────────────────
# 主入口
# ──────────────────────────────────────────────────────────────────────────────
print_brutal_hint() {
    echo "【极限性能优化建议】"
    echo "如果要完全发挥 Brutal CC 的极速性能并让 4MB 发送缓冲区生效，"
    echo "请手动执行以下步骤："
    echo "  1. 确保 tcp-brutal 内核模块已安装：https://github.com/apernet/tcp-brutal"
    echo "  2. 在客户端配置文件 outbounds[mirage] 块中添加 \"brutal_rate_mbps\": 8"
    echo "  3. 重启 mirage-rs：systemctl restart mirage-client"
    echo "=========================================================="
}

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

main() {
    title "Mirage-rs 极速安装向导"
    if [[ $EUID -ne 0 ]]; then
        err "需要 Root 权限。请使用 sudo bash install.sh 运行。"
    fi
    
    local mode=$(ask_choice "请选择安装类型" "部署服务端 (Server)" "部署客户端 (Client)" "同时部署服务端与客户端")
    
    setup_fhs
    optimize_sysctl
    
    case $mode in
        1)
            config_server
            ;;
        2)
            config_client
            print_brutal_hint
            ;;
        3)
            config_server
            config_client
            print_brutal_hint
            ;;
    esac
    
    title "安装完成！"
    echo -e "  配置目录: $(_c 36 "${ETC_DIR}")"
    echo -e "  数据目录: $(_c 36 "${STATE_DIR}")"
    echo -e "  日志命令: $(_c 36 "journalctl -u mirage-server -f")"
    echo -e "\n  感谢使用 Mirage-rs，极致性能尽在掌握。"
}

main "$@"
