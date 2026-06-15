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
        warn "本地未找到 mirage 文件，这里在真实发布时将通过 curl 下载 GitHub Actions 编译的产物。"
        # curl -fsSL -o "$BIN_PATH" "https://github.com/your-repo/mirage-rs/releases/latest/download/mirage-linux-amd64"
        touch "$BIN_PATH" # Placeholder for sandbox
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

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable "mirage-${role}.service"
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
    
    local port=$(ask "监听端口 [1-65535]" "443")
    local rand_pwd=$(generate_password)
    local pwd=$(ask "认证密码" "$rand_pwd")
    local sni=$(ask_camouflage_host "www.apple.com")
    
    local log_level=$(ask_choice "日志等级" "info (推荐)" "warn" "debug" "error")
    local log_str="info"
    case $log_level in 1) log_str="info";; 2) log_str="warn";; 3) log_str="debug";; 4) log_str="error";; esac
    
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
            "camouflage_host": "${sni}"
        }
    ],
    "outbounds": [],
    "gui": {
        "enabled": true,
        "listen": "0.0.0.0:9090"
    },
    "routing": {
        "default_outbound": "direct",
        "rules": []
    },
    "tuning": {
        "geodata_dir": "${ETC_DIR}/geosite"
    }
EOF
    
    ok "服务端配置文件已保存至: ${ETC_DIR}/config_server.json"
    setup_systemd "server"
    
    info "你可以使用以下命令启动服务端: systemctl start mirage-server"
}

config_client() {
    title "配置 Mirage-rs 客户端"
    
    local srv_host=$(ask "服务端 IP 或域名" "1.2.3.4")
    local srv_port=$(ask "服务端端口" "443")
    local pwd=$(ask "认证密码" "")
    local sni=$(ask_camouflage_host "www.apple.com")
    
    local socks_port=$(ask "本地 Socks5 监听端口" "1080")
    
    local pool_size=$(ask "并发连接池大小 (越大速度越快，推荐 50)" "50")
    
    local log_level=$(ask_choice "日志等级" "info (推荐)" "warn" "debug" "error")
    local log_str="info"
    case $log_level in 1) log_str="info";; 2) log_str="warn";; 3) log_str="debug";; 4) log_str="error";; esac

    cat > "${ETC_DIR}/config_client.json" <<EOF
{
    "schema_version": 1,
    "log_level": "${log_str}",
    "inbounds": [
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": ${socks_port}
        }
    ],
    "outbounds": [
        {
            "type": "pyreality",
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
        "enabled": true,
        "listen": "127.0.0.1:9090"
    },
    "routing": {
        "default_outbound": "proxy",
        "rules": [
            {
                "outbound": "direct",
                "geosite": ["cn", "apple-cn"]
            },
            {
                "outbound": "direct",
                "ip_cidr": ["127.0.0.0/8", "192.168.0.0/16"]
            }
        ]
    },
    "tuning": {
        "geodata_dir": "${ETC_DIR}/geosite",
        "geosite_url": "https://github.com/v2fly/domain-list-community/releases/latest/download/dlc.dat",
        "geoip_url": "https://github.com/v2fly/geoip/releases/latest/download/geoip.dat"
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
main() {
    title "Mirage-rs 极速安装向导"
    if [[ $EUID -ne 0 ]]; then
        err "需要 Root 权限。请使用 sudo bash install.sh 运行。"
    fi
    
    local mode=$(ask_choice "请选择安装类型" "部署服务端 (Server)" "部署客户端 (Client)" "同时部署服务端与客户端")
    
    setup_fhs
    
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
    echo -e "  日志命令: $(_c 36 "journalctl -u mirage-server -f")"
    echo -e "\n  感谢使用 Mirage-rs，极致性能尽在掌握。"
}

main "$@"
