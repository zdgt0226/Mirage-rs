#!/usr/bin/env bash
# ==============================================================================
# check-no-real-endpoints.sh
#
# 安全门禁检查：防止源码与文档中硬编码真实服务器地址、口令或密钥。
#
# 检查项：
# a. mirage://…@HOST 节点 URI（必须为 RFC 5737/3849 文档占位或保留域名）
# b. 环境变量或默认值回退为公网 IPv4 或长十六进制口令串 (>=24位)
# c. 源码与文档中出现的公网 IPv4 字面量（非保留/文档段且未列入 allowlist）
#
# 排除项说明：
# - *.lock (依赖锁文件)
# - *.dat (二进制规则集数据库)
# - 二进制文件 (由 git grep -I 自动跳过)
# - native/mirage-core/src/vendor/ (只读镜像上游代码)
# - target/ (编译产物)
# - CHANGELOG.md (历史发布说明段落，包含历史上报的 AS906 测速网段等审计记录)
# ==============================================================================
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$REPO_ROOT"

ALLOWLIST_FILE="scripts/endpoint-allowlist.txt"
if [[ ! -f "$ALLOWLIST_FILE" ]]; then
    echo "[-] 错误: 白名单文件 $ALLOWLIST_FILE 不存在" >&2
    exit 1
fi

PATH_EXCLUDES=(
    ':!*.lock'
    ':!*.dat'
    ':!native/mirage-core/src/vendor/**'
    ':!target/**'
    ':!CHANGELOG.md'
    ':!scripts/endpoint-allowlist.txt'
    ':!scripts/check-no-real-endpoints.sh'
)

# 加载白名单至关联数组
declare -A ALLOWED_MAP=()
while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line%%#*}"
    line="$(echo "$line" | tr -d '[:space:]')"
    [[ -z "$line" ]] && continue
    ALLOWED_MAP["$line"]=1
done < "$ALLOWLIST_FILE"

is_public_ipv4() {
    local ip="$1"
    local a b c d
    IFS=. read -r a b c d <<< "$ip"
    [[ "$a" =~ ^[0-9]+$ && "$b" =~ ^[0-9]+$ && "$c" =~ ^[0-9]+$ && "$d" =~ ^[0-9]+$ ]] || return 1
    (( a <= 255 && b <= 255 && c <= 255 && d <= 255 )) || return 1

    # 0.0.0.0/8
    (( a == 0 )) && return 1
    # 10.0.0.0/8
    (( a == 10 )) && return 1
    # 100.64.0.0/10 (RFC 6598 CGNAT)
    (( a == 100 && b >= 64 && b <= 127 )) && return 1
    # 127.0.0.0/8
    (( a == 127 )) && return 1
    # 169.254.0.0/16
    (( a == 169 && b == 254 )) && return 1
    # 172.16.0.0/12
    (( a == 172 && b >= 16 && b <= 31 )) && return 1
    # 192.0.0.0/24 (IETF Protocol Assignments)
    (( a == 192 && b == 0 && c == 0 )) && return 1
    # 192.0.2.0/24 (RFC 5737 TEST-NET-1)
    (( a == 192 && b == 0 && c == 2 )) && return 1
    # 192.168.0.0/16
    (( a == 192 && b == 168 )) && return 1
    # 198.18.0.0/15 (RFC 2544 Benchmarking / Fake-IP)
    (( a == 198 && (b == 18 || b == 19) )) && return 1
    # 198.51.100.0/24 (RFC 5737 TEST-NET-2)
    (( a == 198 && b == 51 && c == 100 )) && return 1
    # 203.0.113.0/24 (RFC 5737 TEST-NET-3)
    (( a == 203 && b == 0 && c == 113 )) && return 1
    # 224.0.0.0/4 (Multicast)
    (( a >= 224 && a <= 239 )) && return 1
    # 240.0.0.0/4 (Reserved / Bogon / Broadcast 255.255.255.255)
    (( a >= 240 )) && return 1

    return 0
}

FAILED=0

# ── 检查 a: mirage://…@HOST 节点链接必须使用文档保留地址 ──────────────────────
echo "[*] [Check A] 正在扫描 mirage:// 节点链接格式与端点..."

matches_a=$(git grep --untracked -n -I -E 'mirage://' -- "${PATH_EXCLUDES[@]}" || true)
if [[ -n "$matches_a" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        file="${line%%:*}"
        rest="${line#*:}"
        line_no="${rest%%:*}"
        content="${rest#*:}"

        cur="$content"
        while [[ "$cur" =~ mirage://([^@[:space:]\"\'\`<>]+)@([^:/?[:space:]\"\'\`<>\)]+|\[[^]]+\]) ]]; do
            matched_full="${BASH_REMATCH[0]}"
            host="${BASH_REMATCH[2]}"
            host="${host#[}"
            host="${host%]}"

            valid=0
            # 过滤代码模板/正则变量 (如 $host, $maskedHost, 包含正则元字符等)
            if [[ "$matched_full" =~ [\\^\(\)] || "$host" =~ ^\$ || "$host" =~ [\\^\(\)] ]]; then
                valid=1
            elif [[ "$host" == "127.0.0.1" || "$host" == "localhost" || "$host" == "::1" ]]; then
                valid=1
            elif [[ "$host" =~ ^192\.0\.2\.[0-9]+$ || "$host" =~ ^198\.51\.100\.[0-9]+$ || "$host" =~ ^203\.0\.113\.[0-9]+$ ]]; then
                valid=1
            elif [[ "$host" =~ ^[2001]:0*[dD][bB]8: || "$host" =~ ^2001:0*[dD][bB]8: ]]; then
                valid=1
            elif [[ "$host" =~ (\.example|\.example\.com|example\.com|\.test|\.invalid|\.localhost)$ ]]; then
                valid=1
            elif [[ "$host" == "host" || "$host" == "hostonly" || "$host" == "h" || "$host" == "端口" ]]; then
                valid=1
            elif [[ -n "${ALLOWED_MAP[$host]:-}" ]]; then
                valid=1
            fi

            if [[ $valid -eq 0 ]]; then
                echo "${file}:${line_no}: [Check A] 发现未授权 mirage:// 节点主机: $host"
                FAILED=1
            fi
            cur="${cur#*"$matched_full"}"
        done
    done <<< "$matches_a"
fi

# ── 检查 b: 环境变量回退默认值是公网 IPv4 或长十六进制串 ────────────────────
echo "[*] [Check B] 正在扫描环境变量回退默认值与硬编码长口令/公网地址..."

matches_b_hex=$(git grep --untracked -n -I -E '(unwrap_or|\?:|\$\{[^}]*:-).*([0-9a-fA-F]{24,})' -- "${PATH_EXCLUDES[@]}" || true)
if [[ -n "$matches_b_hex" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        file="${line%%:*}"
        rest="${line#*:}"
        line_no="${rest%%:*}"
        echo "${file}:${line_no}: [Check B] 命中环境变量回退或默认长口令十六进制串: $line"
        FAILED=1
    done <<< "$matches_b_hex"
fi

matches_b_ip=$(git grep --untracked -n -I -E '(unwrap_or|\?:|\$\{[^}]*:-).*([0-9]{1,3}\.){3}[0-9]{1,3}' -- "${PATH_EXCLUDES[@]}" || true)
if [[ -n "$matches_b_ip" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        file="${line%%:*}"
        rest="${line#*:}"
        line_no="${rest%%:*}"
        content="${rest#*:}"

        cur="$content"
        while [[ "$cur" =~ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; do
            ip="${BASH_REMATCH[1]}"
            if is_public_ipv4 "$ip"; then
                if [[ -z "${ALLOWED_MAP[$ip]:-}" ]]; then
                    echo "${file}:${line_no}: [Check B] 命中环境变量回退公网 IPv4 默认值: $ip"
                    FAILED=1
                fi
            fi
            cur="${cur#*"$ip"}"
        done
    done <<< "$matches_b_ip"
fi

# ── 检查 c: 源码与文档中的公网 IPv4 字面量 ──────────────────────────────────
echo "[*] [Check C] 正在扫描源码与文档中的未授权公网 IPv4 字面量..."

matches_c=$(git grep --untracked -n -I -E '([0-9]{1,3}\.){3}[0-9]{1,3}' -- "${PATH_EXCLUDES[@]}" || true)
if [[ -n "$matches_c" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        file="${line%%:*}"
        rest="${line#*:}"
        line_no="${rest%%:*}"
        content="${rest#*:}"

        cur="$content"
        while [[ "$cur" =~ ([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}) ]]; do
            ip="${BASH_REMATCH[1]}"
            if is_public_ipv4 "$ip"; then
                if [[ -z "${ALLOWED_MAP[$ip]:-}" ]]; then
                    echo "${file}:${line_no}: [Check C] 发现未在白名单中的公网 IPv4 字面量: $ip"
                    FAILED=1
                fi
            fi
            cur="${cur#*"$ip"}"
        done
    done <<< "$matches_c"
fi

if [[ $FAILED -eq 0 ]]; then
    echo "[✓] 扫描通过：未发现泄露真实服务器地址、口令或未授权公网端点 (0 命中)。"
    exit 0
else
    echo "[-] 扫描失败：检测到潜在敏感端点或未加白公网地址，请按规则处理。" >&2
    exit 1
fi
