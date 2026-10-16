#!/usr/bin/env bash
# Mirage-rs 回环跨版本兼容性互通测试脚本
# 测试当前源码构建的服务端与上一个已发布的 Release 客户端二进制之间的双向互通性。
set -euo pipefail

REPO="${GITHUB_REPOSITORY:-zdgt0226/Mirage-rs}"
uname_m=$(uname -m)
if [[ "$uname_m" != "x86_64" ]]; then
    echo "[ERROR] 兼容性互通测试仅在 x86_64 Linux 环境运行 (当前: $uname_m)" >&2
    exit 1
fi

# 获取上一个已发布的 Release 标签
PREV_TAG="${PREV_RELEASE_TAG:-}"
if [[ -z "$PREV_TAG" ]]; then
    if command -v gh >/dev/null 2>&1; then
        PREV_TAG=$(gh release list --repo "$REPO" --limit 10 --json tagName,isDraft,isPrerelease \
            -q '[.[] | select(.isDraft == false and .isPrerelease == false)][0].tagName' 2>/dev/null || true)
    fi
fi
if [[ -z "$PREV_TAG" ]]; then
    PREV_TAG=$(curl -sfL -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/${REPO}/releases" 2>/dev/null \
        | python3 -c '
import json, sys
try:
    releases = json.load(sys.stdin)
    for r in releases:
        if not r.get("draft") and not r.get("prerelease"):
            print(r.get("tag_name", ""))
            break
except Exception:
    pass
' 2>/dev/null || true)
fi

if [[ -z "$PREV_TAG" ]]; then
    echo "[ERROR] 未能获取到已发布的 Release 版本标签，测试无法进行！" >&2
    exit 1
fi
echo "[*] 目标测试已发布版本: $PREV_TAG"

TMP_DIR=$(mktemp -d -t mirage-interop.XXXXXX)

HTTP_PID=""
SERVER_PID=""
CLIENT_PID=""

cleanup() {
    local ec=$?
    set +e
    echo "[*] 清理测试进程与临时资源..."
    [[ -n "$CLIENT_PID" ]] && kill "$CLIENT_PID" 2>/dev/null || true
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null || true
    [[ -n "$HTTP_PID" ]] && kill "$HTTP_PID" 2>/dev/null || true
    wait "$CLIENT_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
    wait "$HTTP_PID" 2>/dev/null || true
    if [[ -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
    exit "$ec"
}
trap cleanup EXIT INT TERM

# 下载上一版本客户端二进制与 SHA256SUMS
echo "[*] 下载 Release $PREV_TAG 资产 (mirage-rs-amd64 与 SHA256SUMS)..."
download_ok=false
if command -v gh >/dev/null 2>&1; then
    if gh release download "$PREV_TAG" --repo "$REPO" -p "mirage-rs-amd64" -p "SHA256SUMS" -D "$TMP_DIR"; then
        download_ok=true
    fi
fi
if [[ "$download_ok" != true ]]; then
    if curl -sSfL "https://github.com/${REPO}/releases/download/${PREV_TAG}/mirage-rs-amd64" -o "$TMP_DIR/mirage-rs-amd64" \
       && curl -sSfL "https://github.com/${REPO}/releases/download/${PREV_TAG}/SHA256SUMS" -o "$TMP_DIR/SHA256SUMS"; then
        download_ok=true
    fi
fi

if [[ "$download_ok" != true ]]; then
    echo "[ERROR] 下载 Release 资产失败！" >&2
    exit 1
fi

echo "[*] 校验 SHA256SUMS..."
(cd "$TMP_DIR" && sha256sum -c SHA256SUMS --ignore-missing) || {
    echo "[ERROR] SHA256SUMS 校验不匹配！" >&2
    exit 1
}
chmod +x "$TMP_DIR/mirage-rs-amd64"
CLIENT_BIN="$TMP_DIR/mirage-rs-amd64"
echo "[✓] 老版本客户端就绪: $("$CLIENT_BIN" --version)"

# 每次构建当前源码服务端并使用 ./target/release/mirage
echo "[*] 正在编译当前源码服务端 (cargo build --release --bin mirage)..."
cargo build --release --bin mirage
SERVER_BIN="./target/release/mirage"
if [[ ! -x "$SERVER_BIN" ]]; then
    echo "[ERROR] 未能生成服务端二进制: $SERVER_BIN" >&2
    exit 1
fi
echo "[✓] 当前源码服务端就绪: $("$SERVER_BIN" --version)"

# 端口分配与随机密码生成
get_free_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

HTTP_PORT=$(get_free_port)
SERVER_PORT=$(get_free_port)
SOCKS_PORT=$(get_free_port)

RANDOM_PWD=$(openssl rand -hex 16 2>/dev/null || python3 -c 'import secrets; print(secrets.token_hex(16))')

# 启动本地 HTTP 下载源
mkdir -p "$TMP_DIR/http_root"
PAYLOAD_FILE="$TMP_DIR/http_root/payload.bin"
head -c 8388608 /dev/urandom > "$PAYLOAD_FILE"
EXPECTED_SIZE=$(stat -c%s "$PAYLOAD_FILE")
EXPECTED_SHA=$(sha256sum "$PAYLOAD_FILE" | awk '{print $1}')
echo "[*] 创建测试文件: $EXPECTED_SIZE 字节 (SHA256: $EXPECTED_SHA)"

python3 -m http.server "$HTTP_PORT" --bind 127.0.0.1 --directory "$TMP_DIR/http_root" > "$TMP_DIR/http.log" 2>&1 &
HTTP_PID=$!

for _ in {1..30}; do
    if curl -sf "http://127.0.0.1:${HTTP_PORT}/payload.bin" --head >/dev/null 2>&1; then
        break
    fi
    sleep 0.2
done

# 启动服务端
SERVER_CFG="$TMP_DIR/server_config.json"
cat > "$SERVER_CFG" <<EOF
{
    "schema_version": 1,
    "log_level": "info",
    "inbounds": [
        {
            "type": "mirage_server",
            "tag": "server-in",
            "listen": "127.0.0.1",
            "port": ${SERVER_PORT},
            "password": "${RANDOM_PWD}",
            "camouflage_host": "www.apple.com",
            "allow_local_targets": true
        }
    ],
    "outbounds": [
        {
            "type": "direct",
            "tag": "direct"
        }
    ],
    "routing": {
        "default_outbound": "direct",
        "rules": []
    }
}
EOF

echo "[*] 启动当前源码服务端 (端口: 127.0.0.1:${SERVER_PORT})..."
"$SERVER_BIN" server -c "$SERVER_CFG" > "$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

for _ in {1..30}; do
    if python3 -c "import socket; s=socket.socket(); s.connect(('127.0.0.1', ${SERVER_PORT})); s.close()" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

# 启动老版本客户端
CLIENT_CFG="$TMP_DIR/client_config.json"
cat > "$CLIENT_CFG" <<EOF
{
    "schema_version": 1,
    "log_level": "info",
    "inbounds": [
        {
            "type": "socks",
            "tag": "socks-in",
            "listen": "127.0.0.1",
            "port": ${SOCKS_PORT}
        }
    ],
    "outbounds": [
        {
            "type": "mirage",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": ${SERVER_PORT},
            "password": "${RANDOM_PWD}",
            "camouflage_host": "www.apple.com"
        }
    ],
    "routing": {
        "default_outbound": "proxy",
        "rules": []
    }
}
EOF

echo "[*] 启动老版本客户端 (SOCKS 端口: 127.0.0.1:${SOCKS_PORT})..."
"$CLIENT_BIN" client -c "$CLIENT_CFG" > "$TMP_DIR/client.log" 2>&1 &
CLIENT_PID=$!

for _ in {1..30}; do
    if python3 -c "import socket; s=socket.socket(); s.connect(('127.0.0.1', ${SOCKS_PORT})); s.close()" 2>/dev/null; then
        break
    fi
    sleep 0.2
done

# 进行 3 次穿透下载测试
echo "[*] 开始回环互通下载验证 (3 次)..."
for i in 1 2 3; do
    DL_FILE="$TMP_DIR/download_${i}.bin"
    echo "  -> 第 ${i}/3 次下载..."
    if ! curl -sS --fail --max-time 30 --socks5 "127.0.0.1:${SOCKS_PORT}" \
        "http://127.0.0.1:${HTTP_PORT}/payload.bin" -o "$DL_FILE"; then
        echo "[ERROR] 第 ${i} 次下载失败！" >&2
        echo "=== 服务端日志 ===" >&2
        cat "$TMP_DIR/server.log" >&2
        echo "=== 客户端日志 ===" >&2
        cat "$TMP_DIR/client.log" >&2
        exit 1
    fi

    ACTUAL_SIZE=$(stat -c%s "$DL_FILE")
    ACTUAL_SHA=$(sha256sum "$DL_FILE" | awk '{print $1}')
    if [[ "$ACTUAL_SIZE" != "$EXPECTED_SIZE" || "$ACTUAL_SHA" != "$EXPECTED_SHA" ]]; then
        echo "[ERROR] 第 ${i} 次下载校验失败: 尺寸 $ACTUAL_SIZE (预期 $EXPECTED_SIZE), 哈希 $ACTUAL_SHA (预期 $EXPECTED_SHA)" >&2
        exit 1
    fi
    echo "     [✓] 第 ${i} 次下载通过 (大小: $ACTUAL_SIZE 字节, 哈希一致)"
done

echo "[✓] 全部 3 次下载均成功且数据一致！当前服务端与 Release $PREV_TAG 客户端回环互通完全正常。"
