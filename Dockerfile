# 多架构容器镜像: 直接装 Release CI 预编译的 **musl 静态二进制** (无 glibc 依赖)。
# 由 .github/workflows/release.yml 的 container job 用 buildx 构建 (linux/amd64,linux/arm64)。
# 本地构建示例 (需先把 mirage-rs-amd64-musl / mirage-rs-arm64-musl 放到构建上下文):
#   docker buildx build --platform linux/amd64,linux/arm64 -t mirage-rs .
FROM alpine:3.20

# TLS 根证书 (reqwest 拉取伪装模板 / geo 更新等需要)。
RUN apk add --no-cache ca-certificates

# buildx 按目标平台注入 TARGETARCH = amd64 / arm64, 恰好匹配产物命名 mirage-rs-<arch>-musl。
ARG TARGETARCH
COPY mirage-rs-${TARGETARCH}-musl /usr/local/bin/mirage
RUN chmod +x /usr/local/bin/mirage

ENTRYPOINT ["/usr/local/bin/mirage"]
