# SPEC — P1 多用户凭据 (认证 + 统计 + 管理 API), v1 最小可用

用户确认: 执行 P1, v1 = 认证+统计+管理API (无配额/限速 enforcement, 留 v2)。存储 = config.json (复用 rules/profiles 模式)。
分支: `feat/multiuser-auth`。协议**零改动、向后兼容** (token 格式不变, 客户端不变)。

## 核心机制
token = `prefix(8)||hidden_ts(8)||poly1305_tag(16)`, tag 由 password 派生。服务端存**多凭据**, 握手对每个试 `verify_session_token` —— 非匹配在 tag 比对处即 false (不碰 replay), 命中那次才插 replay → **天然单插正确**。命中即认出 user, 用其 password 派生 session master (per-user 密钥隔离)。O(N) HMAC/握手, 小团队可忽略。

## 变更 (按文件)
1. **config.rs**: `MirageServer` 加 `#[serde(default)] users: Vec<MirageUser>`; `struct MirageUser { name, password }`。旧单 `password` 恒为凭据 "default" (向后兼容); users 追加。校验: name 非空且唯一, password 非空。
2. **hello_auth.rs**: 加 `identify_session_token(passwords: &[String], token, tol) -> Option<usize>` = `position(|pw| verify_session_token(pw,...))`。+ 单测 (命中索引 / 全不中 None / replay 只插一次)。
3. **mirage_server/handshake.rs**: `run_handshake` 参数 `password: &str` → `creds: &[(String,String)]` (name,pw); 返回值加命中的 `(name, password)`。auth 循环用 identify。
4. **mirage_server/control.rs**: 用命中 password 调 `create_crypto_pair(_pfs)` 派生密钥; user 名传 `monitor::register`。
5. **mirage_server/mod.rs**: QUIC(lean) 腿同样多凭据 (实验腿, 一致性)。装配处把 config 的 `password`+`users` 组装成 creds 列表传入。
6. **monitor.rs**: `register` 加 `user: Option<String>` 维度; per-user 聚合 (字节上/下行 + 活跃连接数)。查询接口供 API。
7. **api/handlers/users.rs** (新) + 路由: `GET /api/users` (列 name + per-user 用量, **绝不返 password**) · `POST /api/users` (改 config.json `inbounds[mirage_server].users`, 复用 profiles 的 CONFIG_WRITE_LOCK + 版本冲突 + parse 校验 + 原子写 + 热重载)。
8. **文档**: README 特性 + 安全声明更新 (单口令→多用户); CHANGELOG; API 契约 (给 Mirage-console 前端消费, 记 docs 或 PR 描述)。

## 不变量 (must not change)
- INV1 协议 wire 不变: 单用户 config (无 users) 行为逐字节同现状; 老客户端认证照通。
- INV2 per-user 密钥隔离: 每 user 用自己 password 派生 master, 不串。
- INV3 replay 防护不退化: 多凭据循环 replay 仍每 token 单插 (由 tag-fail-先返回保证, 测试锁)。
- INV4 password 绝不出 API/日志: GET /api/users 只返 name+用量; 日志不打 password。
- INV5 API 写 config 失败不落地 (parse 校验挡, 原子写)。

## Gauntlet
- 单测: identify_session_token (命中/未中/replay 单插) · 多用户握手 roundtrip (两 user 各自 password 认证成功 + 密钥隔离 + 错 password 拒) · config users 解析/校验 (空名/重名/空密码拒) · API users GET 不含 password / POST 改 config 生效。
- 全 `cargo test` · clippy `--all-targets -D warnings` · 单用户回归 (既有 mirage_server 测试全过 = 向后兼容)。

## v2 (不做, 记录): per-user 限速 (token bucket 按 user) · 流量配额 cap + 超额 enforcement + 计量持久化 · per-user 路由策略。
