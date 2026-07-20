---
id: auth-ts-bootstrap-deadlock
title: "认证时间容差可配置: 紧窗口 + TIME_SYNC 在 auth 之后 = bootstrap 死锁"
category: decision
status: active
created: "2026-07-20T11:43:27"
updated: "2026-07-20T12:20:56"
---

## compiled_truth

**故障**:两端时钟偏差 >10s 时,客户端**永久**连不上 —— 服务端刷 `auth failed`,客户端刷
`TIME_SYNC decryption failed`。密码一致、TCP 通,排查一度误判为认证 bug。

**根因是设计缺陷,不是数值问题**:
- 首次握手用的是客户端**未经 TIME_SYNC 校正**的裸系统时钟(`TIME_OFFSET` 初始为 0);
- 而 `TIME_SYNC` 帧**只在 auth 成功后**才下发;
- ⇒ auth 卡在时间窗口上 → TIME_SYNC 永远 bootstrap 不了 → **偏差大的机器永久锁死**。
- 且 auth 失败必须走 camouflage 转发(见 [[camouflage-forward-on-auth-fail]]),**不能**回时间提示,
  否则破坏抗探测 —— 所以那个窗口是首次握手的唯一容错。

**决定**:`TOKEN_TS_TOLERANCE_SECS` 改为服务端 config `auth_ts_tolerance_secs`(**默认 60**,旧 config 兼容);
重放缓存保留桶数从容差自动推导;客户端"TIME_SYNC 解密失败"改为一次性详细提示(查密码/时钟/NTP)。
注:10s 是此前从 60s 收紧的,理由"已经有 TIME_SYNC 了"**忽略了 bootstrap 死锁**。

**同一病灶群**:NTP 若走代理 → 隧道挂则 NTP 同步不了 → 时钟更偏 → 隧道更挂,**死循环**。
建议路由加 `{"outbound":"direct","port":[123]}`。网关授时不能依赖它自己要建的隧道。

**教训**:auth 令牌带时间戳 + 紧窗口,而校准时间的通道又在 auth **之后** = bootstrap 死锁。
**收紧任何安全窗口前先问:失败时能否自恢复?**


## timeline

- time: 2026-07-20T11:43:27
  kind: decision
  summary: "Created this page: 认证时间容差可配置: 紧窗口 + TIME_SYNC 在 auth 之后 = bootstrap 死锁"
  source: "git 3f0aa00, 真机 e2e"
  affects: [auth-ts-bootstrap-deadlock]

- time: 2026-07-20T12:20:56
  kind: decision
  summary: "沉淀真机 e2e 撞到的设计缺陷与教训"
  source: git 3f0aa00
  affects: [auth-ts-bootstrap-deadlock]
