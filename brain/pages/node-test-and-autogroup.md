---
id: node-test-and-autogroup
title: "节点测活 (mirage test) + 导入建组 (opt-in urltest, 不擅自改路由)"
category: decision
status: active
tags: [cli, import, probe, urltest, routing]
created: "2026-07-26T16:50:20"
updated: "2026-07-26T19:08:31"
---

## compiled_truth

## 背景

用户提议: import 时测节点可用才导入; 导入后代理数>1 自动切 RTT 选路。评估后**去自动化** ——
用户接受。

## 决定

1. **`mirage-rs test` 子命令**: 测 mirage 出站可用性, 走**完整握手 + 解密服务端首帧确认认证**。
   裸 TCP connect 不算 (伪装前置是真站点, :443 本就通)。认证没过→服务端转伪装站→会话密钥
   解不开其真 TLS = 确定的"密码不符/非 Mirage/时钟偏差"信号。`proxy::probe::probe_mirage`
   复用客户端握手原语 (hello_auth + tls_raw + read_server_handshake + create_crypto_pair),
   判定更严: 必须 recv_data 解密成功。结果 Ok/Unconfirmed(旧服务端无 TIME_SYNC)/Fail。

2. **import 测活**: `--test` 告警仍导入; `--require-live` 不可用则拒绝 (即"可用才导入")。

3. **import 建组 (opt-in)**: `--group [--group-name auto]` 建/更新 urltest 组纳入全部
   mirage 节点 + 把 default_outbound 指向它 = RTT 自动选路。**默认不动路由**, 只在代理>1 时
   打印建议 (给现成片段)。apply_urltest_group: 同名非 urltest 出站拒绝占用; 幂等 (更新成员)。

## 为什么不自动切 RTT (对用户原提议的 pushback)

- import 现在刻意不碰 routing。静默重写 default_outbound = 最小惊讶违背 + 危险。
- 手动路由常是故意的 (Netflix-JP 走日本落地、按 inbound 分家人)。RTT-最低会把解锁流量甩给
  低延迟节点 → 解锁崩。故"建议而非强加", 显式 --group 才改。

## 验证

端到端对真 lite-server: 对密码=可用/错密码=认证失败/死端口/挂起=握手超时。import 各 flag
(建议/--group/幂等/--require-live 拦截+不改配置/--test 告警仍导入) 实测。单测: mirage_outbounds
抽取 · apply_urltest_group (建组/幂等/拒占名)。

关联 [[dns-direct-upstream-tcp]] (同期 CLI/DNS 改进)。


## timeline

- time: 2026-07-26T16:50:20
  kind: decision
  summary: "Created this page: 节点测活 (mirage test) + 导入建组 (opt-in urltest, 不擅自改路由)"
  source: feat/node-test-and-autogroup
  affects: [node-test-and-autogroup]

- time: 2026-07-26T16:50:20
  kind: decision
  summary: "mirage test 走真握手+解密认证测活(裸TCP不算); import 建组是 opt-in(--group才改default_outbound), 默认只建议不静默改路由(护 region-unlock/per-inbound 意图)"
  source: brain update-truth
  affects: [node-test-and-autogroup]

- time: 2026-07-26T16:50:46
  kind: note
  summary: "端到端全部路径已对真 lite-server 验证; CLI 各 flag 实测通过"
  source: feat/node-test-and-autogroup
  affects: [node-test-and-autogroup]

- time: 2026-07-26T16:58:48
  kind: decision
  summary: "mirage test 走真握手+解密认证测活(裸TCP不算); import 建组是 opt-in(--group才改default_outbound), 默认只建议不静默改路由(护 region-unlock/per-inbound 意图)"
  source: brain update-truth
  affects: [node-test-and-autogroup]

- time: 2026-07-26T18:48:00
  kind: note
  summary: "Sonnet 审计修 4 条: probe 握手超时下限 15s(护慢链路, 修 HIGH 误判)、apply_urltest_group routing 缺失则创建、server_port try_from 防截断、解密失败措辞软化; import 加 --timeout"
  source: feat/node-test-and-autogroup
  affects: [node-test-and-autogroup]

- time: 2026-07-26T19:08:31
  kind: note
  summary: "group 加可调 urltest 参数 flag (interval/tolerance/test-type/url), 未给建组默认更新保留"
  source: abf284a
  affects: [node-test-and-autogroup]
