---
id: camouflage-forward-on-auth-fail
title: "认证失败不报错, 转发到真实伪装站"
category: decision
status: active
created: "2026-07-20T11:43:26"
updated: "2026-07-20T12:19:19"
---

## compiled_truth

**决定**:服务端握手认证失败时**不返回任何错误**,而是把该 TCP 连接**转发到真实的伪装站**
(`camouflage_host`),让探针拿到真站的完整响应。

**真机验证已满分通过**(外部机器对 VPS 探测,SNI=speedtest.net):
- 证书与直连真站**完全一致**(subject/issuer/notBefore/notAfter 精确到秒);
- `TLSv1.3` + `Verify return code: 0 (ok)`,握手完整走完;
- `curl --resolve` 拿到 `HTTP/2 301` + `server: Varnish` = 真 Ookla 后端应答,ALPN h2 正确透传。

**关键推理**:TLS1.3 下 Certificate 在加密 flight 里;能读出且验得过 ⇒ 本次会话是**真实 ECDH** ⇒
排除"回放缓存模板"(回放的 flight 用抓取时的会话密钥加密,本次 ECDH 根本解不开)。

**常见误解(需纠正)**:有分析称"探针被转发后能看到目标站的 TCP 指纹"——**错**。
转发是 `copy_bidirectional` 两条独立 TCP 在应用层搬字节,探针的 TCP 终结在 Mirage 自己的 Linux 栈,
`splice` 不桥接 TCP 层。探针与合法客户端看到**同一个** Linux TCP 指纹。

**影响面**:这是**像 Reality 的强项**,不是弱点。但它只解决**主动探测**,不改变
SNI/IP/ASN 不一致这个**被动**暴露面(见 [[tls-fingerprint-mimicry]])。两者别混淆。


## timeline

- time: 2026-07-20T11:43:26
  kind: decision
  summary: "Created this page: 认证失败不报错, 转发到真实伪装站"
  source: "src/proxy/mirage_server/camouflage.rs, 真机探测验证"
  affects: [camouflage-forward-on-auth-fail]

- time: 2026-07-20T12:19:19
  kind: decision
  summary: "沉淀抗主动探测机制及其真机验证结论"
  source: "src/proxy/mirage_server/camouflage.rs, 真机探测"
  affects: [camouflage-forward-on-auth-fail]
