---
id: no-doh-dot
title: "不用 DoH/DoT 作为抗审查手段"
category: decision
status: active
created: "2026-07-20T11:43:27"
updated: "2026-07-20T12:21:29"
---

## compiled_truth

**决定**:**不把 DoH/DoT 当作抗审查手段**。

**理由**(README 明确论证):墙内 DoT(853)端口**即封**;DoH(443)靠 SNI 阻断 + 封公共解析器 IP +
投毒,对公共解析器**长期不可靠**。加密到一个会被封/被投毒的解析器并不解决问题。

**替代路线**:抗审查靠 **fake-IP + 远端解析**(被墙域名走 fake-IP,真解析推到墙外服务端)+ 本地缓存 + 合理 TTL。
见 [[fakeip-remote-resolution]]。国内/直连域名走上游 UDP,并已加**多上游并行 + 重传**兜底
(单发单上游时上游丢一个包就会被客户端重传放大成 ~11s 卡顿)。

**注意区分**:这条**不**否定把 DoH/DoT 作为**功能特性**(给直连域名用)的价值 ——
roadmap 里 hickory 相关的 DoH/DoT 属另一件事;本页否定的是"用 DoH/DoT 来对抗审查"这个**定位**。


## timeline

- time: 2026-07-20T11:43:27
  kind: decision
  summary: "Created this page: 不用 DoH/DoT 作为抗审查手段"
  source: "README.md:263"
  affects: [no-doh-dot]

- time: 2026-07-20T12:21:29
  kind: decision
  summary: "记录抗审查 DNS 的路线取舍"
  source: "README.md:263"
  affects: [no-doh-dot]
