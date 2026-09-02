# Mirage-rs 架构 / 原理图

用 [archify](https://github.com/tt-a1i/archify) 生成的独立交互 HTML (主题切换 / 缩放 / 导出)。
浏览器直接打开即可。图基于真实代码核对 (router 判定顺序、InboundConfig/OutboundNode 枚举、eBPF 职责)。

| 文件 | 类型 | 内容 |
|---|---|---|
| [`architecture.html`](architecture.html) | 架构 | 组件拓扑: 客户端/网关 (eBPF·入站·DNS/fake-IP·路由·出站) + 墙外服务端 (握手鉴权·camouflage) |
| [`connection-flow.html`](connection-flow.html) | 原理 | 连接处理 + 判定管线: 入站→取目标→规则引擎(首个命中)→限速→出站分派 |

源 spec (`*.json`) 同目录, 改后用 archify 重新 `deliver` 即可再生 HTML。
