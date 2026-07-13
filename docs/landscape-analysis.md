# Landscape 项目借鉴分析

对 `/opt/claude/landscape`(Rust + eBPF 把 Linux 改造成网关的项目)的架构分析,以及
可被 Mirage-rs 吸收的设计。2026-07-13。

## Landscape 是什么

纯**路由/网关**(无代理隧道),核心卖点:**DNS 驱动的按域名分流** —— 每个 flow(按
IP/MAC 分组的设备策略组)有独立 Hickory DNS(独立缓存/上游 UDP/DoH/DoT/DoQ);DNS 答案
灌进 per-flow eBPF map,XDP/TC 读 map 线速转发。**"无用户态数据面、无 iptables"**。

数据面比我们重得多:完整 XDP+TC chain(root→stage→exit 流水线)、**eBPF 内全锥 NAT4/NAT6**
(基于 einat-ebpf)、MSS clamp、firewall、PPPoE、metrics(ringbuf)、tproxy(重定向进 Docker)。

**关键约束**:要求内核 **≥ 6.9 + BTF/CO-RE**(用 vmlinux.h)。Mirage-rs 部署目标内核偏老
(部署机曾 sk_lookup sockmap EINVAL),**它的 eBPF 代码并非拿来即用**。

## 可吸收项(按优先级)

| 优先级 | 借鉴点 | 价值 | 成本 |
|---|---|---|---|
| P1 | **MSS clamp**(TC/XDP 钳制 TCP MSS = MTU−40) | 网关经典坑:大传输/部分站点 PMTU 黑洞卡死。直连转发若 WAN=PPPoE(1492)必中。~30 行 | 低 |
| P2 | **tproxy IPv4+IPv6 双栈**(同一 sk_lookup+sk_assign) | 补 tc_divert 的 IPv6 缺口 | 中 |
| P2 | **einat-ebpf 全锥 NAT**(纯 eBPF NAT4/6, 零 MASQUERADE) | 真正实现"零 iptables"初衷(我们直连回程仍留 1 条 MASQUERADE) | 高 |
| P2 | **`union u_ld_ip` 统一 v4/v6 地址抽象** | 将来给 tc_divert/cgroup_connect 加 v6 少写一半分支 | 低 |
| P3 | NAT/conn metrics 走 **BPF ringbuf** 逐连接上报 | 实时连接级指标的干净范式 | 中 |
| P3 | **per-flow DNS 隔离**(设备组各自独立 DNS/缓存/上游) | 多策略/多租户场景才需要 | 中 |

## 明确不吸收(会走偏)

- **DNS→真实IP 灌 map 分流**(Landscape 核心):对纯路由器合理,但对**抗审查代理是错的**
  —— 要求客户端先解析到真实 IP,墙内 DNS 可能被污染。我们的 **fake-IP + 服务端远程解析**
  正是为了不信任本地 DNS,**必须保留**。见 [[architecture-decisions]]。
- **全 XDP+TC chain 流水线**:线速转发才需要;我们代理路径走用户态隧道,XDP 又不能
  sk_assign,收益低、复杂度爆炸。
- **sea-orm SQLite + DB 迁移**:我们 JSON 配置 + 热重载更轻、契合规模。其"配置版本化/
  前后兼容"理念可留意,但不必上 DB。

## 落地建议

1. **最划算先做:MSS clamp**。真机冒烟若见"小请求通、大下载/某些站点卡死",几乎必是它。
   可像 tc_divert 一样先 netns 验证再上。**判定**:`ip link` 看 WAN MTU < 1500(PPPoE/隧道
   母网)则强烈建议加。
2. **einat 别自己重写**:einat-ebpf 是独立 GPL 项目(数千行:端口分配、bpf 内 conntrack、
   校验和、fragment 处理),自己实现是巨坑。若那 1 条 MASQUERADE 真要消掉,**直接 vendor
   einat**,不要重造。P2、非紧急。
3. **IPv6**:主链路真机稳定后,用 `u_ld_ip` 抽象一次性给 tc_divert + tproxy + cgroup_connect
   上 v6。

## 关键源码位置(备查)

- NAT(einat 血统):`landscape-ebpf/src/bpf/land_nat4_v3.h`、`einat_helpers.h`、`einat_nat4.h`、
  `xdp_nat.bpf.c`、`tc_chain/tc_nat.bpf.c`
- tproxy:`landscape-ebpf/src/bpf/tproxy.bpf.c`(sk_lookup→sk_assign, v4/v6)
- MSS:`xdp_mss.bpf.c` / `tc_chain/tc_mss.bpf.c`(`mtu_size=1492`, `max_mss = mtu - iphdr - 20`)
- DNS→map:`landscape-ebpf/src/map_setting/flow_dns.rs`(per-flow LruHash {IP→FlowMarkInfo})
- per-flow DNS:`landscape-dns/src/server.rs`、`listener/doh.rs`、`start_flow_dns_listener`
- 配置迁移:`landscape-database/migration/src/*`(sea-orm 版本化 up/down)
