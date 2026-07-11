# 透明网关部署冒烟 checklist

> 适用: `v0.4.5-alpha.22+`,透明网关模式(fake-IP + sk_lookup + tc_divert 裸-IP 分流)。
> 目标: 一次性验通「LAN 设备 → 网关 → 出口」整链路。**每步给了预期 + 失败排查方向。**
> 前 6 步验功能,第 7 步验性能(LPM 是否成热点),第 8 步是回归项。

拓扑约定:

```
LAN 设备 (网关+DNS 都指向网关 LAN_IP)
      │
   [网关] eth_lan ← tc_divert 挂这;  eth_wan → NAT 出公网
      │  mirage-rs client 透明网关模式 (transparent:12345 + dns:53 + fake-IP)
      ▼
   Mirage 服务端 (境外) / 直连出口
```

准备两台机器: 一台当**网关**(装 mirage-rs client 网关模式),一台当 **LAN 设备**(默认网关 + DNS 都指网关的 LAN IP)。

---

## 0. 前置条件(网关上)

```bash
uname -r                                   # 内核 ≥ 5.9 (sk_lookup + tc bpf_sk_assign)
getcap $(command -v mirage-rs-client) 2>/dev/null   # 应有 cap_bpf,cap_net_admin (或以 root 跑)
mirage-rs-client --version                 # 应显示 v0.4.5-alpha.22+
ip rule list | grep 'fwmark 0x1'           # install.sh 应已加: fwmark 1 lookup 100
ip route show table 100                    # 应有: local default dev lo
sysctl net.ipv4.ip_forward                 # = 1
```

- ❌ 无 `cap_bpf` → tc_divert/sk_lookup 挂不上。`sudo setcap cap_bpf,cap_net_admin+ep <bin>` 或 root 跑。
- ❌ 无 fwmark 规则/table 100 → sk_assign 的包走转发不投本地(见 [README 透明网关章节] 或重跑 install.sh 网关模式)。

配置样例(网关 client `config.json` 关键片段,install.sh 网关模式自动生成):

```json
"inbounds": [
  { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "port": 1080 },
  { "type": "transparent", "tag": "transparent-in", "listen": "0.0.0.0",
    "port": 12345, "interface": "eth_lan" },
  { "type": "dns", "tag": "dns-in", "listen": "0.0.0.0", "port": 53 }
],
"advanced_dns": {
  "resolvers": [
    { "tag": "direct", "address": "223.5.5.5:53" },
    { "tag": "remote", "address": "8.8.8.8", "via": "proxy" }
  ],
  "fakeip": { "enabled": true, "inet4_range": "198.18.0.0/15" }
}
```

`interface` 必须填**面向 LAN 设备的网卡**,否则 tc_divert 不接管裸-IP 转发流量。

---

## 1. tc_divert 是否挂上

```bash
journalctl -u mirage-rs-client -b | grep -E 'tc_divert|direct_cidr'
tc filter show dev eth_lan ingress          # 应看到 direct-action 的 bpf 程序
```

- ✅ 预期日志: `tc_divert 已接管 eth_lan 上的裸-IP 转发流量 (N 段直连快路径)`,N > 0(geoip 已灌)。
- ❌ 无该行 → 查 `interface` 配了没 / eBPF 是否启用(日志有无 `eBPF ... DISABLED`)/ cap。
- ⚠️ N = 0 → geoip.dat 没加载。查 `.geosite/geoip.dat` 是否存在、`[ROUTE]` 规则是否引用了 geoip。

## 2. fake-IP DNS 解析(sk_lookup 路径)

在 **LAN 设备**上:

```bash
nslookup www.google.com <网关LAN_IP>       # 代理域名 → 应返回 198.18.x.x (fake-IP)
nslookup www.baidu.com  <网关LAN_IP>       # 国内域名 → 应返回真实 IP
```

- ❌ google 也返回真实 IP → fake-IP 没生效,DNS 没指对/`advanced_dns.fakeip` 没开。网关日志看 `[DNS]`/`[FAKEIP]` 标签。

## 3. 代理链路(fake-IP → 隧道 → 出口)

LAN 设备:

```bash
curl -s https://www.google.com -o /dev/null -w '%{http_code}\n'   # 应 200/301
curl -s https://ipinfo.io/ip                                       # 应显示**服务端**出口 IP
```

- 网关日志应有 `[ROUTE] ... → [proxy]` + `[TUNNEL]` 建立。
- ❌ 超时 → 见第 6 步 TCP 分水岭排查。

## 4. 裸-IP 分流(tc_divert 核心,无 DNS)

直接连 IP、绕过 DNS,验 tc_divert 的内核分流:

```bash
# LAN 设备: 境外裸 IP → 应走代理(出口=服务端 IP)
curl -s --resolve x:443:1.1.1.1 https://1.1.1.1 -o /dev/null -w '%{http_code}\n'
# LAN 设备: 国内裸 IP (在 geoip direct_cidr 内) → 应直连(出口=网关 WAN IP)
curl -s https://<某国内CDN_IP> -o /dev/null -w '%{http_code}\n'
```

- 网关日志: 境外 IP 有 `[ROUTE]→[proxy]`;国内 IP 有 `[DIRECT]` splice。

## 5. CGNAT / mesh / 链路本地不被劫持(alpha.22 修复回归)

若网关/LAN 有 Tailscale 等 mesh(100.64.0.0/10)或访问云元数据:

```bash
# LAN 设备经网关 ping mesh 对端 (100.64.x.x) — 应通,不被劫持
ping -c2 100.64.0.1
# 网关自身访问云元数据 — 应通
curl -s --max-time 3 http://169.254.169.254/ -o /dev/null -w '%{http_code}\n'
```

- ✅ 都应正常(走直连/转发)。网关日志**不应**出现把 100.64/169.254 当 proxy 的 `[ROUTE]`。
- ❌ mesh 断了 → `is_direct_dst` 没含该段(确认跑的是 alpha.22+)。

## 6. TCP listener 分水岭(已 netns 验证通过,真机复核)

`tc_divert` 抓 TCP 裸-IP 后 sk_assign 到透明 listener,accept 出的 socket 拿到**原始 foreign 目的**(`local_addr()`),决定透明 TCP 是否成立。**已在 netns 实测跑通**(`examples/verify_tc_divert_tcp.sh`,`v0.4.5-alpha.23+`):listener 用 IP_TRANSPARENT + BPF 只对首 SYN sk_assign、已建流仅打 fwmark。真机上再复核:

```bash
# 网关上,代理一条 TCP 时看反查目标是否 = 原始目的
journalctl -u mirage-rs-client -f | grep -E '\[TPROXY\].*TCP|\[ROUTE\]'
```

- ❌ 若代理 TCP 全部失败、但 UDP/DNS 正常 → 确认跑的是 `alpha.23+`(含 IP_TRANSPARENT listener + BPF SYN-only assign 两处修复);仍失败则抓包看 SYN-ACK 是否以原始 foreign IP 为源发出。

## 7. 🔬 LPM 是否成为 CPU 热点(决定要不要加 flow cache)

**背景**: `tc_divert` 对每个直连包查一次 `direct_cidr`(LPM 基数树,CN geoip ~8k–10k 前缀)。理论上千兆(~70k PPS)开销 <0.1% 核,不是瓶颈;但**用数据说话**,别凭感觉加缓存。

**制造负载**: LAN 设备从**国内 CDN 高速下载**(走直连路径,持续压满带宽):

```bash
# LAN 设备: 持续下载一个国内大文件, 打满上行/下行
curl -o /dev/null http://<国内CDN大文件URL>
```

**网关上同时测**(需 `perf`,`apt install linux-perf` / `dnf install perf`):

```bash
# ① 看软中断线程里 LPM 查找占比
perf top -e cycles -g --sort symbol 2>/dev/null | grep -iE 'trie_lookup_elem|ksoftirqd'
# ② 或采样 3 秒统计
perf record -a -g -- sleep 3 && perf report --stdout 2>/dev/null | grep -i trie_lookup_elem
# ③ 同时看 softirq CPU 占用
mpstat -P ALL 1 3 | awk '/Average/ {print $2, "%soft="$8}'
```

**判定阈值**:

| `trie_lookup_elem` 在 perf 中占比 | `%soft`(单核软中断) | 结论 |
|---|---|---|
| < 1% | < 20% | ✅ 不是瓶颈,**不要加缓存**(过早优化,还会和热重载互斥引泄漏) |
| 1% ~ 5% | 20% ~ 50% | 🟡 观察。若目标 >1G 或更大 geoip 表再考虑 |
| > 5% | > 60% 且吞吐上不去 | 🔴 确认是热点,**这时才**上带 reload 失效的 flow cache(不是裸 LRU) |

> 若确需缓存: key=目标 IP、value=直连/劫持,但**必须**在 `direct_cidr` 热重载时失效
> (generation 版本号 或 reload 清 LRU),否则改路由规则后旧缓存会让流量绕过代理泄漏。
> 裸 `LRU_HASH` 无失效 = bug。

## 8. 热重载刷新(回归)

```bash
# 网关: 往某 direct 规则的 ip_cidr 加一段, 保存 config.json
journalctl -u mirage-rs-client -f | grep -E 'Hot-reload|direct_cidr synced'
```

- ✅ 预期: `Hot-reload successful` + `tc_divert direct_cidr synced: M 段直连快路径`(M 变化),无需重启。

---

## 快速判据总表

| # | 项 | 一句话预期 |
|---|---|---|
| 1 | tc_divert attach | 日志 `tc_divert 已接管 ... (N 段)` |
| 2 | fake-IP DNS | 代理域名→198.18.x.x,国内域名→真实 IP |
| 3 | 代理链路 | `ipinfo.io/ip` 显示服务端出口 |
| 4 | 裸-IP 分流 | 境外裸 IP 走代理,国内裸 IP 直连 |
| 5 | mesh/元数据 | 100.64/169.254 不被劫持(alpha.22) |
| 6 | TCP 分水岭 | 代理 TCP 通(netns 已验;失败确认 alpha.23+) |
| 7 | LPM 热点 | `trie_lookup_elem` <1% → 不加缓存 |
| 8 | 热重载 | 改规则后 `direct_cidr synced` 自动刷 |
