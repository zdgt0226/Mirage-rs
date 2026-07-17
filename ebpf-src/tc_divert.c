// TC ingress 透明分流 (eBPF TPROXY, 无 iptables/nftables)
//
// 挂在 LAN 网卡 tc clsact ingress. sk_lookup 只在本地投递触发, 抓不到转发的
// 裸-IP 流量; 本程序在 tc 层用 bpf_sk_assign 把要代理的转发流量"偷"进本地透明
// 监听 socket (等价 iptables TPROXY target, 但纯 eBPF 程序化挂载、无感)。
//
// Step 1: 跳过私网/本地, 其余 TCP(SYN+已建)/UDP 全 assign 给监听口, 分流(代理
// vs 直连)暂交用户态 router。Step 2 会在此加 LPM trie 做 BPF 内分流。
//
// 关键: 监听 socket 必须 IP_TRANSPARENT (收非本地目的包); sk_assign 后原始目的
// 地由 IP_TRANSPARENT/IP_RECVORIGDSTADDR 保留, 无需改包、无需 conntrack。

#include <linux/bpf.h>
#include <stddef.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define MIRAGE_FWMARK 0x1 // 被劫持包打此 mark, 配 ip rule fwmark→local 路由表

struct divert_cfg {
    __u32 listen_port; // 透明监听端口 (host order)
    __u32 mtu;         // MSS clamp: max_mss = mtu-40; 0 或 <68 表示关闭
};

// TCP SYN MSS clamp: 转发的 SYN/SYN-ACK 若 MSS 选项超 (mtu-40) 则钳制, 防小 MTU
// 路径 (PPPoE/隧道) 大段无法分片致大传输卡死。借鉴 landscape xdp_mss。
static __always_inline void clamp_tcp_mss(struct __sk_buff *skb, struct tcphdr *th,
                                          __u16 max_mss, void *data_end) {
    __u8 doff = th->doff * 4;
    if (doff <= 20)
        return;
    __u32 opt_base = ETH_HLEN + sizeof(struct iphdr) + 20; // 54 (ihl==5)
    __u32 csum_off = ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check);
    __u8 *opt = (__u8 *)th + 20;
    __u8 opts_len = doff - 20;
    __u8 pos = 0;

#pragma unroll
    for (int i = 0; i < 10; i++) {
        if (pos + 2 > opts_len)
            break;
        if ((void *)(opt + 2) > data_end)
            break;
        __u8 kind = opt[0];
        if (kind == 0)
            break;
        if (kind == 1) {
            opt++;
            pos++;
            continue;
        }
        __u8 olen = opt[1];
        if (olen < 2)
            break;
        if (kind == 2 && olen == 4) {
            if ((void *)(opt + 4) > data_end)
                break;
            __be16 old_mss = *(__be16 *)(opt + 2);
            if (bpf_ntohs(old_mss) > max_mss) {
                __be16 new_mss = bpf_htons(max_mss);
                bpf_l4_csum_replace(skb, csum_off, old_mss, new_mss, 2);
                bpf_skb_store_bytes(skb, opt_base + pos + 2, &new_mss, sizeof(new_mss), 0);
            }
            break;
        }
        pos += olen;
        opt += olen;
    }
}

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct divert_cfg);
} tc_divert_cfg SEC(".maps");

// 直连 CIDR 集 (用户态灌: 国内 geoip)。命中 → 不劫持, 交内核正常转发。
// 私网/本地/组播已由 is_direct_dst 硬编码兜底, 这里只放可加载的 geoip 段。
struct lpm_key {
    __u32 prefixlen;
    __be32 addr; // 网络序, 与 ip->daddr 同布局
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 65536);
    __type(key, struct lpm_key);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} direct_cidr SEC(".maps");

// 私网/本地/组播/广播 → 不劫持 (交内核正常处理)
static __always_inline int is_direct_dst(__u32 daddr_be) {
    __u32 d = bpf_ntohl(daddr_be);
    if ((d & 0xff000000) == 0x0a000000) return 1; // 10.0.0.0/8
    if ((d & 0xfff00000) == 0xac100000) return 1; // 172.16.0.0/12
    if ((d & 0xffff0000) == 0xc0a80000) return 1; // 192.168.0.0/16
    if ((d & 0xffc00000) == 0x64400000) return 1; // 100.64.0.0/10 (CGNAT/Tailscale/mesh/K8s)
    if ((d & 0xffff0000) == 0xa9fe0000) return 1; // 169.254.0.0/16 (链路本地/云元数据)
    if ((d & 0xff000000) == 0x7f000000) return 1; // 127.0.0.0/8
    if ((d & 0xf0000000) == 0xe0000000) return 1; // 224.0.0.0/4 multicast
    if (d == 0xffffffff) return 1;                // 255.255.255.255
    return 0;
}

SEC("classifier")
int tc_divert(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->ihl != 5) // 有 IP options 的少见, 简化跳过
        return TC_ACT_OK;
    // cfg 上移 (MSS clamp 需 mtu; listen_port 后面 assign 用)。
    __u32 zero = 0;
    struct divert_cfg *cfg = bpf_map_lookup_elem(&tc_divert_cfg, &zero);
    if (!cfg)
        return TC_ACT_OK;

    // 转发 TCP SYN 钳 MSS: 放在分流判定前, 覆盖直连 (TC_ACT_OK) 路径 —— 直连转发的
    // 大段才是 PMTU 黑洞高发区。改包后指针失效, 重新取。
    if (cfg->mtu >= 68 && ip->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)(ip + 1);
        if ((void *)(th + 1) <= data_end && th->syn) {
            clamp_tcp_mss(skb, th, (__u16)(cfg->mtu - 40), data_end);
            data = (void *)(long)skb->data;
            data_end = (void *)(long)skb->data_end;
            eth = data;
            if ((void *)(eth + 1) > data_end)
                return TC_ACT_OK;
            ip = (void *)(eth + 1);
            if ((void *)(ip + 1) > data_end)
                return TC_ACT_OK;
        }
    }

    if (is_direct_dst(ip->daddr))
        return TC_ACT_OK;
    // 命中 geoip 直连段 → 不劫持
    struct lpm_key k = { .prefixlen = 32, .addr = ip->daddr };
    if (bpf_map_lookup_elem(&direct_cidr, &k))
        return TC_ACT_OK;

    __be16 lport = bpf_htons((__u16)cfg->listen_port);

    struct bpf_sock *sk = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)(ip + 1);
        if ((void *)(th + 1) > data_end)
            return TC_ACT_OK;

        // 只对新连接的首 SYN 做 sk_assign → 透明 listener。已建连接的后续包
        // (含完成握手的 3rd ACK, 此时内核侧是 NEW_SYN_RECV request_sock) 若也
        // sk_assign 会打断 tcp_check_req 把 child 入 accept 队列的正常流程 →
        // 握手悬死 + RST。对它们只打 fwmark 走本地投递, 让内核自身的 established
        // 查找命中 child (child 靠 IP_TRANSPARENT 绑非本地 foreign 目的)。
        if (th->syn && !th->ack) {
            struct bpf_sock_tuple lt = {};
            lt.ipv4.daddr = bpf_htonl(0x7f000001); // 通配匹配 0.0.0.0:lport
            lt.ipv4.dport = lport;
            sk = bpf_sk_lookup_tcp(skb, &lt, sizeof(lt.ipv4), BPF_F_CURRENT_NETNS, 0);
            if (!sk)
                return TC_ACT_OK;
            goto assign;
        }
        // 已建流: 仅打 mark, 交内核本地投递 + established 查找。
        // 打 mark 前先探一下透明 listener 还在不在: 进程被 SIGKILL / 优雅停止后本
        // 程序仍挂在网卡上 (tc 过滤器持有 prog 引用, 不随进程消失), 而 fwmark→local
        // 路由表的 ip rule 由独立的 mirage-gw-nat.service 装、只在卸载时删。两者叠加
        // 会把 LAN 的每个已建流包引到 local 表却无 socket 可收 → 整段非直连 TCP 黑洞。
        // listener 不在就别打 mark, 让包走正常转发 —— 代理没了顶多不加速, 不该断网。
        struct bpf_sock_tuple lt = {};
        lt.ipv4.daddr = bpf_htonl(0x7f000001);
        lt.ipv4.dport = lport;
        sk = bpf_sk_lookup_tcp(skb, &lt, sizeof(lt.ipv4), BPF_F_CURRENT_NETNS, 0);
        if (!sk)
            return TC_ACT_OK;
        bpf_sk_release(sk);
        skb->mark = MIRAGE_FWMARK;
        return TC_ACT_OK;
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *uh = (void *)(ip + 1);
        if ((void *)(uh + 1) > data_end)
            return TC_ACT_OK;

        // UDP: 直接 assign 给主监听 socket (它靠 IP_ORIGDSTADDR 逐包 demux)
        struct bpf_sock_tuple lt = {};
        lt.ipv4.daddr = bpf_htonl(0x7f000001);
        lt.ipv4.dport = lport;
        sk = bpf_sk_lookup_udp(skb, &lt, sizeof(lt.ipv4), BPF_F_CURRENT_NETNS, 0);
        if (!sk)
            return TC_ACT_OK;
        goto assign;
    }
    return TC_ACT_OK;

assign:
    bpf_sk_assign(skb, sk, 0);
    // sk_assign 只设 skb->sk; 还需打 fwmark, 配 ip rule fwmark→local 路由表,
    // 否则外网目的 + ip_forward 会走转发路径, 不进 ip_local_deliver。
    skb->mark = MIRAGE_FWMARK;
    bpf_sk_release(sk);
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
