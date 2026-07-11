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
};

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
    if (is_direct_dst(ip->daddr))
        return TC_ACT_OK;
    // 命中 geoip 直连段 → 不劫持
    struct lpm_key k = { .prefixlen = 32, .addr = ip->daddr };
    if (bpf_map_lookup_elem(&direct_cidr, &k))
        return TC_ACT_OK;

    __u32 zero = 0;
    struct divert_cfg *cfg = bpf_map_lookup_elem(&tc_divert_cfg, &zero);
    if (!cfg)
        return TC_ACT_OK;
    __be16 lport = bpf_htons((__u16)cfg->listen_port);

    struct bpf_sock *sk = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *th = (void *)(ip + 1);
        if ((void *)(th + 1) > data_end)
            return TC_ACT_OK;

        // 1) 已建流 (同 4 元组): 该流之前已 assign 给代理 accept 出的 socket
        //    (其 local_addr = 原始 foreign dst, 靠 IP_TRANSPARENT 保留)。
        struct bpf_sock_tuple ft = {};
        ft.ipv4.saddr = ip->saddr;
        ft.ipv4.daddr = ip->daddr;
        ft.ipv4.sport = th->source;
        ft.ipv4.dport = th->dest;
        sk = bpf_sk_lookup_tcp(skb, &ft, sizeof(ft.ipv4), BPF_F_CURRENT_NETNS, 0);
        if (sk)
            goto assign;

        // 2) 新流 (SYN): 查透明监听 socket (127.0.0.1:lport, 通配匹配 0.0.0.0)
        struct bpf_sock_tuple lt = {};
        lt.ipv4.daddr = bpf_htonl(0x7f000001);
        lt.ipv4.dport = lport;
        sk = bpf_sk_lookup_tcp(skb, &lt, sizeof(lt.ipv4), BPF_F_CURRENT_NETNS, 0);
        if (!sk)
            return TC_ACT_OK;
        goto assign;
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
