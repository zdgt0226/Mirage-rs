// TC MSS clamp: 把转发的 TCP SYN/SYN-ACK 里的 MSS 选项钳制到 (MTU-40), 防 PMTU
// 黑洞 —— WAN 是 PPPoE(1492)/隧道等小 MTU 时, 大段无法分片会让部分站点大传输卡死。
// 借鉴 landscape xdp_mss.bpf.c 的 option 扫描, 改用 skb helper 修校验和 (适配 TC)。
//
// 挂 LAN 网卡 tc ingress (转发的 SYN 从这进)。只动 SYN 且 MSS 超限的包, 其余原样放行。

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct mss_cfg {
    __u32 mtu; // 路径 MTU (取两侧较小者), max_mss = mtu - 20(ip) - 20(tcp)
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct mss_cfg);
} mss_cfg SEC(".maps");

SEC("classifier")
int mss_clamp(struct __sk_buff *skb) {
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
    if (ip->ihl != 5 || ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;
    struct tcphdr *th = (void *)(ip + 1);
    if ((void *)(th + 1) > data_end)
        return TC_ACT_OK;
    if (!th->syn) // 只有 SYN/SYN-ACK 携带 MSS 选项
        return TC_ACT_OK;

    __u32 zero = 0;
    struct mss_cfg *cfg = bpf_map_lookup_elem(&mss_cfg, &zero);
    if (!cfg || cfg->mtu < 68)
        return TC_ACT_OK;
    __u16 max_mss = (__u16)(cfg->mtu - 40);

    __u8 doff = th->doff * 4;
    if (doff <= 20)
        return TC_ACT_OK;

    __u32 tcp_off = sizeof(*eth) + sizeof(*ip); // 34
    __u32 opt_base = tcp_off + 20;
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
            break; // End of options
        if (kind == 1) { // NOP
            opt++;
            pos++;
            continue;
        }
        __u8 olen = opt[1];
        if (olen < 2)
            break;
        if (kind == 2 && olen == 4) { // MSS
            if ((void *)(opt + 4) > data_end)
                break;
            __be16 old_mss = *(__be16 *)(opt + 2);
            if (bpf_ntohs(old_mss) > max_mss) {
                __be16 new_mss = bpf_htons(max_mss);
                __u32 mss_off = opt_base + pos + 2;
                __u32 csum_off = tcp_off + offsetof(struct tcphdr, check);
                bpf_l4_csum_replace(skb, csum_off, old_mss, new_mss, 2);
                bpf_skb_store_bytes(skb, mss_off, &new_mss, sizeof(new_mss), 0);
            }
            break;
        }
        pos += olen;
        opt += olen;
    }
    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
