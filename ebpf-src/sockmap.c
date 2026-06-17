#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   
    __type(value, __u32); 
} mirage_sockmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} mirage_bpf_stats SEC(".maps");

struct ip_key {
    __u32 data[5];
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, struct ip_key);
    __type(value, __u8);
} mirage_target_ips SEC(".maps");

struct tcp_state {
    __u32 srtt_us;
    __u32 snd_cwnd;
    __u32 total_retrans;
    __u32 padding;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, struct ip_key);
    __type(value, struct tcp_state);
} mirage_rtt_map SEC(".maps");

static inline void extract_ip(struct bpf_sock_ops *skops, struct ip_key *key) {
    if (skops->family == 2) { // AF_INET
        key->data[0] = 2;
        key->data[1] = 0;
        key->data[2] = 0;
        key->data[3] = 0;
        key->data[4] = skops->remote_ip4;
    } else { // AF_INET6
        key->data[0] = 10;
        key->data[1] = skops->remote_ip6[0];
        key->data[2] = skops->remote_ip6[1];
        key->data[3] = skops->remote_ip6[2];
        key->data[4] = skops->remote_ip6[3];
    }
}

SEC("sockops")
int mirage_sockops(struct bpf_sock_ops *skops)
{
    int op = skops->op;
    
    // Request state callbacks when connection is established
    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_sock_ops_cb_flags_set(skops, 
            skops->bpf_sock_ops_cb_flags 
            | BPF_SOCK_OPS_STATE_CB_FLAG
            | BPF_SOCK_OPS_RTT_CB_FLAG);
    }
    
    if (op == BPF_SOCK_OPS_RTT_CB || op == BPF_SOCK_OPS_STATE_CB || op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        struct ip_key key = {};
        extract_ip(skops, &key);
        
        // Filter out non-mirage traffic
        if (!bpf_map_lookup_elem(&mirage_target_ips, &key)) {
            return 0;
        }

        struct tcp_state s = {
            .srtt_us = skops->srtt_us,
            .snd_cwnd = skops->snd_cwnd,
            .total_retrans = skops->total_retrans,
            .padding = 0,
        };
        
        if (s.srtt_us > 0) {
            bpf_map_update_elem(&mirage_rtt_map, &key, &s, BPF_ANY);
        }
    }
    return 0;
}

SEC("sk_skb/stream_verdict")
int mirage_stream_verdict(struct __sk_buff *skb)
{
    __u64 cookie = bpf_get_socket_cookie(skb);
    
    int ret = bpf_sk_redirect_hash(skb, &mirage_sockmap, &cookie, 0);
    
    // Track stats
    // 0: success, 2: drop/fallback
    __u32 key = (ret == SK_PASS) ? 0 : 2;
    __u64 *val = bpf_map_lookup_elem(&mirage_bpf_stats, &key);
    if (val) {
        (*val)++;
    }
    
    return ret;
}

char _license[] SEC("license") = "GPL";
