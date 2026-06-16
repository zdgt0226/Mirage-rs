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
