#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/**
 * [Socket 重定向 Map]
 * 将网络包直接重定向到对应的 Socket 的关键结构。
 * 键(Key)是 Socket Cookie (__u64)，值(Value)是 Socket 的文件描述符映射。
 */
struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   
    __type(value, __u32); 
} mirage_sockmap SEC(".maps");

/**
 * [eBPF 核心统计信息 Map]
 * 每 CPU 数组，用于记录 BPF fast-path 的命中和失败包数。
 * 0: Success (命中并短路转发)
 * 2: Fallback (回退给 Linux 内核协议栈)
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u64);
} mirage_bpf_stats SEC(".maps");

// IP 地址在 BPF 映射中的键格式（支持 IPv4 / IPv6）
struct ip_key {
    __u32 data[5];
};

/**
 * [目标 IP 白名单 Map]
 * 仅用于过滤，只有发往/来自这些 IP 的流量才会被监控 RTT 等拥塞指标。
 * 避免无关背景流量污染数据。
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, struct ip_key);
    __type(value, __u8);
} mirage_target_ips SEC(".maps");

// 用户态需要的 TCP 底层指标结构体
struct tcp_state {
    __u32 srtt_us;       // 平滑往返时间（微秒）
    __u32 snd_cwnd;      // 当前发送拥塞窗口大小（报文段数）
    __u32 total_retrans; // 累计重传次数（感知丢包率的核心）
    __u32 data_segs_out; // 发送出去的总数据段数
};

/**
 * [TCP 状态 Map]
 * 内核提取到的拥塞指标将存入此 LRU 缓存，Rust 用户态会定期读取它
 * 键(Key)是 Socket Cookie，这避免了多个连接复用相同 IP 导致的数据混淆。
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct tcp_state);
} mirage_rtt_map SEC(".maps");

// 辅助函数：统一提取 IPv4/IPv6 为标准 ip_key 格式
static inline void extract_ip(struct bpf_sock_ops *skops, struct ip_key *key) {
    if (skops->family == 2) { // AF_INET (IPv4)
        key->data[0] = 2;
        key->data[1] = 0;
        key->data[2] = 0;
        key->data[3] = 0;
        key->data[4] = skops->remote_ip4;
    } else { // AF_INET6 (IPv6)
        key->data[0] = 10;
        key->data[1] = skops->remote_ip6[0];
        key->data[2] = skops->remote_ip6[1];
        key->data[3] = skops->remote_ip6[2];
        key->data[4] = skops->remote_ip6[3];
    }
}

/**
 * [SockOps 挂载点]
 * 拦截 Socket 状态变更事件，激活 TCP 拥塞参数的回调。
 * 当连接 RTT 更新时，自动将最新的指标写入 `mirage_rtt_map` 供用户态（Brutal 拥塞控制）分析。
 */
SEC("sockops")
int mirage_sockops(struct bpf_sock_ops *skops)
{
    int op = skops->op;
    
    // 当连接建立（主动或被动）时，强制向内核注册 RTT 变更回调
    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        bpf_sock_ops_cb_flags_set(skops, 
            skops->bpf_sock_ops_cb_flags 
            | BPF_SOCK_OPS_STATE_CB_FLAG
            | BPF_SOCK_OPS_RTT_CB_FLAG);
    }
    
    // 如果收到了我们订阅的回调（状态变更、RTT 刷新）
    if (op == BPF_SOCK_OPS_RTT_CB || op == BPF_SOCK_OPS_STATE_CB || op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB) {
        struct ip_key key = {};
        extract_ip(skops, &key);
        
        // 白名单检查：过滤掉与 Mirage 无关的流量
        if (!bpf_map_lookup_elem(&mirage_target_ips, &key)) {
            return 0;
        }

        struct tcp_state s = {
            .srtt_us = skops->srtt_us,
            .snd_cwnd = skops->snd_cwnd,
            .total_retrans = skops->total_retrans,
            .data_segs_out = skops->data_segs_out,
        };
        
        // 只有当获取到了有效延迟时才更新 Map
        if (s.srtt_us > 0) {
            __u64 cookie = bpf_get_socket_cookie(skops);
            bpf_map_update_elem(&mirage_rtt_map, &cookie, &s, BPF_ANY);
        }
    }
    return 0;
}

/**
 * [SK_SKB 挂载点：Stream Verdict]
 * 基于 Socket Cookie 执行零拷贝的 L4 旁路转发。
 * 这里不走 Linux 漫长的网络栈，直接引导数据包抵达目标 Socket 缓冲区。
 */
SEC("sk_skb/stream_verdict")
int mirage_stream_verdict(struct __sk_buff *skb)
{
    __u64 cookie = bpf_get_socket_cookie(skb);
    
    // 尝试在 SockMap 中寻找对应 Cookie 的关联 Socket 并转发
    int ret = bpf_sk_redirect_hash(skb, &mirage_sockmap, &cookie, 0);
    
    // 记录统计数据，供 GUI 前端 Neon Dashboard 展示
    // 0: success, 2: drop/fallback
    __u32 key = (ret == SK_PASS) ? 0 : 2;
    __u64 *val = bpf_map_lookup_elem(&mirage_bpf_stats, &key);
    if (val) {
        (*val)++;
    }
    
    return ret;
}

char _license[] SEC("license") = "GPL";
