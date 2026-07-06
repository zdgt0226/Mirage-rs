#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17
#endif

// 用于存储 TCP 监听 socket 的映射，大小为 1
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} mirage_listener_sk SEC(".maps");

// 用于存储 UDP 透明 socket 的映射，大小为 1
struct {
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} mirage_udp_sk SEC(".maps");

// 定义 fake_ip 网段，包含网络地址和子网掩码
struct fakeip_cfg { 
    __u32 net; 
    __u32 mask; 
};

// 存储 fake_ip 配置的映射
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct fakeip_cfg);
} mirage_fakeip_cfg SEC(".maps");

// eBPF 程序入口：当网络栈查找本地 socket 失败时触发
SEC("sk_lookup")
int mirage_sk_lookup(struct bpf_sk_lookup *ctx) {
    __u32 dst_ip = ctx->local_ip4;
    __u32 zero = 0;

    // 1. 获取并检查是否落入 fake-ip 网段
    struct fakeip_cfg *cfg = bpf_map_lookup_elem(&mirage_fakeip_cfg, &zero);
    if (!cfg) {
        return SK_PASS;
    }

    // 检查目的 IP 是否属于 fake_ip 范围（注意网络字节序）
    if ((dst_ip & cfg->mask) != cfg->net) {
        return SK_PASS;  // 不是 fake-ip，让正常流量走
    }

    // 2. 按协议选择目标 socket: UDP → udp socket, 其余 (TCP) → listener socket.
    //    sk_lookup 对 TCP/UDP 都会触发, 必须分流, 否则 UDP 包被 assign 到 TCP
    //    socket → 协议不匹配 → 丢弃 (原 UDP 透明失效的根因)。
    struct bpf_sock *sk;
    if (ctx->protocol == IPPROTO_UDP) {
        sk = bpf_map_lookup_elem(&mirage_udp_sk, &zero);
    } else {
        sk = bpf_map_lookup_elem(&mirage_listener_sk, &zero);
    }
    if (!sk) {
        return SK_PASS;
    }

    // 3. 将该连接/数据报指派给对应的透明代理 socket
    bpf_sk_assign(ctx, sk, 0);
    
    // 释放对 socket 的引用
    bpf_sk_release(sk);
    
    return SK_PASS;
}

char _license[] SEC("license") = "GPL";
