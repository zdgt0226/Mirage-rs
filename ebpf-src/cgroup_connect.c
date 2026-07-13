// cgroup/connect4 本机出向透明重定向 (纯 eBPF, 无 iptables)。
//
// tc_divert(ingress) 只抓转发流量; 本机自身发起的连接走本地出向、碰不到 ingress。
// 本程序在进程 connect() 时把要代理的目的 (fake-IP / 非直连外网) 改写为本地透明
// listener (127.0.0.1:lport), 让本机流量也能进代理。
//
// 难点: connect4 改写 dst 会丢掉原始 fake-IP, 而 listener 要靠原始目的反查域名。
// 故两步存原始目的:
//   ① connect4: 存 cookie→origdst (此刻源端口还没分配)
//   ② sockops TCP_CONNECT_CB (源端口已分配): 按 cookie 取回, re-key 成 srcport→origdst
// 服务端 accept 后按 peer 端口 (=客户端源端口) 查 srcport→origdst 拿回 fake-IP。
//
// 防环路: 跳过 dst == Mirage 服务端 IP:port (代理自己的隧道必须直连), 跳过直连/私网。

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char _license[] SEC("license") = "GPL";

struct connect_cfg {
    __u32 listen_ip;   // 网络序 (127.0.0.1)
    __u32 listen_port; // host 序
    __u32 server_ip;   // 网络序, 防环路旁路
    __u32 server_port; // host 序
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct connect_cfg);
} cc_cfg SEC(".maps");

struct orig_dst {
    __u32 ip;   // 网络序 (与 ctx->user_ip4 同布局)
    __u32 port; // host 序 (bpf_ntohs 后存, userspace 直接用)
};

// cookie → origdst (connect4 阶段, 源端口未知)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, struct orig_dst);
} cc_cookie SEC(".maps");

// 源端口(host) → origdst (sockops re-key, 供服务端按 peer 端口查)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, struct orig_dst);
} cc_port SEC(".maps");

static __always_inline int is_direct(__u32 daddr_be) {
    __u32 d = bpf_ntohl(daddr_be);
    if ((d & 0xff000000) == 0x0a000000) return 1; // 10/8
    if ((d & 0xfff00000) == 0xac100000) return 1; // 172.16/12
    if ((d & 0xffff0000) == 0xc0a80000) return 1; // 192.168/16
    if ((d & 0xff000000) == 0x7f000000) return 1; // 127/8 (含 listener 自身)
    if ((d & 0xffc00000) == 0x64400000) return 1; // 100.64/10
    if ((d & 0xffff0000) == 0xa9fe0000) return 1; // 169.254/16
    return 0;
}

SEC("cgroup/connect4")
int cc_connect4(struct bpf_sock_addr *ctx) {
    if (ctx->protocol != IPPROTO_TCP)
        return 1;
    __u32 zero = 0;
    struct connect_cfg *cfg = bpf_map_lookup_elem(&cc_cfg, &zero);
    if (!cfg)
        return 1;

    __u32 dip = ctx->user_ip4;              // 网络序
    __be16 dport = (__be16)ctx->user_port;  // 网络序

    // 防环路: 连 Mirage 服务端本身
    if (dip == cfg->server_ip && dport == bpf_htons((__u16)cfg->server_port))
        return 1;
    // 直连/私网/loopback 不改写
    if (is_direct(dip))
        return 1;

    __u64 cookie = bpf_get_socket_cookie(ctx);
    struct orig_dst od = { .ip = dip, .port = bpf_ntohs(dport) };
    bpf_map_update_elem(&cc_cookie, &cookie, &od, BPF_ANY);

    // 改写目的 → 本地透明 listener
    ctx->user_ip4 = cfg->listen_ip;
    ctx->user_port = bpf_htons((__u16)cfg->listen_port);
    return 1;
}

SEC("sockops")
int cc_sockops(struct bpf_sock_ops *skops) {
    if (skops->op != BPF_SOCK_OPS_TCP_CONNECT_CB)
        return 0;
    __u64 cookie = bpf_get_socket_cookie(skops);
    struct orig_dst *od = bpf_map_lookup_elem(&cc_cookie, &cookie);
    if (!od)
        return 0;
    __u32 sport = skops->local_port; // host 序
    bpf_map_update_elem(&cc_port, &sport, od, BPF_ANY);
    bpf_map_delete_elem(&cc_cookie, &cookie);
    return 0;
}
