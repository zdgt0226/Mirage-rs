#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// v0.4.5-alpha.3: mirage_sockmap (SOCKHASH) + mirage_bpf_stats (PERCPU_ARRAY) +
// sk_skb/stream_verdict 已全部删除. 参考 dae 结论 (control/kern/tproxy.c:178) sockmap
// redirect 家族 (sk_msg/sk_skb + bpf_*_redirect_hash) 在 kernel 6.x 有 panic + 静默
// 丢包问题, 生产不可用. Mirage 客户端直连零拷贝改用 splice(2)+pipe (userspace 触发
// kernel 搬 page 引用), 见 src/proxy/splice.rs.
//
// 本 ELF 现只提供 sockops (RTT 反馈用于 brutal CC 动态速率) + IP 白名单.

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

// 用户态需要的 TCP 底层指标结构体.
//
// v0.4.4+: 扩展了 remote_ip / port / family, 用户态 GUI Active Tunnels 面板
// 能展示 "这条 cookie 是连到哪". layout 必须跟 Rust src/ebpf/mod.rs::TcpState
// 严格一一对应 (size_of 36 字节, 自然对齐 4).
//
// 内核 family 值: 2 = AF_INET, 10 = AF_INET6. 客户端的连接 remote = mirage
// 服务器 IP, 服务端的连接 remote = 客户端 IP.
struct tcp_state {
    __u32 srtt_us;       // 平滑往返时间（微秒）             offset 0
    __u32 snd_cwnd;      // 当前发送拥塞窗口大小（报文段数）   offset 4
    __u32 total_retrans; // 累计重传次数（感知丢包率的核心）   offset 8
    __u32 data_segs_out; // 发送出去的总数据段数               offset 12
    __u32 remote_ip[4];  // IPv4 在 [0], IPv6 全部 4 个 u32     offset 16
    __u16 remote_port;   // 远端端口 (host byte order)         offset 32
    __u16 family;        // 2=AF_INET, 10=AF_INET6              offset 34
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
//
// BPF verifier 不允许 "ctx 指针 + 偏移 → 解引用" 模式 (dereference of
// modified ctx ptr disallowed). 防御写法: 把所有 ctx 字段访问提前到
// 函数开头的直线代码中, 存入局部变量; 分支只用局部变量做 store. 这样
// 编译器即便做分支合并优化, 也不会产出"取 ctx 字段地址 → 跨分支解引用"
// 的字节码. __always_inline 确保不被外联成调用导致 ctx 传参问题.
static __always_inline void extract_ip(struct bpf_sock_ops *skops, struct ip_key *key) {
    __u32 family = skops->family;
    __u32 ip4    = skops->remote_ip4;
    __u32 ip6_0  = skops->remote_ip6[0];
    __u32 ip6_1  = skops->remote_ip6[1];
    __u32 ip6_2  = skops->remote_ip6[2];
    __u32 ip6_3  = skops->remote_ip6[3];

    if (family == 2) { // AF_INET (IPv4) — caller 已 zero-init key
        key->data[0] = 2;
        key->data[4] = ip4;
        return;
    }
    // AF_INET6 (IPv6)
    key->data[0] = 10;
    key->data[1] = ip6_0;
    key->data[2] = ip6_1;
    key->data[3] = ip6_2;
    key->data[4] = ip6_3;
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
        // 跟 extract_ip 同样的防御写法: 所有 ctx 字段提前到直线代码读到 locals,
        // 避免 clang -O2 分支合并产出 "取 ctx 字段地址 → 跨分支解引用" 的字节码
        // (verifier 拒绝 "modified ctx ptr dereference"). 详见 commit 66138c4.
        __u32 family = skops->family;
        __u32 ip4    = skops->remote_ip4;
        __u32 ip6_0  = skops->remote_ip6[0];
        __u32 ip6_1  = skops->remote_ip6[1];
        __u32 ip6_2  = skops->remote_ip6[2];
        __u32 ip6_3  = skops->remote_ip6[3];
        __u32 rport  = skops->remote_port;
        __u32 srtt   = skops->srtt_us;
        __u32 cwnd   = skops->snd_cwnd;
        __u32 retr   = skops->total_retrans;
        __u32 segs   = skops->data_segs_out;

        // Build ip_key for whitelist lookup
        struct ip_key key = {};
        if (family == 2) {
            key.data[0] = 2;
            key.data[4] = ip4;
        } else {
            key.data[0] = 10;
            key.data[1] = ip6_0;
            key.data[2] = ip6_1;
            key.data[3] = ip6_2;
            key.data[4] = ip6_3;
        }

        // 白名单检查：过滤掉与 Mirage 无关的流量
        if (!bpf_map_lookup_elem(&mirage_target_ips, &key)) {
            return 0;
        }

        // Build tcp_state with both metrics and remote endpoint info
        struct tcp_state s = {
            .srtt_us = srtt,
            .snd_cwnd = cwnd,
            .total_retrans = retr,
            .data_segs_out = segs,
            .remote_port = (__u16)rport,
            .family = (__u16)family,
        };
        if (family == 2) {
            s.remote_ip[0] = ip4;
        } else {
            s.remote_ip[0] = ip6_0;
            s.remote_ip[1] = ip6_1;
            s.remote_ip[2] = ip6_2;
            s.remote_ip[3] = ip6_3;
        }

        // 只有当获取到了有效延迟时才更新 Map
        if (srtt > 0) {
            __u64 cookie = bpf_get_socket_cookie(skops);
            bpf_map_update_elem(&mirage_rtt_map, &cookie, &s, BPF_ANY);
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
