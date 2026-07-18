#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

/**
 * [DNS Fake-IP 缓存 Map]
 * eBPF XDP 程序查询的主缓存。由 Rust 用户态维护，键是域名的 DJB2 哈希，值是分配的 IPv4 伪装地址。
 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   // 域名的 DJB2 哈希值
    __type(value, __u32); // Fake IPv4 地址
} mirage_dns_cache SEC(".maps");

struct dns_hdr {
    __u16 id;
    __u16 flags;
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 arcount;
};

/**
 * [DJB2 字符串哈希算法 (为 eBPF 展开优化)]
 * 用于将 DNS 请求包中的域名动态解析并转化为 u64 哈希值。
 * 由于 eBPF 虚拟机不支持复杂的循环，这里使用了 `#pragma unroll` 对网络包的 Label 逐层拆解。
 */
// 三点必须一起, 否则加载被拒 (在内核 6.1 上逐一实测):
//   ① __always_inline: 仅 `inline` 会被编成独立 BPF 子函数 (BPF-to-BPF call), 传包指针进
//      子函数验证器跟不住边界 → "reg type unsupported for arg#0"。与 tc_divert.c 同款。
//   ② __u32 off (无符号): 原 `int off` 经符号扩展后 `data+off` 可能被验证器判为负越界
//      ("value -2147483648 makes pkt pointer out of bounds")。
//   ③ 单层扁平循环: 原 10×63 嵌套 #pragma unroll 内联后状态爆炸 (>100 万指令 → E2BIG)。
//      改成单循环 + "长度字节/字符字节"状态机, 哈希的字符与顺序同原实现 (同序 DJB2, 结果一致)。
// DNS 名 wire 格式最长 255 字节, 循环上界取 256。
static __always_inline __u64 hash_domain(void *data, void *data_end, __u32 *offset) {
    __u64 hash = 5381;
    __u32 off = *offset;
    __u32 remaining = 0; // 当前 label 还剩几个字符待读; 0 表示下一字节是长度字节

    #pragma unroll
    for (int i = 0; i < 256; i++) {
        if (data + off + 1 > data_end) break;
        __u8 b = *((__u8 *)(data + off));
        off += 1;
        if (remaining == 0) {
            if (b == 0) break;      // 根标签 → 域名结束
            if (b > 63) break;      // 非法 label 长度
            remaining = b;          // 进入该 label 的字符
        } else {
            __u8 c = b;
            if (c >= 'A' && c <= 'Z') c += 32; // to lowercase
            hash = ((hash << 5) + hash) + c;   // DJB2, 与用户态一致
            remaining -= 1;
        }
    }
    *offset = off;
    return hash;
}

/**
 * [XDP 挂载点：DNS 极速响应引擎]
 * 运行在网卡驱动层 (NIC Driver)，在内核协议栈甚至分配 SKB 之前截获数据包。
 * 核心逻辑：
 * 1. 深度解析以太网帧，寻找目标端口 53 的 UDP DNS 请求。
 * 2. 提取 QNAME 并进行 DJB2 哈希运算。
 * 3. 查表 (mirage_dns_cache)，若命中则原地修改 MAC/IP/UDP 首部。
 * 4. 插入 DNS Answer 伪装记录，修改包尾指针。
 * 5. 零拷贝，直接调用 XDP_TX 原路由网卡打回给发送方（响应时间在微秒级）。
 */
SEC("xdp")
int mirage_xdp_dns(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) return XDP_PASS;

    // 有 IP options (ihl>5) 则 (iph+1) 与后面硬编码 offset=54 都假设的 20B IP 头不成立,
    // udph 会错落进 options 区。这类包少见, 直接放行交内核 (与 tc_divert.c 同款守卫)。
    if (iph->ihl != 5) return XDP_PASS;

    if (iph->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udph = (void *)(iph + 1);
    if ((void *)(udph + 1) > data_end) return XDP_PASS;

    // Check if it's a DNS query (Port 53)
    if (udph->dest != bpf_htons(53)) return XDP_PASS;

    struct dns_hdr *dns = (void *)(udph + 1);
    if ((void *)(dns + 1) > data_end) return XDP_PASS;

    // Only process standard queries (qdcount == 1, flags query)
    if (dns->qdcount != bpf_htons(1) || (dns->flags & bpf_htons(0x8000))) return XDP_PASS;

    // 只处理【无附加/权威段】的裸查询。带 EDNS0 OPT (arcount≥1, 现代客户端近乎必带)
    // 或权威段时, 本程序把 answer 追加在问题段之后会覆盖 OPT 记录、且不重排 arcount →
    // 回畸形响应致客户端 SERVFAIL/重试。这类查询交用户态 DNS server 正确处理。
    if (dns->ancount != 0 || dns->nscount != 0 || dns->arcount != 0) return XDP_PASS;

    __u32 offset = sizeof(*eth) + sizeof(*iph) + sizeof(*udph) + sizeof(*dns);

    // Hash the QNAME
    __u64 domain_hash = hash_domain(data, data_end, &offset);

    // Check QTYPE and QCLASS
    if (data + offset + 4 > data_end) return XDP_PASS;
    __u16 qtype = bpf_ntohs(*((__u16 *)(data + offset)));
    
    // Only intercept A records (QTYPE 1)
    if (qtype != 1) return XDP_PASS;

    // Lookup Fake-IP in BPF Map
    __u32 *fake_ip = bpf_map_lookup_elem(&mirage_dns_cache, &domain_hash);
    if (!fake_ip) return XDP_PASS; // Cache miss, let userspace handle it

    // Cache hit! Construct DNS Response
    
    // 1. Swap MAC addresses
    __u8 tmp_mac[ETH_ALEN];
    __builtin_memcpy(tmp_mac, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, tmp_mac, ETH_ALEN);

    // 2. Swap IP addresses
    __u32 tmp_ip = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp_ip;

    // 3. Swap UDP ports
    __u16 tmp_port = udph->source;
    udph->source = udph->dest;
    udph->dest = tmp_port;

    // 4. Modify DNS header (QR=1, RA=1, ANCOUNT=1)
    dns->flags = bpf_htons(0x8180); // Standard response, No error
    dns->ancount = bpf_htons(1);

    // 5. Append Answer section
    // QNAME is already there, we append a pointer to it + Type + Class + TTL + RDLENGTH + RDATA
    int answer_offset = offset + 4;
    
    // We need to grow the packet to fit the 16-byte answer
    // BPF helper bpf_xdp_adjust_tail
    if (bpf_xdp_adjust_tail(ctx, 16)) return XDP_PASS;
    
    // Re-evaluate pointers after adjust_tail
    data_end = (void *)(long)ctx->data_end;
    data = (void *)(long)ctx->data;
    
    // Safety check again
    if (data + answer_offset + 16 > data_end) return XDP_PASS;
    
    // Write answer (16 bytes)
    // Name pointer (0xC00C) pointing to the QNAME
    *((__u16 *)(data + answer_offset)) = bpf_htons(0xC00C);
    // Type A (1)
    *((__u16 *)(data + answer_offset + 2)) = bpf_htons(1);
    // Class IN (1)
    *((__u16 *)(data + answer_offset + 4)) = bpf_htons(1);
    // TTL (600)
    *((__u32 *)(data + answer_offset + 6)) = bpf_htonl(600);
    // RDLENGTH (4)
    *((__u16 *)(data + answer_offset + 10)) = bpf_htons(4);
    // RDATA (Fake IP)
    *((__u32 *)(data + answer_offset + 12)) = *fake_ip;

    // 6. Update lengths and checksums
    // Re-evaluate headers
    eth = data;
    iph = (void *)(eth + 1);
    udph = (void *)(iph + 1);
    
    __u16 new_udp_len = bpf_ntohs(udph->len) + 16;
    udph->len = bpf_htons(new_udp_len);
    iph->tot_len = bpf_htons(bpf_ntohs(iph->tot_len) + 16);
    
    // UDP checksum=0 means "no checksum" per RFC 768 — legal for IPv4 UDP.
    // 实测在常见 Linux + 网卡组合下客户端能正确接收 (XDP_TX 通常直接回 NIC,
    // 不经过路径上的 NAT/防火墙). 但存在已知风险:
    //
    //   如果用户反馈 "tcpdump 能抓到 XDP 返回的 DNS 响应包, 但客户端解析
    //   失败/超时" → 大概率就是中间设备 (严格的企业防火墙 / 古怪 NAT) 丢
    //   弃了 checksum=0 的 UDP 包. 此时需要补上 RFC 768 的 UDP 增量校验
    //   和计算 (包括 IPv4 伪首部), 不能再用 0 偷懒.
    udph->check = 0;
    
    // Recalculate IP checksum (RFC 1071)
    iph->check = 0;
    __u32 csum = 0;
    __u16 *ptr = (__u16 *)iph;
    #pragma unroll
    for (int i = 0; i < sizeof(*iph) / 2; i++) {
        csum += *ptr++;
    }
    csum = (csum & 0xffff) + (csum >> 16);
    iph->check = ~(__u16)(csum + (csum >> 16));

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";
