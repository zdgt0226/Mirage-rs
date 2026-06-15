#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

struct {
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65536);
    __type(key, __u64);   // socket cookie of the sending socket
    __type(value, __u32); // file descriptor of the receiving socket (inserted from userspace)
} mirage_sockmap SEC(".maps");

SEC("sk_msg")
int mirage_sk_msg(struct sk_msg_md *msg)
{
    // Retrieve the socket cookie of the sender
    __u64 cookie = bpf_get_socket_cookie(msg);
    
    // Attempt to redirect the message to the paired socket found in the hash map.
    // BPF_F_INGRESS tells the kernel to put the packet onto the target socket's receive queue.
    // This entirely bypasses the userspace process reading and writing the buffer.
    bpf_msg_redirect_hash(msg, &mirage_sockmap, &cookie, BPF_F_INGRESS);
    
    // If redirect fails (e.g., no entry in map), pass it down the normal TCP stack
    return SK_PASS; 
}

char _license[] SEC("license") = "GPL";
