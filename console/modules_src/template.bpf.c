/*
 * eBPFsploit 模块开发模板
 * ========================
 *
 * 使用本模板快速开发新的 eBPF 模块。
 *
 *  开发流程：
 *   1. 复制本文件并重命名为 <your_module>.bpf.c
 *   2. 修改 .metadata section 中的模块描述、依赖和配置
 *   3. 定义你的 BPF Maps
 *   4. 实现 Hook 函数
 *   5. make modules 编译
 *   6. 编译产物自动输出到 console/modules/<your_module>.bpf.o
 *
 *  支持的 Hook 类型（Agent 自动识别并挂载）：
 *   - Tracepoint:     SEC("tp/syscalls/sys_enter_xxx")
 *   - Kprobe:         SEC("kprobe/function_name")
 *   - Kretprobe:      SEC("kretprobe/function_name")
 *   - Uprobe:         SEC("uprobe")          — Agent 自动解析 libcrypt 路径
 *   - Uretprobe:      SEC("uretprobe")       — Agent 自动解析 libcrypt 路径
 *   - XDP:            SEC("xdp")             — 需要 -i <iface> 或 config[64] 指定网卡
 *   - LSM:            SEC("lsm/hook_name")   — 需要内核 LSM BPF 支持
 *
 *  .metadata JSON 字段说明：
 *   - name:      模块名（与文件名一致，不含 .bpf.c）
 *   - desc:      模块描述（显示在 list 命令中）
 *   - requires:  前置要求数组，Console 自动检查可用性
 *       可选值: "is_root", "tracefs", "probe_write", "uprobe",
 *               "kprobe", "xdp", "lsm_bpf", "cap_mac_admin", "cap_net_admin"
 *   - options:   加载时配置 {KEY: [默认值, 描述]}
 *       Console 的 set/show options 会读取此字段
 *       加载时写入 config[0:96] 传给 Agent
 *   - maps:      运行时可更新的 Map 信息 {map名: {key_size, value_size, key_type, value_type}}
 *       key_type/value_type: "u8", "u16", "u32", "u64", "str"
 *       Console 的 update 命令根据此信息自动打包 key/value
 *
 *  BPF Map 配置约定：
 *   - Array Map（如 inject_payload, master_password）：
 *       key=0，value 为配置数据。加载时自动从 config 写入。
 *       运行时通过 update <sess> <map_name> "new_value" 更新。
 *   - Hash Map（如 hidden_pids, hidden_ports）：
 *       key=目标项，value=1 表示启用。
 *       运行时通过 update <sess> <map_name> <key> 添加条目。
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* ================================================================
 * .metadata — Console 通过 pyelftools 从此 ELF section 读取模块信息
 *
 * 请根据你的模块修改以下内容：
 * ================================================================ */
char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"template\","
      "\"desc\":\"模块模板：请替换为你的功能描述\","
      "\"requires\":[\"is_root\",\"tracefs\"],"
      "\"options\":{"
        "\"MY_OPTION\":[\"default_value\",\"选项描述（显示在 show options 中）\"]"
      "},"
      "\"maps\":{"
        "\"my_config\":{\"key_size\":4,\"value_size\":64,\"key_type\":\"u32\",\"value_type\":\"str\"},"
        "\"my_targets\":{\"key_size\":4,\"value_size\":4,\"key_type\":\"u32\",\"value_type\":\"u32\"}"
      "}"
    "}";

/* ================================================================
 * BPF Maps
 *
 * Array Map: 用于存储配置数据（如 payload、密码等）
 *   - 加载时由 Agent 自动写入 options 中的初始值
 *   - 运行时可通过 update <sess> my_config "new_value" 更新
 *
 * Hash Map: 用于存储目标集合（如要隐藏的 PID、端口等）
 *   - 运行时通过 update <sess> my_targets <key> 添加条目
 *   - value 默认为 1（表示该 key 存在于集合中）
 * ================================================================ */

/* 示例 Array Map：存储可配置的字符串数据 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[64]);
} my_config SEC(".maps");

/* 示例 Hash Map：存储目标集合（如 PID、端口号等） */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u32);
} my_targets SEC(".maps");

/* 示例 Per-CPU 暂存区：用于需要大缓冲区的场景（规避 512B 栈限制） */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[2048]);
} scratch SEC(".maps");

/* ================================================================
 * Hook 函数
 *
 * 以下提供几种常见 Hook 类型的模板，按需保留或删除。
 * ================================================================ */

/* ---- 示例 1: Tracepoint Hook（最常用）----
 *
 * Hook 系统调用入口/出口。适用于文件操作、进程操作等场景。
 * 入口函数通过 ctx->args[] 获取系统调用参数。
 * 出口函数通过 ctx->ret 获取返回值。
 *
 * 常用 Tracepoint：
 *   tp/syscalls/sys_enter_openat   — 文件打开
 *   tp/syscalls/sys_exit_openat    — 文件打开返回
 *   tp/syscalls/sys_enter_read     — 文件读取
 *   tp/syscalls/sys_exit_read      — 文件读取返回
 *   tp/syscalls/sys_enter_write    — 文件写入
 *   tp/syscalls/sys_enter_getdents64 — 目录读取（进程隐藏用）
 *   tp/syscalls/sys_exit_getdents64  — 目录读取返回
 *   tp/syscalls/sys_exit_execve    — 进程执行返回
 *   tp/syscalls/sys_enter_close    — 文件关闭
 */
SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    /* ctx->args[0] = dirfd
     * ctx->args[1] = filename (用户空间指针)
     * ctx->args[2] = flags
     * ctx->args[3] = mode
     */
    const char *filename = (const char *)ctx->args[1];

    /* 读取用户空间的文件名 */
    char fname[32];
    bpf_probe_read_user_str(&fname, sizeof(fname), filename);

    /* 示例：匹配特定文件路径 */
    if (fname[0] == '/' && fname[1] == 'e' /* ... */) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;

        /* 检查是否在目标集合中 */
        // if (bpf_map_lookup_elem(&my_targets, &pid)) { ... }

        bpf_printk("TEMPLATE: openat intercepted, pid=%d\n", pid);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    /* ctx->ret = 返回的文件描述符 (< 0 表示失败) */
    if (ctx->ret < 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    /* 在此处理 openat 的返回值，例如记录 fd */

    return 0;
}

/* ---- 示例 2: Kprobe Hook ----
 *
 * Hook 内核函数。适用于需要拦截内核行为的场景。
 * 注意：kprobe 依赖内核符号，不同版本可能不兼容。
 */
// SEC("kprobe/tcp_v4_connect")
// int BPF_KPROBE(hook_tcp_connect, struct sock *sk) {
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     bpf_printk("TEMPLATE: tcp_connect from pid=%d\n", pid);
//     return 0;
// }

/* ---- 示例 3: LSM Hook ----
 *
 * 利用 Linux Security Module 框架的 BPF 扩展。
 * 返回 0 允许操作，返回负值（如 -EACCES = -13）拒绝操作。
 * 需要内核启用 CONFIG_BPF_LSM 且 lsm= 参数包含 "bpf"。
 */
// SEC("lsm/file_open")
// int BPF_PROG(restrict_file_open, struct file *file) {
//     /* 获取 inode 号 */
//     u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
//
//     /* 检查是否在受保护集合中 */
//     if (bpf_map_lookup_elem(&my_targets, &ino))
//         return -13; /* -EACCES */
//
//     return 0; /* 允许 */
// }

/* ---- 示例 4: XDP Hook ----
 *
 * 在网卡驱动层处理数据包，性能极高。
 * 返回值：XDP_PASS（放行）、XDP_DROP（丢弃）、XDP_TX（原路返回）
 * 适用于网络流量过滤、端口隐藏等场景。
 */
// SEC("xdp")
// int my_xdp_prog(struct xdp_md *ctx) {
//     void *data     = (void *)(long)ctx->data;
//     void *data_end = (void *)(long)ctx->data_end;
//
//     struct ethhdr *eth = data;
//     if ((void *)(eth + 1) > data_end)
//         return XDP_PASS;
//
//     /* 解析 IP/TCP 头并判断 ... */
//     return XDP_PASS;
// }

/* ================================================================
 * 常用 BPF Helper 函数速查
 *
 * bpf_get_current_pid_tgid()         — 获取当前 PID/TGID
 * bpf_get_current_uid_gid()          — 获取当前 UID/GID
 * bpf_get_current_comm(buf, size)    — 获取当前进程名
 * bpf_get_current_task()             — 获取 task_struct 指针
 *
 * bpf_probe_read_user(dst, sz, src)      — 读取用户空间内存
 * bpf_probe_read_user_str(dst, sz, src)  — 读取用户空间字符串
 * bpf_probe_read_kernel(dst, sz, src)    — 读取内核空间内存
 * bpf_probe_write_user(dst, src, sz)     — 写入用户空间内存（需特权）
 *
 * bpf_map_lookup_elem(map, key)               — 查找 Map 元素
 * bpf_map_update_elem(map, key, val, flags)   — 更新 Map 元素
 * bpf_map_delete_elem(map, key)               — 删除 Map 元素
 *
 * bpf_printk(fmt, ...)               — 调试输出（/sys/kernel/debug/tracing/trace_pipe）
 *
 * BPF_CORE_READ(ptr, field)          — CO-RE 安全读取结构体字段
 * BPF_CORE_READ(ptr, f1, f2)         — 链式读取 ptr->f1->f2
 * ================================================================ */
