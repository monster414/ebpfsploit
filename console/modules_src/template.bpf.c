/*
 * eBPFsploit Module Development Template
 * ====================================
 *
 * Use this template to quickly develop new eBPF modules.
 *
 *  Development Workflow:
 *   1. Copy this file and rename it to <your_module>.bpf.c
 *   2. Modify the description, dependencies, and configuration in the .metadata section
 *   3. Define your BPF Maps
 *   4. Implement the Hook functions
 *   5. Run `make modules` to compile
 *   6. The compiled binary will be automatically output to console/modules/<your_module>.bpf.o
 *
 *  Supported Hook Types (Agent automatically detects and attaches):
 *   - Tracepoint:     SEC("tp/syscalls/sys_enter_xxx")
 *   - Kprobe:         SEC("kprobe/function_name")
 *   - Kretprobe:      SEC("kretprobe/function_name")
 *   - Uprobe:         SEC("uprobe")          — Agent automatically resolves libcrypt path
 *   - Uretprobe:      SEC("uretprobe")       — Agent automatically resolves libcrypt path
 *   - XDP:            SEC("xdp")             — Requires -i <iface> or config[64] to specify network interface
 *   - LSM:            SEC("lsm/hook_name")   — Requires kernel LSM BPF support
 *
 *  .metadata JSON Field Definitions:
 *   - name:      Module name (same as filename, without .bpf.c)
 *   - desc:      Module description (shown in the `list` command)
 *   - requires:  Prerequisites array. The Console automatically checks for availability.
 *       Valid values: "is_root", "tracefs", "probe_write", "uprobe",
 *                     "kprobe", "xdp", "lsm_bpf", "cap_mac_admin", "cap_net_admin"
 *   - options:   Load-time configuration {KEY: [default_value, description]}
 *       Console's set/show options will read this field.
 *       Written to config[0:96] during loading and passed to Agent.
 *   - maps:      Runtime updateable Map information {map_name: {key_size, value_size, key_type, value_type}}
 *       key_type/value_type: "u8", "u16", "u32", "u64", "str"
 *       Console's update command automatically packs key/value based on this info.
 *
 *  BPF Map Configuration Conventions:
 *   - Array Map (e.g., inject_payload, master_password):
 *       key=0, value is configuration data. Automatically written from config during load.
 *       Update at runtime via: update <sess> <map_name> "new_value".
 *   - Hash Map (e.g., hidden_pids, hidden_ports):
 *       key=target_item, value=1 means enabled.
 *       Add entries at runtime via: update <sess> <map_name> <key>.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

/* ================================================================
 * .metadata — Console uses pyelftools to read module information from this ELF section
 *
 * Please modify the following content according to your module:
 * ================================================================ */
char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"template\","
      "\"desc\":\"Module Template: Replace this with your feature description\","
      "\"requires\":[\"is_root\",\"tracefs\"],"
      "\"options\":{"
        "\"MY_OPTION\":[\"default_value\",\"Option description (shown in `show options`)\"]"
      "},"
      "\"maps\":{"
        "\"my_config\":{\"key_size\":4,\"value_size\":64,\"key_type\":\"u32\",\"value_type\":\"str\"},"
        "\"my_targets\":{\"key_size\":4,\"value_size\":4,\"key_type\":\"u32\",\"value_type\":\"u32\"}"
      "}"
    "}";

/* ================================================================
 * BPF Maps
 *
 * Array Map: Used to store configuration data (e.g., payload, passwords)
 *   - Initialized automatically by the Agent from options during load.
 *   - Can be updated at runtime via: update <sess> my_config "new_value"
 *
 * Hash Map: Used to store target sets (e.g., PIDs or ports to hide)
 *   - Add entries at runtime via: update <sess> my_targets <key>
 *   - value defaults to 1 (indicating the key exists in the set)
 * ================================================================ */

/* Example Array Map: Store configurable string data */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[64]);
} my_config SEC(".maps");

/* Example Hash Map: Store target sets (e.g., PIDs, port numbers) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u32);
} my_targets SEC(".maps");

/* Example Per-CPU Scratch Area: For scenarios requiring large buffers (evading 512B stack limit) */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[2048]);
} scratch SEC(".maps");

/* ================================================================
 * Hook Functions
 *
 * Below are templates for several common Hook types. Keep or delete as needed.
 * ================================================================ */

/* ---- Example 1: Tracepoint Hook (Most common) ----
 *
 * Hooks syscall entry/exit. Suitable for file operations, process ops, etc.
 * The entry function accesses syscall arguments via ctx->args[].
 * The exit function accesses the return value via ctx->ret.
 *
 * Common Tracepoints:
 *   tp/syscalls/sys_enter_openat   — File open
 *   tp/syscalls/sys_exit_openat    — File open return
 *   tp/syscalls/sys_enter_read     — File read
 *   tp/syscalls/sys_exit_read      — File read return
 *   tp/syscalls/sys_enter_write    — File write
 *   tp/syscalls/sys_enter_getdents64 — Directory read (used for process hiding)
 *   tp/syscalls/sys_exit_getdents64  — Directory read return
 *   tp/syscalls/sys_exit_execve    — Process execution return
 *   tp/syscalls/sys_enter_close    — File close
 */
SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx) {
    /* ctx->args[0] = dirfd
     * ctx->args[1] = filename (user-space pointer)
     * ctx->args[2] = flags
     * ctx->args[3] = mode
     */
    const char *filename = (const char *)ctx->args[1];

    /* Read filename from user space */
    char fname[32];
    bpf_probe_read_user_str(&fname, sizeof(fname), filename);

    /* Example: Match specific file path */
    if (fname[0] == '/' && fname[1] == 'e' /* ... */) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;

        /* Check if inside target set */
        // if (bpf_map_lookup_elem(&my_targets, &pid)) { ... }
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx) {
    /* ctx->ret = Returned file descriptor (< 0 means failure) */
    if (ctx->ret < 0)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    /* Handle openat return value here, e.g., record the fd */

    return 0;
}

/* ---- Example 2: Kprobe Hook ----
 *
 * Hooks kernel functions. Suitable for intercepting internal kernel boundaries.
 * Note: kprobes rely on kernel symbols, which may be incompatible across versions.
 */
// SEC("kprobe/tcp_v4_connect")
// int BPF_KPROBE(hook_tcp_connect, struct sock *sk) {
//     u32 pid = bpf_get_current_pid_tgid() >> 32;
//     return 0;
// }

/* ---- Example 3: LSM Hook ----
 *
 * Uses the Linux Security Module (LSM) BPF extension.
 * Return 0 to allow the operation, or a negative value (e.g., -EACCES = -13) to deny.
 * Requires kernel CONFIG_BPF_LSM and "bpf" included in the `lsm=` boot parameter.
 */
// SEC("lsm/file_open")
// int BPF_PROG(restrict_file_open, struct file *file) {
//     /* Get inode number */
//     u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
//
//     /* Check if in protected set */
//     if (bpf_map_lookup_elem(&my_targets, &ino))
//         return -13; /* -EACCES */
//
//     return 0; /* Allow */
// }

/* ---- Example 4: XDP Hook ----
 *
 * Processes packets at the NIC driver layer for extreme performance.
 * Return values: XDP_PASS (allow), XDP_DROP (drop), XDP_TX (reflect back).
 * Suitable for network traffic filtering, port hiding, etc.
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
//     /* Parse IP/TCP headers and make decisions ... */
//     return XDP_PASS;
// }

/* ================================================================
 * Common BPF Helper Functions Quick Reference
 *
 * bpf_get_current_pid_tgid()         — Get current PID/TGID
 * bpf_get_current_uid_gid()          — Get current UID/GID
 * bpf_get_current_comm(buf, size)    — Get current process name
 * bpf_get_current_task()             — Get task_struct pointer
 *
 * bpf_probe_read_user(dst, sz, src)      — Read user-space memory
 * bpf_probe_read_user_str(dst, sz, src)  — Read user-space string
 * bpf_probe_read_kernel(dst, sz, src)    — Read kernel-space memory
 * bpf_probe_write_user(dst, src, sz)     — Write user-space memory (requires privileges)
 *
 * bpf_map_lookup_elem(map, key)               — Find Map element
 * bpf_map_update_elem(map, key, val, flags)   — Update Map element
 * bpf_map_delete_elem(map, key)               — Delete Map element
 *
 * BPF_CORE_READ(ptr, field)          — CO-RE safe read of struct field
 * BPF_CORE_READ(ptr, f1, f2)         — Chained safe read ptr->f1->f2
 * ================================================================ */
