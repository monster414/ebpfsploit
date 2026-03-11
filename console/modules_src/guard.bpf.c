#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"guard\","
      "\"desc\":\"Persistence Guard: Uses LSM BPF Hooks to protect specified files/processes from rm/mv/kill.\","
      "\"requires\":[\"is_root\",\"lsm_bpf\",\"cap_mac_admin\"],"
      "\"options\":{},"
      "\"maps\":{"
        "\"target_inodes\":{\"key_size\":8,\"value_size\":4,\"key_type\":\"u64\",\"value_type\":\"u32\"},"
        "\"target_pids\":{\"key_size\":4,\"value_size\":4,\"key_type\":\"u32\",\"value_type\":\"u32\"}"
      "}"
    "}";

/* Protected Inode set (indexed by inode number)
 * update format: config[0:8]=inode(u64 LE), config[8:12]=1(u32 LE) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u64);
    __type(value, u32);
} target_inodes SEC(".maps");

/* Protected PID set (automatically populated by execve hook) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} target_pids SEC(".maps");

/* 1. Permission Interception: Returns EACCES when accessing protected inodes, even for root */
SEC("lsm/inode_permission")
int BPF_PROG(restrict_permission, struct inode *inode, int mask) {
    u64 ino = BPF_CORE_READ(inode, i_ino);
    // MAY_WRITE is 2, MAY_APPEND is 8. Block any write attempts.
    if ((mask & 2 || mask & 8) && bpf_map_lookup_elem(&target_inodes, &ino))
        return -13; /* -EACCES */
    return 0;
}

/* 1.5 File Open Interception: Block write/truncate open flags */
SEC("lsm/file_open")
int BPF_PROG(restrict_open, struct file *file) {
    u64 ino = BPF_CORE_READ(file, f_inode, i_ino);
    if (bpf_map_lookup_elem(&target_inodes, &ino)) {
        unsigned int flags = BPF_CORE_READ(file, f_flags);
        // O_WRONLY=01, O_RDWR=02, O_APPEND=02000, O_TRUNC=01000
        if (flags & (00000001 | 00000002 | 00001000 | 00002000))
            return -13; // EACCES
    }
    return 0;
}

/* 1.6 File Truncate Interception: Block truncate() syscalls */
SEC("lsm/path_truncate")
int BPF_PROG(restrict_truncate, const struct path *path) {
    struct dentry *dentry = BPF_CORE_READ(path, dentry);
    u64 ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    if (bpf_map_lookup_elem(&target_inodes, &ino))
        return -13;
    return 0;
}

/* 2. Rename Interception: Block 'mv' */
SEC("lsm/path_rename")
int BPF_PROG(restrict_rename,
             const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry) {
    u64 ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
    if (bpf_map_lookup_elem(&target_inodes, &ino)) {
        return -1; /* -EPERM */
    }
    return 0;
}

/* 3. Delete Interception: Block 'rm' */
SEC("lsm/path_unlink")
int BPF_PROG(restrict_unlink, const struct path *dir, struct dentry *dentry) {
    u64 ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    if (bpf_map_lookup_elem(&target_inodes, &ino))
        return -1;
    return 0;
}

/* 4. execve Tracking: When a protected file is executed, automatically add the new PID to the protection list */
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->ret != 0) return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct file *exe = BPF_CORE_READ(task, mm, exe_file);
    if (!exe) return 0;
    u64 ino = BPF_CORE_READ(exe, f_inode, i_ino);
    if (bpf_map_lookup_elem(&target_inodes, &ino)) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 val = 1;
        bpf_map_update_elem(&target_pids, &pid, &val, BPF_ANY);
    }
    return 0;
}

/* 5. kill Interception: Protected PIDs cannot be terminated by any signal */
SEC("lsm/task_kill")
int BPF_PROG(restrict_kill,
             struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred) {
    u32 pid = BPF_CORE_READ(p, pid);
    if (bpf_map_lookup_elem(&target_pids, &pid))
        return -1;
    return 0;
}
