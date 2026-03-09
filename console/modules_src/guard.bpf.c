#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"guard\","
      "\"desc\":\"持久化守护：基于 LSM BPF Hook，保护指定文件/进程免遭 rm/mv/kill\","
      "\"requires\":[\"is_root\",\"lsm_bpf\",\"cap_mac_admin\"],"
      "\"options\":{},"
      "\"maps\":{"
        "\"protected_inodes\":{\"key_size\":8,\"value_size\":4,\"key_type\":\"u64\",\"value_type\":\"u32\"},"
        "\"protected_pids\":{\"key_size\":4,\"value_size\":4,\"key_type\":\"u32\",\"value_type\":\"u32\"}"
      "}"
    "}";

/* 受保护的 Inode 集合（按 inode number 索引）
 * update 格式：config[0:8]=inode(u64 LE), config[8:12]=1(u32 LE) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u64);
    __type(value, u32);
} protected_inodes SEC(".maps");

/* 受保护的 PID 集合（由 execve hook 自动填充） */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u32);
} protected_pids SEC(".maps");

/* 1. 权限拦截：即使是 root，访问受保护 inode 也返回 EACCES */
SEC("lsm/inode_permission")
int BPF_PROG(restrict_permission, struct inode *inode, int mask) {
    u64 ino = BPF_CORE_READ(inode, i_ino);
    if (mask != 0 && bpf_map_lookup_elem(&protected_inodes, &ino))
        return -13; /* -EACCES */
    return 0;
}

/* 2. 重命名拦截：拒绝 mv */
SEC("lsm/path_rename")
int BPF_PROG(restrict_rename,
             const struct path *old_dir, struct dentry *old_dentry,
             const struct path *new_dir, struct dentry *new_dentry) {
    u64 ino = BPF_CORE_READ(old_dentry, d_inode, i_ino);
    if (bpf_map_lookup_elem(&protected_inodes, &ino)) {
        bpf_printk("[guard] rename blocked: inode %llu\n", ino);
        return -1; /* -EPERM */
    }
    return 0;
}

/* 3. 删除拦截：拒绝 rm */
SEC("lsm/path_unlink")
int BPF_PROG(restrict_unlink, const struct path *dir, struct dentry *dentry) {
    u64 ino = BPF_CORE_READ(dentry, d_inode, i_ino);
    if (bpf_map_lookup_elem(&protected_inodes, &ino))
        return -1;
    return 0;
}

/* 4. execve 跟踪：受保护文件被执行时，自动将新 PID 加入保护列表 */
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct trace_event_raw_sys_exit *ctx) {
    if (ctx->ret != 0) return 0;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct file *exe = BPF_CORE_READ(task, mm, exe_file);
    if (!exe) return 0;
    u64 ino = BPF_CORE_READ(exe, f_inode, i_ino);
    if (bpf_map_lookup_elem(&protected_inodes, &ino)) {
        u32 pid = bpf_get_current_pid_tgid() >> 32;
        u32 val = 1;
        bpf_map_update_elem(&protected_pids, &pid, &val, BPF_ANY);
        bpf_printk("[guard] PID %u auto-protected (inode %llu)\n", pid, ino);
    }
    return 0;
}

/* 5. kill 拦截：受保护 PID 无法被任何信号终止 */
SEC("lsm/task_kill")
int BPF_PROG(restrict_kill,
             struct task_struct *p, struct kernel_siginfo *info,
             int sig, const struct cred *cred) {
    u32 pid = BPF_CORE_READ(p, pid);
    if (bpf_map_lookup_elem(&protected_pids, &pid))
        return -1;
    return 0;
}
