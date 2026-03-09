# Compiler settings
CC = gcc
CLANG = clang

# Targets and Paths
AGENT_DIR = agent
CONSOLE_DIR = console
MODULES_SRC_DIR = $(CONSOLE_DIR)/modules_src
MODULES_DIR = $(CONSOLE_DIR)/modules

AGENT = $(AGENT_DIR)/agent

# Find all .bpf.c files (exclude template)
MODULE_SRCS = $(filter-out $(MODULES_SRC_DIR)/template.bpf.c, $(wildcard $(MODULES_SRC_DIR)/*.bpf.c))
# Generate corresponding .bpf.o rules
MODULES = $(patsubst $(MODULES_SRC_DIR)/%.bpf.c, $(MODULES_DIR)/%.bpf.o, $(MODULE_SRCS))

# Flags
AGENT_CFLAGS = -O2
AGENT_LDFLAGS = -lbpf -lelf -lz
ARCH := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
BPF_CFLAGS = -O2 -g -target bpf -D__TARGET_ARCH_$(ARCH)

# Targets and Paths
# vmlinux.h target
VMLINUX_H = $(MODULES_SRC_DIR)/vmlinux.h

.PHONY: all agent modules clean vmlinux

# Default target builds everything
all: agent modules

# Agent build rule — 使用 builder.py 生成唯一 Agent + 注入 PSK
agent:
	@echo "[*] Building Agent via builder.py (PSK + anti-hash)..."
	python3 $(AGENT_DIR)/builder.py
	@echo "[+] Agent built successfully: $(AGENT)"

# Generate vmlinux.h
vmlinux: $(VMLINUX_H)

$(VMLINUX_H):
	@echo "[*] Generating vmlinux.h..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@ || (echo "[-] Failed to generate vmlinux.h. Is bpftool installed?" && exit 1)
	@echo "[+] vmlinux.h generated."

# Modules build rules
modules: $(MODULES_DIR) $(MODULES)

$(MODULES_DIR):
	@mkdir -p $(MODULES_DIR)

$(MODULES_DIR)/%.bpf.o: $(MODULES_SRC_DIR)/%.bpf.c $(VMLINUX_H)
	@echo "[*] Compiling eBPF module: $(notdir $@)..."
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	@echo "[+] Module $(notdir $@) is ready in $(MODULES_DIR)/"

# Clean up
clean:
	@echo "[*] Cleaning up..."
	@rm -f $(AGENT)
	@rm -f $(MODULES_DIR)/*.bpf.o
	@rm -f $(VMLINUX_H)
	@python3 $(AGENT_DIR)/builder.py clean 2>/dev/null || true
	@echo "[+] Clean complete."
