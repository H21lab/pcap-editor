import textwrap, binascii, builtins, copy, sys, os, importlib, io
from scapy.packet import Raw, NoPayload, Packet
from scapy.layers.l2 import Ether, CookedLinux
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy_ext import reconstruct
from registry import PROTOCOL_METADATA, Provider

class ScriptRunner:
    @staticmethod
    def run(hex_data: str, script: str, ws_layers_json: str = "[]", wpan_dlt: int = 1) -> bytes:
        import socket
        orig_getaddrinfo = socket.getaddrinfo
        def patched_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
            if family == socket.AF_INET6 and isinstance(host, str) and ":" in host:
                raise socket.gaierror(-2, "Name or service not known")
            return orig_getaddrinfo(host, port, family, type, proto, flags)
        
        socket.getaddrinfo = patched_getaddrinfo
        try:
            from scapy.all import conf
            conf.resolve = None
            conf.verb = 0
            try: conf.dot15d4_protocol = 'zigbee'
            except: pass
            sys.setrecursionlimit(5000)
            
            orig_raw = binascii.unhexlify(hex_data)

            # Create string buffers for stdout and stderr
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            redirected_stdout = io.StringIO()
            redirected_stderr = io.StringIO()
            sys.stdout = redirected_stdout
            sys.stderr = redirected_stderr

            from scapy_ext import reconstruct, WTAP
            
            # Standard context for script execution
            safe_globals = {
                "__builtins__": builtins.__dict__,
                "binascii": binascii, "unhexlify": binascii.unhexlify, "hexlify": binascii.hexlify,
                "Packet": Packet, "Raw": Raw, "NoPayload": NoPayload,
                "Ether": Ether, "IP": IP, "TCP": TCP, "UDP": UDP, "ICMP": ICMP, "CookedLinux": CookedLinux,
                "copy": copy, "os": os, "sys": sys, "importlib": importlib,
                "WTAP": WTAP
            }
            
            # Load all Scapy layers into globals for convenience
            try:
                import scapy.all as scapy_all
                for name in dir(scapy_all):
                    attr = getattr(scapy_all, name)
                    if isinstance(attr, type) and issubclass(attr, Packet): 
                        safe_globals[name] = attr
                
                # Explicitly load common layers that might not be in scapy.all
                import scapy.layers.http as scapy_http
                for name in dir(scapy_http):
                    attr = getattr(scapy_http, name)
                    if isinstance(attr, type) and issubclass(attr, Packet):
                        safe_globals[name] = attr

                import scapy.layers.ntlm as scapy_ntlm
                for name in dir(scapy_ntlm):
                    attr = getattr(scapy_ntlm, name)
                    if isinstance(attr, type) and issubclass(attr, Packet):
                        safe_globals[name] = attr

                import scapy.layers.smb as scapy_smb
                for name in dir(scapy_smb):
                    attr = getattr(scapy_smb, name)
                    if isinstance(attr, type) and issubclass(attr, Packet):
                        safe_globals[name] = attr
                
                import scapy.layers.smb2 as scapy_smb2
                for name in dir(scapy_smb2):
                    attr = getattr(scapy_smb2, name)
                    if isinstance(attr, type) and issubclass(attr, Packet):
                        safe_globals[name] = attr

                import scapy.layers.zigbee as scapy_zigbee
                for name in dir(scapy_zigbee):
                    attr = getattr(scapy_zigbee, name)
                    if isinstance(attr, type) and issubclass(attr, Packet):
                        safe_globals[name] = attr

                # Explicitly load common contribs
                from scapy.contrib.mpls import MPLS
                safe_globals['MPLS'] = MPLS
            except: pass

            try:
                # We must use the same sanitization as engine.py for consistency
                clean_script = script.replace('\x00', '')
                exec(clean_script, safe_globals)
                
                # Flush captured stderr to the real stderr so it appears in the console
                if redirected_stderr.getvalue():
                    print(redirected_stderr.getvalue(), file=old_stderr)

            except Exception as e:
                # Capture output before re-raising
                script_stdout = redirected_stdout.getvalue()
                script_stderr = redirected_stderr.getvalue()
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                import traceback
                raise RuntimeError(
                    f"Execution Error: {e}\n"
                    f"--- Script:\n{clean_script}\n"
                    f"--- stdout ---\n{script_stdout}\n"
                    f"--- stderr ---\n{script_stderr}\n"
                    f"--- Traceback ---\n{traceback.format_exc()}"
                )
            finally:
                # Ensure stdout and stderr are restored even if no exception
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                
            # Check for generate_packet function (new template style)
            gen_pkt_func = safe_globals.get("generate_packet")
            if gen_pkt_func and callable(gen_pkt_func):
                return bytes(gen_pkt_func())

            telco_bin = safe_globals.get("telco_bin")
            telco_offset = safe_globals.get("telco_offset")
            telco_old_len = safe_globals.get("telco_old_len")
            telco_proto = safe_globals.get("telco_proto")

            if telco_bin is not None and telco_offset is not None:
                # Construct the patched binary exactly as instructed by the script
                patched_raw = orig_raw[:telco_offset] + telco_bin + orig_raw[telco_offset + telco_old_len:]
                
                # THE CRITICAL CHANGE: 
                # We TRUST the script's output binary. 
                try:
                    if telco_proto in ["IP", "UDP", "TCP"]:
                        pkt = reconstruct(binascii.hexlify(patched_raw).decode(), hint=telco_proto, wpan_dlt=wpan_dlt)
                        for l in pkt:
                            for f in ['len', 'chksum']:
                                if hasattr(l, f): setattr(l, f, None)
                        fixed_bin = bytes(pkt)
                        if len(fixed_bin) == len(patched_raw):
                            return fixed_bin
                except:
                    pass

                return patched_raw

            # Fallback to Scapy pkt if script uses legacy 'pkt = ...' style
            res_pkt = safe_globals.get("pkt")
            if res_pkt: 
                return bytes(res_pkt)
            
            return orig_raw
        finally:
            socket.getaddrinfo = orig_getaddrinfo
