import os
import sys
import json
import base64
import binascii
import re
import importlib
import logging
import textwrap
from typing import List, Dict, Any, Optional
from scapy.all import *
from models import DissectionResult, Layer, ModelField
from registry import PROTOCOL_METADATA, Provider, PROTOCOL_MAP

def safe_repr(obj):
    # This function is now mostly used for legacy templates without source_code
    try:
        if isinstance(obj, (bytes, bytearray)):
            return f"unhexlify('{binascii.hexlify(obj).decode()}')"
        if isinstance(obj, list):
            return "[" + ", ".join(safe_repr(x) for x in obj) + "]"
        if isinstance(obj, tuple):
            items = [safe_repr(x) for x in obj]
            if len(items) == 1: return "(" + items[0] + ",)"
            return "(" + ", ".join(items) + ")"
        if isinstance(obj, dict):
            items = []
            try:
                keys = sorted(list(obj.keys()), key=lambda x: str(x))
            except:
                keys = list(obj.keys())
            for k in keys:
                v = obj[k]
                items.append(f"{repr(k)}: {safe_repr(v)}")
            return "{" + ", ".join(items) + "}"
        if hasattr(obj, 'command'):
            return obj.command()
        if isinstance(obj, (int, float, bool, type(None))): return repr(obj)
        if isinstance(obj, str): return repr(obj)
        if hasattr(obj, 'val') and not isinstance(obj, type): return safe_repr(obj.val)
        if hasattr(obj, 'get_val'): return safe_repr(obj.get_val())
        return repr(str(obj))
    except Exception: return repr(str(obj))

class DissectionContext:
    def __init__(self, pkt_id: str):
        self.pkt_id = pkt_id
        self.layers: List[Layer] = []
        self.instances: Dict[int, Any] = {}

    def register_instance(self, index: int, obj: Any, offset: int, length: int, protocol: str):
        self.instances[index] = {
            "obj": obj,
            "offset": offset,
            "length": length,
            "protocol": protocol,
            "val": {}
        }

    def get_instance(self, index: int):
        return self.instances.get(index)

class DissectionEngine:
    def __init__(self, dissectors=None):
        self.templates = {}
        self.dissectors = dissectors
        self._load_templates()
        
        # Add Templates dir to path so templates can import utils.py
        dirs = self._get_possible_template_dirs()
        for d in dirs:
            if d not in sys.path:
                sys.path.append(d)

    def dissect(self, hex_data: str, pkt_id: str, ws_layers: Any = "[]", wpan_dlt: int = 1, debug_mode: bool = False) -> DissectionResult:
        from handlers.scapy_handler import ScapyDissector
        
        ctx = DissectionContext(pkt_id)
        if isinstance(ws_layers, str):
            ws_layers_list = json.loads(ws_layers)
        else:
            ws_layers_list = ws_layers
        
        # Scapy initial dissection to get basic layers
        ctx.layers = ScapyDissector().dissect_hex(hex_data, ws_layers, wpan_dlt)
        
        # Post-process layers with templates or Pycrate
        for lyr in ctx.layers:
            authoritative_name = self._get_authoritative_name(lyr.protocol)
            meta = PROTOCOL_METADATA.get(authoritative_name, {})
            provider = meta.get("provider", Provider.SCAPY)
            
            t_name, has_t = self._get_template_name(authoritative_name)

            end_pos = (lyr.offset + lyr.length) * 2

            if provider == Provider.PYCRATE:
                decode_data = hex_data[lyr.offset*2 :]
            else:
                decode_data = hex_data[lyr.offset*2 : end_pos]

            # Always use 'decode' method - templates handle encoding method internally
            val = self._template_decode(authoritative_name, decode_data, 'decode', length=lyr.length)

            if val is None: 
                val = getattr(lyr, 'val', {})
                if not val:
                    val = {"raw": hex_data[lyr.offset*2 : end_pos]}
            
            if not isinstance(val, dict):
                val = {'val': val}
            
            # Merge original fields from ScapyDissector if they aren't in val
            lyr_scapy_val = getattr(lyr, 'val', {})
            for k, v in lyr_scapy_val.items():
                if k not in val:
                    val[k] = v

            if '_orig_hex' not in val:
                val['_orig_hex'] = hex_data[lyr.offset*2 : (lyr.offset+lyr.length)*2]

            lyr.val = val
            ctx.register_instance(lyr.index, None, lyr.offset, lyr.length, authoritative_name)
            inst = ctx.get_instance(lyr.index)
            if inst: inst['val'] = val

        # Auto-detect and override linktype for CookedLinux (SLL)
        actual_dlt = wpan_dlt
        for lyr in ctx.layers:
            if lyr.protocol == "CookedLinux":
                actual_dlt = 113
                break

        command = self._generate_template_script(ctx, hex_data, actual_dlt, debug_mode)
        return DissectionResult(ctx.layers, command)

    def _get_possible_template_dirs(self):
        try:
            root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            templates_dir = os.path.join(root_dir, "Templates")
            core_python_dir = os.path.dirname(os.path.abspath(__file__))
        except:
            templates_dir = "./Templates"
            core_python_dir = "."
        dirs = [
            os.path.join(os.getcwd(), 'Templates'), './Templates', '/home/pyodide/Templates', '/Templates',
            templates_dir, os.path.join(core_python_dir, "Templates"), core_python_dir
        ]
        res = []
        for d in dirs:
            if os.path.exists(d): res.append(d)
        return res

    def _load_templates(self):
        dirs = self._get_possible_template_dirs()
        for d in dirs:
            if not os.path.isdir(d): continue
            for f in os.listdir(d):
                if f.endswith(".py") and f != "__init__.py":
                    name = f[:-3]
                    self.templates[name] = os.path.join(d, f)

    def _get_template_name(self, protocol: str):
        if protocol in self.templates: return protocol, True
        if protocol.lower() in self.templates: return protocol.lower(), True
        return None, False

    def _load_template_module(self, name: str):
        if name not in self.templates: return None
        try:
            spec = importlib.util.spec_from_file_location(name, self.templates[name])
            mod = importlib.util.module_from_spec(spec)
            mod.safe_repr = safe_repr
            spec.loader.exec_module(mod)
            return mod
        except Exception as e:
            print(f"Error loading template {name}: {e}")
            return None

    def _read_template_source(self, name: str):
        if name not in self.templates: return ""
        try:
            with open(self.templates[name], 'r') as f:
                return f.read()
        except:
            return ""

    def _get_authoritative_name(self, protocol: str) -> str:
        return PROTOCOL_MAP.get(protocol.lower(), protocol)

    def _template_decode(self, protocol: str, hex_data: str, method: str = "decode", **kwargs):
        t_name, has_t = self._get_template_name(protocol)
        if not has_t: return None
        mod = self._load_template_module(t_name)
        if not mod: return None
        
        try:
            decode_func = getattr(mod, method, None)
            if not decode_func: return None
            try:
                return decode_func(hex_data, **kwargs)
            except TypeError:
                # Fallback if keyword arguments are not supported
                return decode_func(hex_data)
        except Exception as e:
            print(f"Error decoding {protocol} with template: {e}")
            return None

    def _generate_template_script(self, ctx: DissectionContext, hex_data: str, wpan_dlt: int, debug_mode: bool = False) -> str:
        NL = "\n"
        header = textwrap.dedent('''
            from binascii import unhexlify, hexlify
            import copy, sys, os, importlib, json, struct, logging
            from scapy.all import *
            for lyr in ['inet', 'inet6', 'ppp', 'l2', 'sctp', 'dhcp', 'dhcp6', 'dns', 'rip', 'ntlm', 'http', 'snmp', 'dot11', 'dot15d4', 'sixlowpan', 'ipx', 'tls.all', 'smb', 'smb2']:
                try: exec(f'from scapy.layers.{lyr} import *')
                except: pass
            for lyr in ['bfd', 'igmp', 'mpls', 'pfcp', 'gtp', 'gtp_v2']:
                try: exec(f'from scapy.contrib.{lyr} import *')
                except: pass

            def safe_repr(obj):
                try:
                    if isinstance(obj, (bytes, bytearray)):
                        return f"unhexlify('{binascii.hexlify(obj).decode()}')"
                    if isinstance(obj, list):
                        return "[" + ", ".join(safe_repr(x) for x in obj) + "]"
                    if isinstance(obj, tuple):
                        items = [safe_repr(x) for x in obj]
                        if len(items) == 1: return "(" + items[0] + ",)"
                        return "(" + ", ".join(items) + ")"
                    if isinstance(obj, dict):
                        items = []
                        try:
                            keys = sorted(list(obj.keys()), key=lambda x: str(x))
                        except:
                            keys = list(obj.keys())
                        for k in keys:
                            v = obj[k]
                            items.append(f"{repr(k)}: {safe_repr(v)}")
                        return "{" + ", ".join(items) + "}"
                    if hasattr(obj, 'command'):
                        return obj.command()
                    if isinstance(obj, (int, float, bool, type(None))): return repr(obj)
                    if isinstance(obj, str): return repr(obj)
                    if hasattr(obj, 'val') and not isinstance(obj, type): return safe_repr(obj.val)
                    if hasattr(obj, 'get_val'): return safe_repr(obj.get_val())
                    return repr(str(obj))
                except Exception as e: 
                    return repr(str(obj))

            def decode_raw(hex_data):
                return {"raw": hex_data, "_orig_hex": hex_data}

            def encode_raw(val):
                if isinstance(val, dict) and 'raw' in val: 
                    return val['raw']
                val_copy = copy.deepcopy(val) if isinstance(val, dict) else {}
                orig_hex = val_copy.get('_orig_hex')
                is_edited = val_copy.get('_edited', False)
                if orig_hex and not is_edited:
                    return orig_hex
                return orig_hex if orig_hex else ""

            def source_code_raw(val, payload_var=None):
                load_val = val.get('load') or val.get('raw') or val.get('_orig_hex')
                if load_val:
                    s = f"Raw(load=unhexlify('{load_val}'))"
                else:
                    s = "Raw()"
                if payload_var:
                    s += f" / {payload_var}"
                return s

            class UtilsNamespace:
                pass
            utils = UtilsNamespace()
            utils.safe_repr = safe_repr
            utils.decode_raw = decode_raw
            utils.encode_raw = encode_raw
            utils.source_code_raw = source_code_raw
        ''')
        header += NL

        needs_wtap = False
        if ctx.layers:
             for lyr in ctx.layers:
                 if self._get_authoritative_name(lyr.protocol) == "WTAP":
                     needs_wtap = True
                     break
        
        if needs_wtap:
            header += "class WTAP(Packet):" + NL
            header += "    name = 'WTAP'" + NL
            header += "    fields_desc = [ StrFixedLenField('header', b'', length=100) ]" + NL
            header += "" + NL

        # Check if PPPDirection is needed
        needs_pppdirection = False
        if ctx.layers:
            for lyr in ctx.layers:
                if self._get_authoritative_name(lyr.protocol) == "PPPDirection":
                    needs_pppdirection = True
                    break

        if needs_pppdirection:
            header += "class PPPDirection(Packet):" + NL
            header += "    name = 'PPPDirection'" + NL
            header += "    fields_desc = [ ByteField('direction', 0) ]" + NL
            header += "try:" + NL
            header += "    from scapy.layers.ppp import HDLC" + NL
            header += "    bind_layers(PPPDirection, HDLC)" + NL
            header += "except: pass" + NL
            header += "" + NL

        pycrate_imports = set()
        scapy_contrib_imports = set()

        if ctx.layers:
            for lyr in ctx.layers:
                p_name = self._get_authoritative_name(lyr.protocol)
                t_name, has_t = self._get_template_name(p_name)
                if has_t:
                    t_src = self._read_template_source(t_name)
                    for line in t_src.splitlines():
                        line_strip = line.strip()
                        if line_strip.startswith(("from pycrate_", "import pycrate_")):
                            pycrate_imports.add(line_strip)
                        if line_strip.startswith(("from scapy.contrib.", "from scapy.layers.")):
                            scapy_contrib_imports.add(line_strip)

        if pycrate_imports:
            header += NL.join(sorted(list(pycrate_imports))) + NL
        
        if scapy_contrib_imports:
            for imp in sorted(list(scapy_contrib_imports)):
                header += f"try: {imp}\nexcept ImportError: pass" + NL
        
        header += NL
        
        logic_body = "def generate_packet():" + NL
        
        try:
            target_lyrs = ctx.layers
            if not target_lyrs:
                logic_body += "    return b''" + NL
            else:
                last_payload_var = None
                padding_hex = None
                for i, pl in enumerate(reversed(target_lyrs)):
                    p_name = self._get_authoritative_name(pl.protocol)

                    # Capture Padding for later - don't stack it as payload
                    # Padding is added at Ethernet level to meet minimum frame size
                    if p_name == "Padding":
                        inst = ctx.get_instance(pl.index)
                        if inst and inst.get('val'):
                            padding_hex = inst['val'].get('load') or inst['val'].get('_orig_hex')
                        continue

                    meta = PROTOCOL_METADATA.get(p_name, {})
                    provider = meta.get("provider", Provider.SCAPY)
                    
                    v_prefix = f"{re.sub(r'[^a-zA-Z0-9_]', '_', str(p_name)).lower()}_{len(target_lyrs)-1-i}"
                    current_obj_var = f"{v_prefix}_obj"

                    block = NL + f"    # --- Layer: {p_name} ---" + NL
                    
                    t_name, has_t = self._get_template_name(p_name)
                    inst = ctx.get_instance(pl.index)
                    val = inst.get('val', {}) if inst else {}
                    
                    if isinstance(val, dict) and 'val' in val:
                        inner_val = val['val']
                        if isinstance(inner_val, dict):
                            val_to_repr = {k: v for k, v in inner_val.items() if k not in ['_orig_hex', '_edited', 'raw']}
                        else:
                            val_to_repr = inner_val
                    else:
                        val_to_repr = {k: v for k, v in val.items() if k not in ['_orig_hex', '_edited', 'val']}
                        # If we ONLY have 'raw', keep it. Otherwise remove it to keep it clean.
                        if 'raw' in val_to_repr and len(val_to_repr) > 1:
                            del val_to_repr['raw']
                    
                    v_val_var = f"{v_prefix}_val"
                    block += f"    {v_val_var} = {safe_repr(val_to_repr)}" + NL
                    block += f"    val = {v_val_var}" + NL

                    t_mod = self._load_template_module(t_name) if has_t else None
                    if t_mod and hasattr(t_mod, 'source_code'):
                        src_code = t_mod.source_code(val, last_payload_var)
                        v_repr = safe_repr(val_to_repr)
                        if v_repr in src_code:
                            src_code = src_code.replace(v_repr, v_val_var)
                        block += f"    {current_obj_var} = {src_code}" + NL
                    elif provider == Provider.PYCRATE:
                        pdu_class = meta.get("class")
                        encode_method = "to_aper" if "aper" in meta.get("method", "ber") else "to_ber"
                        block += f"    PDU = {pdu_class}" + NL
                        block += "    try:\n        PDU.reset_val()\n    except:\n        pass" + NL
                        block += f"    PDU.set_val({v_val_var})" + NL
                        block += f"    {current_obj_var} = PDU.{encode_method}()" + NL
                    else: # SCAPY fallback
                        scapy_class = p_name
                        orig_hex_for_raw = val.get('_orig_hex', '')
                        block += f"    # Try to build Scapy layer, fallback to Raw on NameError" + NL
                        block += f"    try:" + NL
                        block += f"        if '{scapy_class}' not in locals() and '{scapy_class}' not in globals(): raise NameError('{scapy_class} not found')" + NL
                        
                        constructor_args = []
                        found_raw_payload_key = None
                        raw_payload_val = None
                        main_layer_constructor = ""

                        if p_name == "Raw":
                            load_val = val.get('load') or val.get('raw') or orig_hex_for_raw
                            if load_val:
                                main_layer_constructor = f"Raw(load=unhexlify('{load_val}'))"
                            else:
                                main_layer_constructor = "Raw()"
                        else:
                                                    for field_name, field_value in val.items():
                                                        if field_name.startswith('_') or field_name in ['load', 'payload', 'data']:
                                                            continue
                                                        if field_name in ['raw', 'raw_payload']:
                                                            found_raw_payload_key = field_name
                                                            raw_payload_val = field_value
                                                            continue
                                                        
                                                        final_val = field_value
                                                        update_needed = False
                                                        
                                                        if isinstance(field_value, str) and not p_name.upper().startswith("HTTP"):
                                                            # Don't convert hex strings to integers
                                                            # Hex strings typically have even length and may contain only hex chars
                                                            is_likely_hex = len(field_value) >= 6 and len(field_value) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in field_value)
                                                            if field_value.isdigit() and len(field_value) <= 6 and not is_likely_hex:
                                                                final_val = int(field_value)
                                                                update_needed = True
                                                            elif ":" in field_value:
                                                                try:
                                                                    import socket
                                                                    packed = socket.inet_pton(socket.AF_INET6, field_value)
                                                                    final_val = socket.inet_ntop(socket.AF_INET6, packed)
                                                                    update_needed = True
                                                                except:
                                                                    pass
                            
                                                        if update_needed:
                                                            block += f"        {v_val_var}[{repr(field_name)}] = {final_val!r}" + NL
                            
                                                        constructor_args.append(f"{field_name}={v_val_var}['{field_name}']")
                                                    main_layer_constructor = f"{scapy_class}({', '.join(constructor_args)})" if constructor_args else f"{scapy_class}()"                        
                        final_constructor = main_layer_constructor
                        if not last_payload_var:
                            for fn in ['load', 'data', 'payload']:
                                if fn in val and val[fn]:
                                    final_constructor += f" / Raw(load=unhexlify({v_val_var}['{fn}']))"
                                    break
                        if found_raw_payload_key and not last_payload_var:
                            # Only add raw payload if there's no proper child layer
                            # Ensure the key is in v_val_var for the script to work
                            block += f"        if {repr(found_raw_payload_key)} not in {v_val_var}: {v_val_var}[{repr(found_raw_payload_key)}] = {raw_payload_val!r}" + NL
                            final_constructor += f" / Raw(load=unhexlify({v_val_var}['{found_raw_payload_key}']))"
                        
                        if last_payload_var:
                            block += f"        {current_obj_var} = {final_constructor} / {last_payload_var}" + NL
                        else:
                            block += f"        {current_obj_var} = {final_constructor}" + NL

                        block += f"    except NameError:" + NL
                        block += f"        # Fallback to Raw since '{scapy_class}' is not an available Scapy class" + NL
                        if last_payload_var:
                            block += f"        {current_obj_var} = Raw(load=unhexlify('{orig_hex_for_raw}')) / {last_payload_var}" + NL
                        else:
                            block += f"        {current_obj_var} = Raw(load=unhexlify('{orig_hex_for_raw}'))" + NL
                    
                    logic_body += block
                    last_payload_var = current_obj_var

                # Add Padding at the end if captured (after Ethernet layer is built)
                if padding_hex:
                    logic_body += NL + f"    # Add Ethernet frame padding" + NL
                    logic_body += f"    {last_payload_var} = {last_payload_var} / Padding(load=unhexlify('{padding_hex}'))" + NL

            logic_body += NL + "    return " + (last_payload_var if last_payload_var else "None") + NL
            
        except Exception as e:
            logging.error(f"Script Generation Error: {e}")
            logic_body += f"    # Error generating script: {e}" + NL
            logic_body += "    return None" + NL

        footer = textwrap.dedent(f'''
            if __name__ == '__main__':
                pkt = generate_packet()
                if pkt:
                    link_type = {wpan_dlt} # Link type from source pcap
                    if pkt.haslayer('CookedLinux'): link_type = 113
                    wrpcap('output.pcap', [pkt], linktype=link_type)
        ''')
        
        return header + logic_body + footer

    def _get_possible_layer_dirs(self):
        try:
            core_python_dir = os.path.dirname(os.path.abspath(__file__))
        except:
            core_python_dir = "."
        return [core_python_dir, os.path.join(core_python_dir, "handlers"), "."]
