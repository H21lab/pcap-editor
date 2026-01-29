import sys, socket, binascii, json, textwrap, string, copy
from types import ModuleType

# --- 1. Environment Mocks ---
def install_mocks():
    socket.has_ipv6 = True
    if not hasattr(socket, "AF_INET6"): socket.AF_INET6 = 10
    _orig_inet_pton = socket.inet_pton
    def _mock_inet_pton(af, addr):
        if af == 10:
            if addr == "::": return bytes(16)
            try:
                c = addr.replace(":", "")
                return binascii.unhexlify(c.zfill(32))
            except: return bytes(16)
        return _orig_inet_pton(af, addr)
    socket.inet_pton = _mock_inet_pton
    _orig_ntop = getattr(socket, "inet_ntop", None)
    def _mock_inet_ntop(af, packed):
        if af == 10: return binascii.hexlify(packed).decode()
        return _orig_ntop(af, packed) if _orig_ntop else str(packed)
    socket.inet_ntop = _mock_inet_ntop
    ssl_mock = ModuleType("ssl"); ssl_mock.HAS_SNI = True; sys.modules["ssl"] = ssl_mock

# --- 2. Scapy Initialization ---
def init_scapy():
    import scapy.config
    scapy.config.conf.ipv6_enabled = True
    from scapy.all import load_layer, load_contrib
    for l in ["dns", "snmp", "ntp", "dhcp", "sctp"]:
        try: load_layer(l)
        except: pass
    for c in ["gtp", "http2"]:
        try: load_contrib(c)
        except: pass

# --- 3. Pycrate Integration ---
PYCRATE_INSTANCES = {}

def pycrate_to_fields(inst):
    fields = []
    if hasattr(inst, 'get_val_paths'):
        try:
            paths = inst.get_val_paths()
            for path, val in paths:
                name = ".".join(str(p) for p in path)
                try: node = inst.get_at(path); type_name = type(node).__name__
                except: type_name = "Unknown"
                val_str = val.hex() if isinstance(val, (bytes, bytearray)) else str(val)
                fields.append({"name": name, "value": val_str, "type": type_name, "editable": True})
            if fields: return fields
        except: pass
    try:
        val = inst.get_val()
        def rec(v, prefix=""):
            res = []
            if isinstance(v, dict):
                for k, sv in v.items(): res.extend(rec(sv, prefix + str(k) + "."))
            elif isinstance(v, (list, tuple)):
                if len(v) == 2 and isinstance(v[0], str): 
                    res.extend(rec(v[1], prefix + v[0] + "."))
                else:
                    for i, sv in enumerate(v): res.extend(rec(sv, prefix + "[" + str(i) + "]"))
            else:
                vs = v.hex() if isinstance(v, (bytes, bytearray)) else str(v)
                res.append({"name": prefix.rstrip('.'), "value": vs, "type": type(v).__name__, "editable": True})
            return res
        return rec(val)
    except: return []

def deep_dissect_pycrate(data, pkt_id, start_idx):
    ui_layers, curr_idx = [], start_idx
    try:
        from pycrate_mobile.M3UA import parse_M3UA
        from pycrate_mobile.SCCP import parse_SCCP
        from pycrate_asn1dir import TCAP_MAPv2v3
        m3ua, err, m_offset = None, True, 0
        m3ua, err = parse_M3UA(data)
        if err and len(data) > 4: m3ua, err = parse_M3UA(data[4:]); m_offset = 4
        if not err:
            PYCRATE_INSTANCES[f"{pkt_id}_{curr_idx}"] = ("M3UA", m3ua, m_offset)
            ui_layers.append({"index": curr_idx, "name": "M3UA (Pycrate)", "class": "M3UA", "fields": pycrate_to_fields(m3ua)})
            curr_idx += 1
            for i in range(m_offset, len(data)-10):
                if data[i] == 0x09:
                    sccp, s_err = parse_SCCP(data[i:])
                    if not s_err:
                        PYCRATE_INSTANCES[f"{pkt_id}_{curr_idx}"] = ("SCCP", sccp, i)
                        ui_layers.append({"index": curr_idx, "name": "SCCP (Pycrate)", "class": "SCCP", "fields": pycrate_to_fields(sccp)})
                        curr_idx += 1
                        for j in range(i+1, len(data)-4):
                            if data[j] == 0x62:
                                tm = copy.deepcopy(TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message)
                                try:
                                    tm.from_ber(data[j:])
                                    PYCRATE_INSTANCES[f"{pkt_id}_{curr_idx}"] = ("TCAP-MAP", tm, j)
                                    ui_layers.append({"index": curr_idx, "name": "TCAP/MAP (Pycrate)", "class": "TCAP_MAP_Message", "fields": pycrate_to_fields(tm)})
                                    return ui_layers
                                except: pass
                        break
    except: pass
    return ui_layers

# --- 4. Scapy Helpers ---
def get_expanded_fields(pkt):
    from scapy.packet import Raw
    fields_info = []
    if isinstance(pkt, Raw):
         fields_info.append({"name": "load", "value": pkt.load.hex(), "type": "RawBytes", "editable": True})
         return fields_info
    if hasattr(pkt, "fields_desc"):
        for f in pkt.fields_desc:
            try:
                val = pkt.getfieldval(f.name)
                vs = val.hex() if isinstance(val, bytes) else str(val)
                fields_info.append({"name": f.name, "value": vs, "type": f.__class__.__name__, "editable": True})
            except: pass
    return fields_info

def serialize_pycrate_object(inst):
    if hasattr(inst, 'to_ber'): return inst.to_ber()
    if hasattr(inst, 'to_bytes'): return inst.to_bytes()
    return bytes(inst)

def reconstruct_packet(hex_data):
    from scapy.layers.l2 import Ether, CookedLinux
    from scapy.layers.inet import IP
    data = binascii.unhexlify(hex_data)
    for cls in [Ether, CookedLinux, IP]:
        try:
            pkt = cls(data)
            if len(pkt) > 10: 
                # If SCTP is present, try to force dissection of SCTPChunkData
                if pkt.haslayer("SCTP"):
                    from scapy.layers.sctp import SCTP, SCTPChunkData
                    sctp = pkt.getlayer(SCTP)
                    if isinstance(sctp.payload, Raw):
                        try:
                            cd = SCTPChunkData(sctp.payload.load)
                            sctp.payload = cd
                        except: pass
                return pkt
        except: pass
    from scapy.all import Ether
    return Ether(data)

# --- 5. Main Entry Points ---
def dissect(hex_data, ws_layers_json, pkt_id=None):
    if pkt_id is None: pkt_id = hex_data
    try:
        from scapy.packet import NoPayload
        pkt = reconstruct_packet(hex_data)
        layers_info, current, idx = [], pkt, 0
        while current and not isinstance(current, NoPayload):
            layers_info.append({"index": idx, "name": current.name, "class": current.__class__.__name__, "fields": get_expanded_fields(current)})
            current, idx = current.payload, idx + 1
        last = pkt.lastlayer()
        raw_p = bytes(last.data) if hasattr(last, 'data') else (bytes(last.payload) if not isinstance(last.payload, NoPayload) else bytes(pkt))
        
        py_layers = deep_dissect_pycrate(raw_p, pkt_id, idx)
        layers_info.extend(py_layers)
        
        # Build command with Pycrate ASN.1 code
        cmd = pkt.command().replace(chr(0), '')
        if py_layers:
            cmd += "\n\n# --- Pycrate ASN.1 Representation ---"
            for pl in py_layers:
                ikey = f"{pkt_id}_{pl['index']}"
                if ikey in PYCRATE_INSTANCES:
                    inst = PYCRATE_INSTANCES[ikey][1]
                    if hasattr(inst, 'to_asn1'):
                        cmd += f"\n# {pl['name']}:\n"
                        cmd += textwrap.indent(inst.to_asn1(), "# ")
                    elif hasattr(inst, 'show'):
                        # M3UA/SCCP might have a show() or just repr
                        cmd += f"\n# {pl['name']} value:\n# {repr(inst.get_val())}\n"
        
        return json.dumps({"layers": layers_info, "command": cmd})
    except Exception as e: return json.dumps({"error": str(e)})

def edit(hex_data, edits_json, ws_layers_json, pkt_id=None):
    if pkt_id is None: pkt_id = hex_data
    try:
        from scapy.packet import Raw
        pkt = reconstruct_packet(hex_data); edits = json.loads(edits_json)
        last = pkt.lastlayer()
        payload_bytes = bytes(last.data) if hasattr(last, 'data') else (bytes(last.payload) if not isinstance(last.payload, NoPayload) else bytes(pkt))
        
        py_changed = False
        for ed in edits:
            ikey = f"{pkt_id}_{ed['layer_index']}"
            if ikey in PYCRATE_INSTANCES:
                l_type, inst, start = PYCRATE_INSTANCES[ikey]; path = ed['field'].split('.'); val = ed['value']
                ppath = [int(p) if p.isdigit() else p for p in path]
                try:
                    if hasattr(inst, 'get_at'):
                        node = inst.get_at(ppath); t = type(node).__name__
                        if any(x in t for x in ['OCT', 'STR', 'OID']): val = binascii.unhexlify(val)
                        elif any(x in t for x in ['INT', 'ENUM']): val = int(val)
                    else:
                        if all(c in string.hexdigits for c in val) and len(val) >= 2: val = binascii.unhexlify(val)
                        elif val.isdigit(): val = int(val)
                except: pass
                def upd(obj, pts, nv):
                    if not pts: return nv
                    k = pts[0]
                    if isinstance(obj, dict): obj[k] = upd(obj.get(k), pts[1:], nv)
                    elif isinstance(obj, (list, tuple)):
                        l = list(obj)
                        if isinstance(k, int): l[k] = upd(l[k], pts[1:], nv)
                        elif len(l) == 2 and l[0] == k: l[1] = upd(l[1], pts[1:], nv)
                        return tuple(l) if isinstance(obj, tuple) else l
                    return obj
                inst.set_val(upd(inst.get_val(), ppath, val))
                payload_bytes = payload_bytes[:start] + serialize_pycrate_object(inst)
                py_changed = True
        
        if py_changed:
            if hasattr(last, 'data'): last.data = payload_bytes
            if hasattr(last, 'len'): del last.len
            else: last.payload = Raw(payload_bytes)
        
        for l in pkt:
            for f in ['chksum', 'len', 'length', 'cksum', 'datalen']:
                if hasattr(l, f): 
                    try: delattr(l, f)
                    except: pass
        
        # Force a full rebuild of the packet to ensure headers are updated
        rebuilt_pkt = pkt.__class__(bytes(pkt))
        return binascii.hexlify(bytes(rebuilt_pkt)).decode('ascii')
    except Exception as e: return json.dumps({"error": str(e)})

def run_script(hex_data, script_text, ws_layers_json):
    try:
        pkt = reconstruct_packet(hex_data); ns = {"pkt": pkt}
        from scapy.all import IP, TCP, UDP, SCTP
        ns.update({"IP": IP, "TCP": TCP, "UDP": UDP, "SCTP": SCTP})
        exec(textwrap.dedent(script_text), ns)
        rebuilt = ns.get("pkt", pkt)
        return binascii.hexlify(bytes(rebuilt.__class__(bytes(rebuilt)))).decode('ascii')
    except Exception as e: return json.dumps({"error": str(e)})

install_mocks()
init_scapy()