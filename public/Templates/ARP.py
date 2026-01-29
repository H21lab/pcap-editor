import binascii
import copy
from scapy.layers.l2 import ARP
from utils import safe_repr

def _find_and_remove_raw(struct):
    if isinstance(struct, list):
        for i, item in enumerate(struct):
            res = _find_and_remove_raw(item)
            if res is not None: return res
    if isinstance(struct, dict):
        for k, v in list(struct.items()):
            if isinstance(v, dict) and 'raw' in v:
                val = binascii.unhexlify(v['raw'])
                del struct[k]
                return val
        for k in ['load', 'data', 'payload']:
            if k in struct and isinstance(struct[k], str):
                try:
                    val = binascii.unhexlify(struct[k])
                    del struct[k]
                    return val
                except: pass
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    header = raw[:28]
    payload = raw[28:]
    pkt = ARP(header)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    if payload:
        val['load'] = binascii.hexlify(payload).decode()
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    raw_payload = _find_and_remove_raw(val_copy)

    def hex_to_mac(h):
        if not isinstance(h, str): return h
        return ':'.join(h[i:i+2] for i in range(0, len(h), 2))

    if 'hwsrc' in val_copy: val_copy['hwsrc'] = hex_to_mac(val_copy['hwsrc'])
    if 'hwdst' in val_copy: val_copy['hwdst'] = hex_to_mac(val_copy['hwdst'])

    try:
        pkt = ARP(**val_copy)
        if raw_payload: pkt.add_payload(raw_payload)
        res_hex = binascii.hexlify(bytes(pkt)).decode()
        if orig_hex and not is_edited and len(res_hex) == len(orig_hex):
            return orig_hex
        return res_hex
    except: return ""

def source_code(val, payload_var):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', '_orig_hex', '_edited']: continue
        if isinstance(v, str):
            fields.append(f"{k}={safe_repr(v)}")
        else:
            fields.append(f"{k}={safe_repr(v)}")
    
    ctor = f"ARP({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor