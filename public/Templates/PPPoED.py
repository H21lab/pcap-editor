import binascii
import copy
from scapy.layers.ppp import PPPoED, PPPoED_Tags
from scapy.packet import Raw
from utils import safe_repr

def _find_and_remove_raw(struct):
    if isinstance(struct, list):
        for i, item in enumerate(struct):
            res = _find_and_remove_raw(item)
            if res is not None: return res
    if isinstance(struct, dict):
        for k, v in list(struct.items()):
            if isinstance(v, dict) and 'raw' in v:
                val = binascii.unhexlify(v['raw']); del struct[k]; return val
        for k in ['load', 'data', 'payload', 'tags']:
            if k in struct:
                if isinstance(struct[k], str):
                    try: val = binascii.unhexlify(struct[k]); del struct[k]; return val
                    except: pass
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    pkt = PPPoED(raw)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    if pkt.payload:
        val['tags'] = binascii.hexlify(bytes(pkt.payload)).decode()
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    if orig_hex and not is_edited: return orig_hex
    
    tags = val_copy.pop('tags', None)
    if isinstance(tags, str): tags = binascii.unhexlify(tags)
    
    val_copy.pop('len', None)
    try:
        pkt = PPPoED(**val_copy)
        if tags: pkt = pkt / Raw(tags)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return ""

def source_code(val, payload_var):
    fields = [f"{k}={safe_repr(v)}" for k, v in val.items() if k not in ['raw', 'tags', 'load', '_orig_hex', '_edited', 'len']]
    ctor = f"PPPoED({', '.join(fields)})"
    
    if payload_var:
        return f"{ctor} / {payload_var}"
    
    tags_hex = val.get('tags', '')
    if tags_hex:
        return f"{ctor} / Raw(unhexlify('{tags_hex}'))"
        
    return ctor
