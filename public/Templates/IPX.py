import binascii
import copy
from utils import safe_repr
try:
    from scapy.layers.ipx import IPX
    HAS_LIB = True
except ImportError:
    HAS_LIB = False

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
    if not HAS_LIB: return {'raw': hex_data}
    pkt = IPX(raw)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    
    payload = bytes(pkt.payload)
    if payload:
        val['load'] = binascii.hexlify(payload).decode()
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited:
        return orig_hex
        
    raw_payload = _find_and_remove_raw(val_copy)
    
    # Always pop len to let scapy recalculate it
    val_copy.pop('len', None)
    val_copy.pop('chksum', None)

    if not HAS_LIB: return orig_hex if orig_hex else ""

    try:
        pkt = IPX(**val_copy)
        if raw_payload:
            pkt.add_payload(raw_payload)
        res_hex = binascii.hexlify(bytes(pkt)).decode()
        if orig_hex and len(res_hex) == len(orig_hex):
            return orig_hex
        return res_hex
    except:
        return ""

def source_code(val, payload_var):
    if not HAS_LIB: return f"Raw(load=unhexlify('{val.get('raw', '')}'))"
    fields = [f"{k}={safe_repr(v)}" for k, v in val.items() if k not in ['raw', 'load', 'payload', '_orig_hex', '_edited', 'len', 'chksum']]
    ctor = f"IPX({', '.join(fields)})"
    return f"{ctor} / {payload_var}" if payload_var else ctor