import binascii
import copy
from utils import safe_repr
try:
    from scapy.layers.ntlm import NTLM_Header as NTLM
except:
    NTLM = None

def decode(hex_data):
    if not NTLM: return {'raw': hex_data}
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    try:
        pkt = NTLM(raw)
    except:
        return {'raw': hex_data}
        
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    
    if pkt.payload:
        val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited: return orig_hex

    load = val_copy.pop('load', None)

    try:
        pkt = NTLM(**val_copy)
        if load:
            pkt = pkt / binascii.unhexlify(load)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    if 'raw' in val:
        return f"Raw(load=unhexlify('{val['raw']}'))"
    fields = [f"{k}={safe_repr(v)}" for k, v in val.items() if k not in ['raw', 'load', '_orig_hex', '_edited']]
    ctor = f"NTLM({', '.join(fields)})"
    return f"{ctor} / {payload_var}" if payload_var else ctor
