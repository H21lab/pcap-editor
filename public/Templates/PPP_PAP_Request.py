import binascii
import copy
from scapy.layers.ppp import PPP_PAP_Request
from utils import safe_repr

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    pkt = PPP_PAP_Request(raw)
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
    
    payload = val_copy.pop('load', None)
    if isinstance(payload, str): payload = binascii.unhexlify(payload)
    
    for field in ['username', 'password']:
        if field in val_copy and isinstance(val_copy[field], str):
            try: val_copy[field] = binascii.unhexlify(val_copy[field])
            except: pass
            
    val_copy.pop('len', None)
    try:
        pkt = PPP_PAP_Request(**val_copy)
        if payload: pkt = pkt / Raw(payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return ""

def source_code(val, payload_var):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', '_orig_hex', '_edited', 'len']: continue
        if k in ['raw', 'username', 'password'] and isinstance(v, str):
            fields.append(f"{k}=unhexlify('{v}')")
        else:
            fields.append(f"{k}={safe_repr(v)}")
            
    ctor = f"PPP_PAP_Request({', '.join(fields)})"
    return f"{ctor} / {payload_var}" if payload_var else ctor