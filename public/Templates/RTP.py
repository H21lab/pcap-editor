import binascii
import copy
from scapy.layers.rtp import RTP
from utils import safe_repr

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    try:
        pkt = RTP(raw)
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

    val_copy.pop('payload', None)
    load = val_copy.pop('load', None)

    try:
        pkt = RTP(**val_copy)
        if load:
            pkt = pkt / binascii.unhexlify(load)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', '_orig_hex', '_edited']: continue
        fields.append(f"{k}={safe_repr(v)}")
    ctor = f"RTP({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
