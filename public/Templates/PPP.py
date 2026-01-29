import binascii
import copy
from scapy.layers.ppp import PPP
from utils import safe_repr

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    pkt = PPP(raw)
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
    if isinstance(payload, dict) and 'raw' in payload:
        payload = binascii.unhexlify(payload['raw'])
    elif isinstance(payload, str):
        payload = binascii.unhexlify(payload)
    try:
        pkt = PPP(**val_copy)
        if payload: pkt.add_payload(payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    # Use proper PPP reconstruction for field editing
    fields = [f"{k}={safe_repr(v)}" for k, v in val.items() if k not in ['raw', 'load', '_orig_hex', '_edited']]
    ctor = f"PPP({', '.join(fields)})"
    return f"{ctor} / {payload_var}" if payload_var else ctor
