import binascii
import copy
from scapy.layers.ppp import HDLC
from utils import safe_repr

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {}
    try:
        pkt = HDLC(raw)
        val = {}
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            val[f.name] = v.hex() if isinstance(v, bytes) else v
        if pkt.payload:
            val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()
        val['_orig_hex'] = hex_data
        return val
    except:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    if orig_hex and not is_edited:
        return orig_hex

    payload = val_copy.pop('load', None)
    if isinstance(payload, str):
        payload = binascii.unhexlify(payload)
    try:
        pkt = HDLC(**val_copy)
        if payload:
            pkt.add_payload(payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    # Use proper HDLC reconstruction for field editing
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', '_orig_hex', '_edited']:
            continue
        fields.append(f"{k}={safe_repr(v)}")

    ctor = f"HDLC({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
