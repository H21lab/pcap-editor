import binascii
from scapy.layers.ppp import PPP
from utils import safe_repr

def decode(hex_data):
    """Decodes PPP header."""
    raw = binascii.unhexlify(hex_data)
    pkt = PPP(raw[:2])
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    return val

def encode(val):
    """Encodes PPP header + payload."""
    payload = val.pop('load', None)
    if isinstance(payload, dict) and 'raw' in payload:
        payload = binascii.unhexlify(payload['raw'])
    elif isinstance(payload, str):
        payload = binascii.unhexlify(payload)
    try:
        pkt = PPP(**val)
        if payload:
            pkt.add_payload(payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return ""

def source_code(val, payload_var):
    fields = [f"{k}={safe_repr(v)}" for k, v in val.items() if k not in ['raw', 'load', '_orig_hex', '_edited']]
    ctor = f"PPP({', '.join(fields)})"
    return f"{ctor} / {payload_var}" if payload_var else ctor