import binascii
from scapy.layers.ppp import PPPoE
from utils import safe_repr

def decode(hex_data):
    """Decodes PPPoE header."""
    raw = binascii.unhexlify(hex_data)
    pkt = PPPoE(raw[:6])
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    return val

def encode(val):
    """Encodes PPPoE header + payload."""
    payload = val.pop('load', None)
    if isinstance(payload, dict) and 'raw' in payload:
        payload = binascii.unhexlify(payload['raw'])
    elif isinstance(payload, str):
        payload = binascii.unhexlify(payload)
    try:
        pkt = PPPoE(**val)
        if payload:
            pkt.add_payload(payload)
        pkt.len = None
        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return ""

def source_code(val, payload_var):
    fields = [f"{k}={safe_repr(v)}" for k, v in val.items() if k not in ['raw', 'load', '_orig_hex', '_edited', 'len']]
    ctor = f"PPPoE({', '.join(fields)})"
    return f"{ctor} / {payload_var}" if payload_var else ctor