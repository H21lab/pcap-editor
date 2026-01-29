import binascii
import copy
from scapy.layers.inet6 import IPv6
from utils import safe_repr

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {}
    try:
        pkt = IPv6(raw)
        val = {}
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            if isinstance(v, bytes):
                val[f.name] = v.hex()
            else:
                val[f.name] = v

        if pkt.payload and bytes(pkt.payload):
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

    # Extract payload
    load = val_copy.pop('load', None)

    # Remove computed fields
    val_copy.pop('plen', None)

    try:
        pkt = IPv6(**val_copy)
        if load:
            pkt = pkt / binascii.unhexlify(load)
        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    fields = []
    for k, v in val.items():
        if k in ('raw', 'load', 'payload', 'plen', '_orig_hex', '_edited'):
            continue
        if k in ('src', 'dst') and isinstance(v, str):
            fields.append(f"{k}='{v}'")
        else:
            fields.append(f"{k}={safe_repr(v)}")

    ctor = f"IPv6({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
