import binascii
import copy
from utils import decode_raw, encode_raw, safe_repr
from scapy.all import DNS

def decode(hex_data):
    # Standard Scapy dissection is preferred via ScapyHandler
    # This is only if called directly
    return decode_raw(hex_data)

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    if orig_hex and not is_edited:
        return orig_hex

    # Try to re-encode with Scapy
    try:
        # Filter to valid DNS fields
        valid_fields = set([f.name for f in DNS().fields_desc])
        dns_fields = {k: v for k, v in val_copy.items() if k in valid_fields}
        pkt = DNS(**dns_fields)
        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    # Use proper DNS reconstruction for field editing
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', '_orig_hex', '_edited']: continue
        fields.append(f"{k}={safe_repr(v)}")

    ctor = f"DNS({', '.join(fields)})" if fields else "DNS()"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
