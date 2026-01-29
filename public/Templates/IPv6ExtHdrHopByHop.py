import binascii
from scapy.layers.inet6 import IPv6ExtHdrHopByHop

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    # Header length is (len + 1) * 8
    nh_len = (raw[1] + 1) * 8
    pkt = IPv6ExtHdrHopByHop(raw[:nh_len])
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        # Options can be complex list of objects, we'll try to keep them if they are simple
        if f.name == "options":
            val[f.name] = v
        else:
            val[f.name] = v.hex() if isinstance(v, bytes) else v
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    payload = val.pop('load', None)
    if isinstance(payload, dict) and 'raw' in payload:
        payload = binascii.unhexlify(payload['raw'])
    
    # Force Scapy to recalculate length
    val.pop('len', None)
    
    try:
        # If options is just strings or something Scapy doesn't like, we might fail
        # but Scapy is usually good at interpreting its own objects
        pkt = IPv6ExtHdrHopByHop(**val)
        if payload: pkt.add_payload(payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return ""