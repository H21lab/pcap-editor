import binascii
import copy
from utils import safe_repr

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {}
    val = {'_orig_hex': hex_data}
    # TFTP_RRQ has filename and mode as null-terminated strings
    try:
        from scapy.layers.tftp import TFTP_RRQ
        pkt = TFTP_RRQ(raw)
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            if isinstance(v, bytes):
                val[f.name] = v.hex()
            else:
                val[f.name] = v
        if pkt.payload:
            val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()
    except:
        val['raw'] = hex_data
    return val

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
        from scapy.layers.tftp import TFTP_RRQ
        pkt = TFTP_RRQ(**val_copy)
        if payload:
            pkt.add_payload(payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    # Try proper TFTP_RRQ reconstruction
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', '_orig_hex', '_edited']: continue
        fields.append(f"{k}={safe_repr(v)}")

    ctor = f"TFTP_RRQ({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
