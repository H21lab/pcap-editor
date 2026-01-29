"""Dot15d4Data template using proper Scapy encoding."""
import binascii
import copy
from scapy.layers.dot15d4 import Dot15d4Data
from scapy.all import Raw
from utils import safe_repr

def decode(hex_data, **kwargs):
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data, '_orig_bytes': hex_data}

    try:
        pkt = Dot15d4Data(raw)
        val = {}
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            if isinstance(v, bytes):
                val[f.name] = v.hex()
            else:
                val[f.name] = v

        if pkt.payload and hasattr(pkt.payload, 'load'):
            val['load'] = binascii.hexlify(pkt.payload.load).decode()
        elif pkt.payload:
            val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()

        val['_orig_hex'] = hex_data
        val['_orig_bytes'] = hex_data
        return val
    except:
        return {'raw': hex_data, '_orig_hex': hex_data, '_orig_bytes': hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    orig_bytes = val_copy.pop('_orig_bytes', None)
    is_edited = val_copy.pop('_edited', False)

    try:
        load = val_copy.pop('load', None)
        pkt = Dot15d4Data(**val_copy)
        if load:
            pkt = pkt / Raw(load=binascii.unhexlify(load))
        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', '_orig_hex', '_orig_bytes', '_edited']:
            continue
        fields.append(f"{k}={safe_repr(v)}")

    ctor = f"Dot15d4Data({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
