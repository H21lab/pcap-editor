import binascii
import copy
from scapy.contrib.ospf import OSPF_Hdr
from utils import safe_repr

def _find_and_remove_raw(struct):
    if isinstance(struct, list):
        for i, item in enumerate(struct):
            if isinstance(item, dict) and 'raw' in item:
                val = binascii.unhexlify(item['raw']); del struct[i]; return val
            res = _find_and_remove_raw(item)
            if res is not None: return res
    if isinstance(struct, dict):
        for k, v in struct.items():
            if isinstance(v, dict) and 'raw' in v:
                val = binascii.unhexlify(v['raw']); del struct[k]; return val
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    pkt = OSPF_Hdr(raw)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v

    if len(bytes(pkt)) < len(raw):
        val['load'] = binascii.hexlify(raw[len(bytes(pkt)):]).decode()
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    if orig_hex and not is_edited: return orig_hex

    raw_payload = _find_and_remove_raw(val_copy)
    val_copy.pop('len', None)
    val_copy.pop('chksum', None)

    try:
        pkt = OSPF_Hdr(**val_copy)
        if raw_payload:
            pkt.add_payload(raw_payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', 'len', 'chksum', '_orig_hex', '_edited']: continue
        fields.append(f"{k}={safe_repr(v)}")
    ctor = f"OSPF_Hdr({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
