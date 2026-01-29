import binascii
import copy
from scapy.contrib.bgp import BGPHeader
from utils import safe_repr

def _find_and_remove_raw(struct):
    if isinstance(struct, list):
        for i, item in enumerate(struct):
            res = _find_and_remove_raw(item)
            if res is not None: return res
    if isinstance(struct, dict):
        # 1. Check for {'raw': ...}
        for k, v in list(struct.items()):
            if isinstance(v, dict) and 'raw' in v:
                val = binascii.unhexlify(v['raw'])
                del struct[k]
                return val
        # 2. Check for load/data/payload as hex strings
        for k in ['load', 'data', 'payload']:
            if k in struct and isinstance(struct[k], str):
                try:
                    val = binascii.unhexlify(struct[k])
                    del struct[k]
                    return val
                except: pass
        # 3. Recurse
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    pkt = BGPHeader(raw)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    
    # Check for payload after header
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

    try:
        pkt = BGPHeader(**val_copy)
        if raw_payload:
            pkt.add_payload(raw_payload)
        res_hex = binascii.hexlify(bytes(pkt)).decode()
        return res_hex
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', 'len', '_orig_hex', '_edited']: continue
        if k == 'marker' and isinstance(v, str):
            fields.append(f"{k}=unhexlify('{v}')")
        else:
            fields.append(f"{k}={safe_repr(v)}")
    ctor = f"BGPHeader({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor