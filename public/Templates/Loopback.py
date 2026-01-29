import binascii
import copy
from scapy.layers.l2 import Loopback

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
    header = raw[:4]
    payload = raw[4:]
    pkt = Loopback(header)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    if payload:
        val['load'] = binascii.hexlify(payload).decode()
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    raw_payload = _find_and_remove_raw(val_copy)
    try:
        pkt = Loopback(**val_copy)
        if raw_payload: pkt.add_payload(raw_payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return ""