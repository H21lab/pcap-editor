import binascii
import copy
from scapy.layers.inet import TCP
from scapy.packet import Raw
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
    data_offset = (raw[12] >> 4) * 4
    header = raw[:data_offset]
    payload = raw[data_offset:]
    pkt = TCP(header)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        if f.name == "options": val[f.name] = v
        elif f.name == "flags": val[f.name] = int(v)
        else: val[f.name] = v.hex() if isinstance(v, bytes) else v
    if payload:
        val['load'] = binascii.hexlify(payload).decode()
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited:
        return orig_hex

    raw_payload = _find_and_remove_raw(val_copy)
    
    val_copy.pop('dataofs', None)
    val_copy.pop('chksum', None)
    
    if 'options' in val_copy:
        if not isinstance(val_copy['options'], list): val_copy['options'] = []
        else:
            new_opts = []
            for opt in val_copy['options']:
                if isinstance(opt, (list, tuple)): new_opts.append(tuple(opt))
                elif isinstance(opt, str): new_opts.append((opt, b""))
                else: new_opts.append(opt)
            val_copy['options'] = new_opts
    try:
        pkt = TCP(**val_copy)
        if raw_payload:
            pkt.add_payload(raw_payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return ""

def source_code(val, payload_var):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', 'dataofs', 'chksum', '_orig_hex', '_edited']: continue
        if k == 'options':
            fields.append(f"{k}={safe_repr(v)}")
        elif isinstance(v, str):
            fields.append(f"{k}={safe_repr(v)}")
        else:
            fields.append(f"{k}={safe_repr(v)}")
    
    ctor = f"TCP({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor