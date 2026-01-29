import binascii
import copy

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

def decode(hex_data, length=None):
    if length is not None:
        return {"load": hex_data[:length*2]}
    return {"load": hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    raw_payload = _find_and_remove_raw(val_copy)
    
    res = val_copy.get('load', '')
    if isinstance(res, (bytes, bytearray)): res = binascii.hexlify(res).decode()
    if raw_payload:
        res += binascii.hexlify(raw_payload).decode()
    return res

def source_code(val, payload_var):
    load = val.get('load', '')
    ctor = f"Raw(load=unhexlify('{load}'))"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor