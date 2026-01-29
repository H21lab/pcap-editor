import binascii
import copy
from scapy.contrib.pfcp import PFCP

def _find_and_remove_raw(struct):
    if isinstance(struct, list):
        for i, item in enumerate(struct):
            res = _find_and_remove_raw(item)
            if res is not None: return res
    if isinstance(struct, dict):
        for k, v in list(struct.items()):
            if isinstance(v, dict) and 'raw' in v:
                val = binascii.unhexlify(v['raw'])
                del struct[k]
                return val
        for k in ['load', 'data', 'payload']:
            if k in struct and isinstance(struct[k], str):
                try:
                    val = binascii.unhexlify(struct[k])
                    del struct[k]
                    return val
                except: pass
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    try:
        pkt = PFCP(raw)
        val = {}
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            val[f.name] = v.hex() if isinstance(v, bytes) else v
        if pkt.payload:
            val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()
        val['_orig_hex'] = hex_data
        return val
    except:
        return {'raw': hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    if orig_hex and not is_edited: return orig_hex
    
    val_copy.pop('length', None) # PFCP length is computed
    raw_payload = _find_and_remove_raw(val_copy)

    try:
        pkt = PFCP(**val_copy)
        if raw_payload: pkt.add_payload(raw_payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return ""


def source_code(val, payload_var=None):
    """Generate source code for PFCP packet reconstruction.

    PFCP has complex IE_list structures with nested Information Elements.
    To avoid import issues with IE_NodeId, IE_Cause, etc., always use Raw fallback
    for reliable reconstruction.
    """
    orig_hex = val.get('_orig_hex') or val.get('raw', '')
    if orig_hex:
        code = f"Raw(load=unhexlify('{orig_hex}'))"
        return f"{code} / {payload_var}" if payload_var else code
    return "Raw()"
