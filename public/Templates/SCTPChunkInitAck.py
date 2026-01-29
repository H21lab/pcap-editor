import binascii
import copy
from scapy.layers.sctp import SCTPChunkInitAck
from scapy.packet import Raw
from utils import safe_repr

def _find_and_remove_raw(struct):
    if isinstance(struct, list):
        for i, item in enumerate(struct):
            res = _find_and_remove_raw(item)
            if res is not None: return res
    if isinstance(struct, dict):
        for k, v in list(struct.items()):
            if isinstance(v, dict) and 'raw' in v:
                val = binascii.unhexlify(v['raw']); del struct[k]; return val
        for k in ['load', 'data', 'payload']:
            if k in struct:
                if isinstance(struct[k], str):
                    try: val = binascii.unhexlify(struct[k]); del struct[k]; return val
                    except: pass
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    pkt = SCTPChunkInitAck(raw)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        if f.name == 'params':
            # Scapy's SCTP params are complex, fallback to hex for now or better representation
            val[f.name] = [binascii.hexlify(bytes(p)).decode() for p in v]
        elif isinstance(v, bytes):
            val[f.name] = v.hex()
        else:
            val[f.name] = v
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    if orig_hex and not is_edited: return orig_hex
    
    params_val = val_copy.pop('params', [])
    if params_val:
        # Reconstruct params from hex
        from scapy.layers.sctp import SCTPParam
        val_copy['params'] = [SCTPParam(binascii.unhexlify(p)) for p in params_val]
        
    val_copy.pop('len', None)
    val_copy.pop('type', None)
    try:
        pkt = SCTPChunkInitAck(**val_copy)
        res_bytes = bytes(pkt)
        pad_len = (4 - (len(res_bytes) % 4)) % 4
        if pad_len > 0: res_bytes += b'\x00' * pad_len
        return binascii.hexlify(res_bytes).decode()
    except: return ""

def source_code(val, payload_var):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', 'len', '_orig_hex', '_edited', 'type']: continue
        if k == 'params':
            p_list = [f"Raw(unhexlify('{p}'))" for p in v]
            fields.append(f"params=[{', '.join(p_list)}]")
        elif isinstance(v, str):
            fields.append(f"{k}={safe_repr(v)}")
        else:
            fields.append(f"{k}={safe_repr(v)}")
    
    ctor = f"SCTPChunkInitAck({', '.join(fields)})"
    return f"{ctor} / {payload_var}" if payload_var else ctor