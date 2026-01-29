import binascii
import struct
import copy
from scapy.layers.sctp import SCTPChunkData
from utils import safe_repr

def _find_and_remove_raw(struct):
    # This helper is kept for the legacy 'encode' path
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
                elif isinstance(struct[k], (bytes, bytearray)):
                    val = struct[k]; del struct[k]; return val
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if len(raw) < 16: return {"raw": hex_data}
    pkt = SCTPChunkData(raw)
    res = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        if f.name == 'data' and isinstance(v, bytes):
            res[f.name] = binascii.hexlify(v).decode()
        else:
            res[f.name] = v
            
    if pkt.payload:
        res["data"] = binascii.hexlify(bytes(pkt.payload)).decode()
    res['_orig_hex'] = hex_data
    return res

def encode(val):
    # Legacy encode function, will be used as a fallback
    if isinstance(val, dict) and "raw" in val: return val["raw"]
    val_copy = copy.deepcopy(val)
    val_copy.pop("_orig_hex", None); val_copy.pop("_edited", False)
    raw_payload = _find_and_remove_raw(val_copy)
    p_bin = raw_payload if raw_payload else b''
    val_copy.pop('len', None)
    if 'ppid' in val_copy: val_copy['proto_id'] = val_copy.pop('ppid')
    pkt = SCTPChunkData(data=p_bin, **val_copy)
    return binascii.hexlify(bytes(pkt)).decode()

def source_code(val, payload_var=None):
    """Generates idiomatic Scapy code for an SCTPChunkData layer."""
    fields = []
    for k, v in val.items():
        if k in ['raw', 'data', 'load', 'payload', '_orig_hex', '_edited', 'len']: continue
        if k == 'ppid': k = 'proto_id' # Scapy uses proto_id
        fields.append(f"{k}={safe_repr(v)}")
    
    # If a payload variable (the encoded NGAP bytes) is provided, set it as 'data'
    if payload_var:
        fields.append(f"data=bytes({payload_var})")
    else:
        # If no payload variable, we must preserve the original data/load
        if 'data' in val and val['data']:
            fields.append(f"data=unhexlify('{val['data']}')")
        elif 'load' in val and val['load']:
             fields.append(f"data=unhexlify('{val['load']}')")

    return f"SCTPChunkData({', '.join(fields)})"
