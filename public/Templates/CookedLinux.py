import binascii
import copy
from scapy.layers.l2 import CookedLinux

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
    header = raw[:16]
    payload = raw[16:]
    pkt = CookedLinux(header)
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
    # Convert src field from hex string back to bytes
    if 'src' in val_copy and isinstance(val_copy['src'], str):
        val_copy['src'] = binascii.unhexlify(val_copy['src'])
    try:
        pkt = CookedLinux(**val_copy)
        if raw_payload: pkt.add_payload(raw_payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return ""

def source_code(val, payload_var=None):
    """Generate source code for CookedLinux packet construction.

    Use Raw fallback to ensure byte-perfect reconstruction.
    There are subtle differences in how different Scapy versions
    handle the src field (8 bytes with lladdrlen-based semantics).
    """
    # Build the 16-byte SLL header from field values
    pkttype = val.get('pkttype', 0)
    lladdrtype = val.get('lladdrtype', 1)
    lladdrlen = val.get('lladdrlen', 6)
    proto = val.get('proto', 0x0800)
    src = val.get('src', '0000000000000000')

    # Ensure src is 8 bytes (pad or truncate)
    if isinstance(src, str):
        src_hex = src
    else:
        src_hex = src.hex() if isinstance(src, bytes) else '0000000000000000'
    src_hex = src_hex.ljust(16, '0')[:16]  # 8 bytes = 16 hex chars

    # Build header hex: pkttype(2) + lladdrtype(2) + lladdrlen(2) + src(8) + proto(2)
    header_hex = f"{pkttype:04x}{lladdrtype:04x}{lladdrlen:04x}{src_hex}{proto:04x}"

    code = f"CookedLinux(unhexlify('{header_hex}'))"
    if payload_var:
        code += f" / {payload_var}"
    return code