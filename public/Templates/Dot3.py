import binascii
import copy
from scapy.layers.l2 import Dot3, LLC, SNAP
from utils import safe_repr

# CDP header in LLC/SNAP
CDP_LLC_SNAP_HEADER = b'\xaa\xaa\x03\x00\x00\x0c\x20\x00'

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
    
    pkt = Dot3(raw)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
        
    payload = bytes(pkt.payload)
    if payload.startswith(CDP_LLC_SNAP_HEADER):
        # Manually create the nested structure for the engine
        val['load'] = {
            'LLC': {
                'dsap': 0xaa, 'ssap': 0xaa, 'ctrl': 3,
                'load': {
                    'SNAP': {
                        'oui': '00000c', 'code': 0x2000,
                        'load': {
                            'CDP': binascii.hexlify(payload[len(CDP_LLC_SNAP_HEADER):]).decode()
                        }
                    }
                }
            }
        }
    elif payload:
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
    
    raw_payload = None
    if 'load' in val_copy:
        load_val = val_copy['load']
        if isinstance(load_val, dict) and 'LLC' in load_val:
            llc_val = load_val['LLC']
            if isinstance(llc_val.get('load'), dict) and 'SNAP' in llc_val['load']:
                snap_val = llc_val['load']['SNAP']
                if snap_val.get('oui') == '00000c' and snap_val.get('code') == 0x2000:
                    cdp_hex = snap_val['load']['CDP']
                    raw_payload = CDP_LLC_SNAP_HEADER + binascii.unhexlify(cdp_hex)
                    del val_copy['load']

    if not raw_payload:
        raw_payload = _find_and_remove_raw(val_copy)

    # Always pop len to let scapy recalculate it
    val_copy.pop('len', None)
    try:
        pkt = Dot3(**val_copy)
        if raw_payload:
            pkt.add_payload(raw_payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return ""

def source_code(val, payload_var):
    fields = [f"{k}={safe_repr(v)}" for k, v in val.items() if k not in ['raw', 'load', 'payload', '_orig_hex', '_edited', 'len']]
    ctor = f"Dot3({', '.join(fields)})"
    return f"{ctor} / {payload_var}" if payload_var else ctor