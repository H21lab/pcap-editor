import binascii
import copy
try:
    from scapy.contrib.lldp import LLDPDU
    HAS_LIB = True
except ImportError:
    HAS_LIB = False

from scapy.packet import Raw

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
    if not HAS_LIB: return {'raw': hex_data}
    try:
        pkt = LLDPDU(raw)
        val = {}
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            val[f.name] = v.hex() if isinstance(v, bytes) else v
        if len(bytes(pkt)) < len(raw):
            val['load'] = binascii.hexlify(raw[len(bytes(pkt)):]).decode()
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

    raw_payload = _find_and_remove_raw(val_copy)
    if not HAS_LIB: return orig_hex if orig_hex else ""
    try:
        pkt = LLDPDU(**val_copy)
        if raw_payload: pkt.add_payload(raw_payload)
        res_hex = binascii.hexlify(bytes(pkt)).decode()
        return res_hex
    except: return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    orig_hex = val.get('_orig_hex', '')
    is_edited = val.get('_edited', False)

    if orig_hex and not is_edited:
        # Try if LLDPDU likes this hex, if not fallback to Raw
        try:
            LLDPDU(binascii.unhexlify(orig_hex))
            return f"LLDPDU(unhexlify('{orig_hex}'))"
        except:
            return f"Raw(load=unhexlify('{orig_hex}'))"
    
    # If edited, we have to try LLDPDU but it might fail if user didn't fix the issue
    return f"LLDPDU()" # Simplified
