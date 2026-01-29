import binascii
import copy
from scapy.layers.dhcp import BOOTP
from utils import safe_repr

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
    pkt = BOOTP(raw)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    
    payload = bytes(pkt.payload)
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
    
    # Correctly handle 'chaddr', 'sname', 'file' as potentially hex strings
    for field_name in ['chaddr', 'sname', 'file']:
        if field_name in val_copy and isinstance(val_copy[field_name], str):
            try:
                # Ensure it's a hex string before unhexlifying
                if len(val_copy[field_name]) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in val_copy[field_name]):
                    val_copy[field_name] = binascii.unhexlify(val_copy[field_name])
            except: pass

    # Scapy expects 'options' as a list of tuples or specific values, not a raw hex string
    # It might be in 'val_copy' as a list of lists if decoded from JSON, convert to tuples
    if 'options' in val_copy and isinstance(val_copy['options'], list):
        new_options = []
        for opt in val_copy['options']:
            if isinstance(opt, list):
                new_options.append(tuple(opt))
            else:
                new_options.append(opt)
        val_copy['options'] = new_options
    
    # Scapy's BOOTP layer also has an 'flags' field that is an IntEnum, convert if string
    if 'flags' in val_copy and isinstance(val_copy['flags'], str):
        try:
            val_copy['flags'] = int(val_copy['flags'], 16)
        except ValueError:
            pass # Keep original if not a valid hex string

    try:
        pkt = BOOTP(**val_copy)
        if raw_payload:
            pkt.add_payload(raw_payload)
        res_hex = binascii.hexlify(bytes(pkt)).decode()
        
        return res_hex
    except Exception:
        return ""

def source_code(val, payload_var):
    # Use proper BOOTP reconstruction for field editing
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', '_orig_hex', '_edited']: continue
        if k in ['chaddr', 'sname', 'file'] and isinstance(v, str):
            fields.append(f"{k}=unhexlify('{v}')")
        elif k == 'options':
            if isinstance(v, list):
                v_fixed = []
                for opt in v:
                    if isinstance(opt, list) and len(opt) == 2:
                        v_fixed.append(tuple(opt))
                    else:
                        v_fixed.append(opt)
                fields.append(f"{k}={safe_repr(v_fixed)}")
            else:
                fields.append(f"{k}={safe_repr(v)}")
        elif k == 'flags':
            fields.append(f"{k}={safe_repr(str(v))}")
        else:
            fields.append(f"{k}={safe_repr(v)}")

    ctor = f"BOOTP({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
