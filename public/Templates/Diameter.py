import binascii
import copy
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
            if k in struct:
                if isinstance(struct[k], str):
                    try:
                        val = binascii.unhexlify(struct[k])
                        del struct[k]
                        return val
                    except: pass
                elif isinstance(struct[k], (bytes, bytearray)):
                    val = struct[k]
                    del struct[k]
                    return val
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    try:
        from pycrate_diameter.Diameter3GPP import Diameter3GPP
    except:
        return {'raw': hex_data}
    raw = binascii.unhexlify(hex_data)
    try:
        msg = Diameter3GPP()
        msg.from_bytes(raw)
        val = msg.get_val()
        if isinstance(val, dict): val['_orig_hex'] = hex_data
        elif isinstance(val, list): val = {'val': val, '_orig_hex': hex_data}
        return val
    except:
        return {'raw': hex_data}

def encode(val):
    try:
        from pycrate_diameter.Diameter3GPP import Diameter3GPP
    except:
        if isinstance(val, dict) and 'raw' in val: return val['raw']
        return ""

    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    if orig_hex and not is_edited:
        return orig_hex
        
    raw_payload = _find_and_remove_raw(val_copy)
    
    if isinstance(val_copy, dict) and 'val' in val_copy:
        val_copy = val_copy['val']
    
    try:
        msg = Diameter3GPP()
        if isinstance(val_copy, dict): val_copy.pop('len', None) # Pop length
        msg.set_val(val_copy)
        res = msg.to_bytes()
        if raw_payload:
            res += raw_payload
        res_hex = binascii.hexlify(res).decode()
        
        return res_hex
    except:
        return ""

def source_code(val, payload_var=None):
    val_repr = safe_repr(val)
    
    return f"""(lambda val_in={val_repr}: (
    [Diameter3GPP := __import__('pycrate_diameter.Diameter3GPP', fromlist=['Diameter3GPP']).Diameter3GPP,
     msg := Diameter3GPP(),
     v_to_set := val_in.get('val', val_in),
     (v_to_set.pop('len', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('_orig_hex', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('_edited', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('raw', None) if isinstance(v_to_set, dict) else None),
     msg.set_val(v_to_set),
     msg.to_bytes()][-1]
))()"""
