import binascii
import copy
from utils import safe_repr

def decode(hex_data):
    try:
        from pycrate_mobile.SIGTRAN import MTP3
    except:
        return {'raw': hex_data}
    raw = binascii.unhexlify(hex_data)
    try:
        msg = MTP3()
        msg.from_bytes(raw)
        return {
            'val': msg.get_val(),
            '_orig_hex': hex_data
        }
    except:
        return {'raw': hex_data}

def encode(val):
    try:
        from pycrate_mobile.SIGTRAN import MTP3
    except:
        if isinstance(val, dict) and 'raw' in val: return val['raw']
        return ""
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited: return orig_hex
    
    val_to_set = val_copy.get('val', val_copy)
    try:
        msg = MTP3()
        msg.set_val(val_to_set)
        return binascii.hexlify(msg.to_bytes()).decode()
    except:
        return encode_raw(val)

def source_code(val, payload_var=None):
    orig_hex = val.get('_orig_hex', '')
    is_edited = val.get('_edited', False)
    
    if not is_edited and not payload_var and orig_hex:
        return f"Raw(load=unhexlify('{orig_hex}'))"

    val_to_encode = copy.deepcopy(val.get('val', val))
    if isinstance(val_to_encode, dict):
        val_to_encode = {k:v for k,v in val_to_encode.items() if k not in ['raw', '_orig_hex', '_edited', 'raw']}
    
    val_repr = safe_repr(val_to_encode)
    
    code = f"""(lambda: (
    [MTP3_LIB := __import__('pycrate_mobile.SIGTRAN', fromlist=['MTP3']),
     msg := MTP3_LIB.MTP3(),
     msg.set_val({val_repr}),
     msg.to_bytes()][-1]
))()"""
    if payload_var:
        return f"{code} + bytes({payload_var})"
    return code