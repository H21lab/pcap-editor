import binascii
import copy
import struct
from utils import safe_repr

def decode(hex_data):
    from pycrate_mobile.SIGTRAN import SIGTRAN
    raw = binascii.unhexlify(hex_data)
    try:
        msg = SIGTRAN()
        msg.from_bytes(raw)
        return {
            'val': msg.get_val(),
            '_orig_hex': hex_data
        }
    except:
        return {'raw': hex_data}

def encode(val):
    try:
        from pycrate_mobile.SIGTRAN import SIGTRAN
    except:
        return ""

    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited: return orig_hex

    struct_val = val_copy.get('val', val_copy)

    try:
        msg = SIGTRAN()
        # Clear lengths to force recalculation
        if isinstance(struct_val, list):
             # Header [Version, Reserved, MsgClass, MsgType, Length]
             if len(struct_val) > 0 and isinstance(struct_val[0], list) and len(struct_val[0]) > 4:
                 struct_val[0][4] = None 
             # Params
             if len(struct_val) > 1 and isinstance(struct_val[1], list):
                 for p in struct_val[1]:
                     if isinstance(p, list) and len(p) > 1:
                         p[1] = None # Param Len

        msg.set_val(struct_val)
        return binascii.hexlify(msg.to_bytes()).decode()
    except:
        return ""

def source_code(val, payload_var=None):
    val_repr = safe_repr(val)

    # Build payload injection code only if we have a payload variable
    if payload_var is not None:
        payload_inject = f"""
     # Process parameters and inject payload if marker is used
     (lambda: [
         (lambda params: [
             [(p.__setitem__(1, None) if isinstance(p, list) and len(p) > 1 else None),
              (p.__setitem__(2, (p[2][:12] if isinstance(p[2], (bytes, bytearray)) else b"") + bytes({payload_var})) if isinstance(p, list) and p[0] == 528 and len(p) > 2 else None)]
             for p in params
         ])(v_to_set[1]) if isinstance(v_to_set, list) and len(v_to_set) > 1 and isinstance(v_to_set[1], list) else None
     ])(),"""
    else:
        # Without payload, just clear parameter lengths
        payload_inject = """
     # Clear parameter lengths for recalculation
     (lambda: [
         (lambda params: [
             (p.__setitem__(1, None) if isinstance(p, list) and len(p) > 1 else None)
             for p in params
         ])(v_to_set[1]) if isinstance(v_to_set, list) and len(v_to_set) > 1 and isinstance(v_to_set[1], list) else None
     ])(),"""

    return f"""(lambda val_in={val_repr}: (
    [SIG_LIB := __import__('pycrate_mobile.SIGTRAN', fromlist=['SIGTRAN']),
     msg := SIG_LIB.SIGTRAN(),
     v_to_set := val_in.get('val', val_in),
     (v_to_set.pop('_orig_hex', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('_edited', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('raw', None) if isinstance(v_to_set, dict) else None),
     # Nullify Message Length in Header [Version, Reserved, MsgClass, MsgType, Length]
     (v_to_set[0].__setitem__(4, None) if isinstance(v_to_set, list) and len(v_to_set) > 0 and isinstance(v_to_set[0], list) and len(v_to_set[0]) > 4 else None),{payload_inject}
     msg.set_val(v_to_set),
     msg.to_bytes()][-1]
))()"""

    

    