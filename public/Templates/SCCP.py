import binascii
import copy
import struct
from utils import safe_repr

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    try:
        import pycrate_mobile.SCCP as SCCP_LIB
        msg, rest = SCCP_LIB.parse_SCCP(raw)
        return {
            'val': msg.get_val(),
            'cls': msg.__class__.__name__,
            '_orig_hex': hex_data
        }
    except:
        return {'raw': hex_data}

def encode(val):
    try:
        import pycrate_mobile.SCCP as SCCP_LIB
    except:
        return ""

    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited: return orig_hex
    
    cls_name = val_copy.pop('cls', 'SCCPUnitData')
    struct_val = val_copy.get('val', val_copy)

    try:
        PDU = getattr(SCCP_LIB, cls_name)()
        PDU.set_val(struct_val)
        return binascii.hexlify(PDU.to_bytes()).decode()
    except:
        return ""

def source_code(val, payload_var=None):
    val_repr = safe_repr(val)
    cls_name = val.get('cls', 'SCCPUnitData')

    # Only include payload injection if we have a payload variable
    if payload_var is not None:
        payload_inject = f"""
     (lambda: [
         (v_to_set[-1].__setitem__(1, bytes({payload_var})) if isinstance(v_to_set[-1], list) and len(v_to_set[-1]) > 1 else None)
     ])() if isinstance(v_to_set, list) and len(v_to_set) > 0 else None,"""
    else:
        payload_inject = ""

    return f"""(lambda val_in={val_repr}: (
    [SCCP_LIB := __import__('pycrate_mobile.SCCP', fromlist=['SCCP']),
     PDU := getattr(SCCP_LIB, '{cls_name}')(),
     v_to_set := val_in.get('val', val_in),
     (v_to_set.pop('_orig_hex', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('_edited', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('raw', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('cls', None) if isinstance(v_to_set, dict) else None),
     # Clear length fields for recalculation (skip first 3 elements: msg_type, handling/class, pointers)
     (lambda: [
         (v_to_set[i].__setitem__(0, None) if isinstance(v_to_set[i], list) and len(v_to_set[i]) > 0 else None)
         for i in range(3, len(v_to_set)) if isinstance(v_to_set, list)
     ])(),{payload_inject}
     PDU.set_val(v_to_set),
     PDU.to_bytes()][-1]
))()"""
