import binascii
import copy
from utils import decode_raw, encode_raw, safe_repr

HAS_LIB = False
try:
    import pycrate_mobile.ISUP as ISUP_LIB
    HAS_LIB = True
except:
    pass

def decode(hex_data):
    if not HAS_LIB: return {'raw': hex_data}
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    try:
        msg, rest = ISUP_LIB.parse_ISUP(raw)
        val = msg.get_val()
        return {
            'val': val,
            'cls': msg.__class__.__name__,
            '_orig_hex': hex_data
        }
    except:
        return {'raw': hex_data}

def encode(val):
    if not HAS_LIB: return encode_raw(val)
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    cls_name = val_copy.pop('cls', 'IAM')
    
    if orig_hex and not is_edited: return orig_hex
    
    try:
        val_to_set = val_copy.get('val', val_copy)
        # Instantiate correct class
        PDU_CLS = getattr(ISUP_LIB, cls_name)
        pkt = PDU_CLS()
        pkt.set_val(val_to_set)
        return binascii.hexlify(pkt.to_bytes()).decode()
    except:
        return encode_raw(val)

def source_code(val, payload_var=None):
    val_to_encode = val.get('val', val)
    cls_name = val.get('cls', 'IAM')
    val_repr = safe_repr(val_to_encode)
    
    return f"""(lambda: (
    [ISUP_LIB := __import__('pycrate_mobile.ISUP', fromlist=['ISUP']),
     PDU := getattr(ISUP_LIB, '{cls_name}')(),
     PDU.set_val({val_repr}),
     PDU.to_bytes()][-1]
))()"""