import binascii
import copy
from utils import decode_raw, encode_raw, safe_repr

try:
    from scapy.layers.hsrp import HSRP
    HAS_LIB = True
except:
    HAS_LIB = False

def decode(hex_data):
    if not HAS_LIB: return decode_raw(hex_data)
    
    raw = binascii.unhexlify(hex_data)
    try:
        pkt = HSRP(raw)
    except:
        return decode_raw(hex_data)
        
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        if isinstance(v, bytes):
            val[f.name] = v.hex()
        else:
            val[f.name] = v
            
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if not HAS_LIB: return encode_raw(val)
    
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited: return orig_hex
    
    # Convert hex strings back to bytes for auth field
    if 'auth' in val_copy and isinstance(val_copy['auth'], str):
        try:
            val_copy['auth'] = binascii.unhexlify(val_copy['auth'])
        except:
            pass

    try:
        pkt = HSRP(**val_copy)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return encode_raw(val)

def source_code(val, payload_var):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', '_orig_hex', '_edited']: continue
        if k == 'auth' and isinstance(v, str):
            fields.append(f"{k}=unhexlify('{v}')")
        else:
            fields.append(f"{k}={safe_repr(v)}")

    ctor = f"HSRP({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
