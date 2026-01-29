import binascii
import copy
from utils import decode_raw, encode_raw

try:
    from scapy.layers.eap import EAPOL
    HAS_LIB = True
except:
    HAS_LIB = False

def decode(hex_data):
    if not HAS_LIB: return decode_raw(hex_data)
    
    raw = binascii.unhexlify(hex_data)
    try:
        pkt = EAPOL(raw)
    except:
        return decode_raw(hex_data)
    
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
        
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if not HAS_LIB: return encode_raw(val)
    
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    # EAPOL does not take 'raw'
    val_copy.pop('raw', None)
    
    if orig_hex and not is_edited: return orig_hex
    
    try:
        pkt = EAPOL(**val_copy)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return encode_raw(val)
