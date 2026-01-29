import binascii
import copy
from scapy.layers.mobileip import MobileIP

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    try:
        pkt = MobileIP(raw)
        val = {}
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            val[f.name] = v.hex() if isinstance(v, bytes) else v
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
    
    val_copy.pop('chksum', None)

    try:
        pkt = MobileIP(**val_copy)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return ""
