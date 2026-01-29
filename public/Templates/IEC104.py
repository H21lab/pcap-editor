import binascii
import copy
try:
    from scapy.contrib.iec104 import IEC104APCI
except:
    IEC104APCI = None

def decode(hex_data):
    if not IEC104APCI: return {'raw': hex_data}
    raw = binascii.unhexlify(hex_data)
    try:
        pkt = IEC104APCI(raw)
    except:
        return {'raw': hex_data}
        
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
        
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited: return orig_hex
    
    return orig_hex if orig_hex else ""
