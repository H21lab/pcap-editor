import binascii
import copy
try:
    from scapy.contrib.bfd import BFD
    HAS_LIB = True
except ImportError:
    HAS_LIB = False

def decode(hex_data):
    if not hex_data: return {}
    raw = binascii.unhexlify(hex_data)
    if not HAS_LIB: return {'raw': hex_data}
    try:
        pkt = BFD(raw)
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
    
    if not HAS_LIB: return orig_hex if orig_hex else ""
    
    try:
        pkt = BFD(**val_copy)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    orig_hex = val.get('_orig_hex', '')
    if orig_hex:
        # Avoid constructing BFD() with arguments that might reference 'A' or other globals
        return f"BFD(unhexlify('{orig_hex}'))"
    return "BFD()"