import binascii
import copy
try:
    from scapy.layers.can import CAN
    HAS_LIB = True
except ImportError:
    HAS_LIB = False

def decode(hex_data):
    if not hex_data: return {}
    raw = binascii.unhexlify(hex_data)
    if not HAS_LIB: return {'raw': hex_data}
    try:
        pkt = CAN(raw)
        val = {}
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            val[f.name] = v.hex() if isinstance(v, bytes) else v
        
        # CAN doesn't usually have a payload in the traditional sense like IP,
        # but if there are extra bytes, store them
        if len(bytes(pkt)) < len(raw):
             val['load'] = binascii.hexlify(raw[len(bytes(pkt)):]).decode()
             
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
        pkt = CAN(**val_copy)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    orig_hex = val.get('_orig_hex', '')
    if orig_hex:
        return f"CAN(unhexlify('{orig_hex}'))"
    return "CAN()"