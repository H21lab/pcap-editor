import binascii
import copy
from scapy.layers.zigbee import ZigbeeNWK

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    try:
        pkt = ZigbeeNWK(raw)
    except:
        return {'raw': hex_data}
        
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    
    if pkt.payload:
        val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited: return orig_hex

    load = val_copy.pop('load', None)

    try:
        pkt = ZigbeeNWK(**val_copy)
        if load:
            pkt = pkt / binascii.unhexlify(load)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    orig_hex = val.get('_orig_hex', '')
    is_edited = val.get('_edited', False)
    if orig_hex and not is_edited:
        return f"ZigbeeNWK(unhexlify('{orig_hex}'))"
    return "ZigbeeNWK()"