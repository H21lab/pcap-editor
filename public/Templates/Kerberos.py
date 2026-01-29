import binascii
import copy
try:
    from scapy.layers.kerberos import Kerberos
except:
    from scapy.all import Kerberos

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    try:
        pkt = Kerberos(raw)
    except:
        return {'raw': hex_data}
        
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        # Kerberos uses ASN1 fields
        try: val[f.name] = int(v)
        except: val[f.name] = str(v)
    
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
        pkt = Kerberos(**val_copy)
        if load:
            pkt = pkt / binascii.unhexlify(load)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    # Kerberos uses complex ASN.1 encoding, fall back to Raw
    orig_hex = val.get('_orig_hex', val.get('raw', ''))
    if orig_hex:
        code = f"Raw(load=unhexlify('{orig_hex}'))"
    else:
        code = "Raw()"
    if payload_var:
        return f"{code} / {payload_var}"
    return code
