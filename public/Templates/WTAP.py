import binascii
import copy

def decode(hex_data, length=None):
    if length is not None:
        header_len = min(len(hex_data), length * 2)
        wpan_tap_header = hex_data[:header_len]
        return {
            'header': wpan_tap_header,
            'load': '',
            '_orig_hex': wpan_tap_header
        }
    # wpan-tap header is 100 bytes long
    wpan_tap_header = hex_data[:200]
    payload = hex_data[200:]
    return {
        'header': wpan_tap_header,
        'load': payload,
        '_orig_hex': hex_data
    }

def encode(val):
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']
    
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    header = val_copy.get('header', '')
    load = val_copy.get('load', '')

    # If the load is a bytes object, hexlify it
    if isinstance(load, bytes):
        load = binascii.hexlify(load).decode()

    res_hex = header + load
    
    if orig_hex and not is_edited and len(res_hex) == len(orig_hex):
        return orig_hex
    return res_hex

def source_code(val, payload_var):
    header = val.get('header', '')
    load = val.get('load', '')
    
    ctor = f"Raw(unhexlify('{header}'))"
    
    if load:
        gap_layer = f"Raw(unhexlify('{load}'))"
        ctor = f"{ctor} / {gap_layer}"
        
    return f"{ctor} / {payload_var}" if payload_var else ctor
