import binascii
import copy

HAS_LIB = False 

def decode(hex_data):
    if not hex_data: return {}
    return {'raw': hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    return val.get('_orig_hex', '')

def source_code(val, payload_var):
    orig_hex = val.get('raw', val.get('_orig_hex', ''))
    if orig_hex:
        return f"Raw(load=unhexlify('{orig_hex}'))"
    return "Raw()"