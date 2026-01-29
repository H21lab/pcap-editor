def decode(hex_data, **kwargs):
    return {'load': hex_data, '_orig_hex': hex_data}

def encode(val):
    if isinstance(val, dict):
        if 'raw' in val: return val['raw']
        orig_hex = val.get('_orig_hex')
        is_edited = val.get('_edited', False)
        if orig_hex and not is_edited:
            return orig_hex
        load = val.get('load') or val.get('raw') or orig_hex
        return load if load else ""
    return ""

def source_code(val, payload_var):
    load_val = val.get('load') or val.get('raw') or val.get('_orig_hex')
    if load_val:
        return f"Raw(load=unhexlify('{load_val}'))"
    return "Raw()"