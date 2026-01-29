import binascii
import copy

def safe_repr(obj):
    try:
        if isinstance(obj, (bytes, bytearray)):
            return f"unhexlify('{binascii.hexlify(obj).decode()}')"
        if isinstance(obj, list):
            return "[" + ", ".join(safe_repr(x) for x in obj) + "]"
        if isinstance(obj, tuple):
            items = [safe_repr(x) for x in obj]
            if len(items) == 1: return "(" + items[0] + ",)"
            return "(" + ", ".join(items) + ")"
        if isinstance(obj, dict):
            items = []
            try:
                keys = sorted(list(obj.keys()), key=lambda x: str(x))
            except:
                keys = list(obj.keys())
            for k in keys:
                v = obj[k]
                items.append(f"{repr(k)}: {safe_repr(v)}")
            return "{" + ", ".join(items) + "}"
        if hasattr(obj, 'command'):
            return obj.command()
        if isinstance(obj, (int, float, bool, type(None))): return repr(obj)
        if isinstance(obj, str): return repr(obj)
        if hasattr(obj, 'val') and not isinstance(obj, type): return safe_repr(obj.val)
        if hasattr(obj, 'get_val'): return safe_repr(obj.get_val())
        return repr(str(obj))
    except Exception: return repr(str(obj))

def decode_raw(hex_data):
    return {"raw": hex_data, "_orig_hex": hex_data}

def encode_raw(val):
    if isinstance(val, dict) and 'raw' in val: 
        return val['raw']
    val_copy = copy.deepcopy(val) if isinstance(val, dict) else {}
    orig_hex = val_copy.get('_orig_hex')
    is_edited = val_copy.get('_edited', False)
    if orig_hex and not is_edited:
        return orig_hex
    return orig_hex if orig_hex else ""

def source_code_raw(val, payload_var=None):
    load_val = val.get('load') or val.get('raw') or val.get('_orig_hex')
    if load_val:
        s = f"Raw(load=unhexlify('{load_val}'))"
    else:
        s = "Raw()"
    if payload_var:
        s += f" / {payload_var}"
    return s
