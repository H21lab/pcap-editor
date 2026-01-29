import binascii
import copy

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {}
    val = {
        'direction': raw[0],
        '_orig_hex': hex_data
    }
    if len(raw) > 1:
        val['load'] = binascii.hexlify(raw[1:]).decode()
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    if orig_hex and not is_edited:
        return orig_hex

    # PPPDirection is just a direction byte followed by payload
    direction = val_copy.get('direction', 0)
    payload = val_copy.get('load', '')
    if isinstance(payload, str):
        payload_bytes = binascii.unhexlify(payload) if payload else b''
    else:
        payload_bytes = payload if payload else b''

    result = bytes([direction]) + payload_bytes
    return binascii.hexlify(result).decode()

def source_code(val, payload_var):
    # PPPDirection is a custom layer for DLT 204 direction byte
    # Use proper reconstruction
    direction = val.get('direction', 0)
    code = f"PPPDirection(direction={direction})"
    if payload_var:
        return f"{code} / {payload_var}"
    return code
