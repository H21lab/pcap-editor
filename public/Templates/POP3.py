"""
POP3 (Post Office Protocol v3) template.
Parses POP3 commands and responses.
"""
import binascii
import copy
from utils import safe_repr

def decode(hex_data, **kwargs):
    """Decode POP3 message from hex."""
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        text = raw.decode('utf-8', errors='replace').strip()
        result = {'_orig_hex': hex_data}

        # Check if it's a response (starts with +OK or -ERR)
        if text.startswith('+OK'):
            result['type'] = 'response'
            result['status'] = 'OK'
            result['message'] = text[4:] if len(text) > 4 else ''
        elif text.startswith('-ERR'):
            result['type'] = 'response'
            result['status'] = 'ERR'
            result['message'] = text[5:] if len(text) > 5 else ''
        else:
            # It's a command
            result['type'] = 'command'
            parts = text.split(' ', 1)
            result['command'] = parts[0].upper()
            result['argument'] = parts[1] if len(parts) > 1 else ''

        return result
    except:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode POP3 message back to hex."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    orig_bytes = val_copy.pop('_orig_bytes', None)
    is_edited = val_copy.pop('_edited', False)

    if not is_edited:
        if orig_bytes: return orig_bytes
        if orig_hex: return orig_hex

    try:
        if val_copy.get('type') == 'response':
            status = val_copy.get('status', 'OK')
            message = val_copy.get('message', '')
            if status == 'OK':
                text = f"+OK {message}\r\n" if message else "+OK\r\n"
            else:
                text = f"-ERR {message}\r\n" if message else "-ERR\r\n"
        else:
            command = val_copy.get('command', 'NOOP')
            argument = val_copy.get('argument', '')
            if argument:
                text = f"{command} {argument}\r\n"
            else:
                text = f"{command}\r\n"

        return binascii.hexlify(text.encode('utf-8')).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    # Text protocols - use raw fallback for reliable round-trip
    from utils import source_code_raw
    return source_code_raw(val, payload_var)
