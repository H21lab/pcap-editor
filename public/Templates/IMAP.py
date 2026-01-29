"""
IMAP (Internet Message Access Protocol) template.
Parses IMAP commands and responses.
"""
import binascii
import copy
from utils import safe_repr

def decode(hex_data, **kwargs):
    """Decode IMAP message from hex."""
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        text = raw.decode('utf-8', errors='replace').strip()
        result = {'_orig_hex': hex_data}

        parts = text.split(' ', 2)

        # Check for untagged responses (start with *)
        if parts[0] == '*':
            result['type'] = 'untagged_response'
            if len(parts) > 1:
                result['response'] = parts[1]
                result['data'] = parts[2] if len(parts) > 2 else ''
        # Check for continuation (+)
        elif parts[0] == '+':
            result['type'] = 'continuation'
            result['data'] = ' '.join(parts[1:]) if len(parts) > 1 else ''
        # Check for tagged responses (tag followed by OK/NO/BAD)
        elif len(parts) > 1 and parts[1] in ('OK', 'NO', 'BAD', 'PREAUTH', 'BYE'):
            result['type'] = 'tagged_response'
            result['tag'] = parts[0]
            result['status'] = parts[1]
            result['message'] = parts[2] if len(parts) > 2 else ''
        else:
            # It's a command
            result['type'] = 'command'
            result['tag'] = parts[0] if parts else ''
            result['command'] = parts[1].upper() if len(parts) > 1 else ''
            result['arguments'] = parts[2] if len(parts) > 2 else ''

        return result
    except:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode IMAP message back to hex."""
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
        msg_type = val_copy.get('type', 'command')

        if msg_type == 'untagged_response':
            response = val_copy.get('response', '')
            data = val_copy.get('data', '')
            text = f"* {response} {data}\r\n" if data else f"* {response}\r\n"
        elif msg_type == 'continuation':
            data = val_copy.get('data', '')
            text = f"+ {data}\r\n" if data else "+\r\n"
        elif msg_type == 'tagged_response':
            tag = val_copy.get('tag', 'A001')
            status = val_copy.get('status', 'OK')
            message = val_copy.get('message', '')
            text = f"{tag} {status} {message}\r\n" if message else f"{tag} {status}\r\n"
        else:
            tag = val_copy.get('tag', 'A001')
            command = val_copy.get('command', 'NOOP')
            arguments = val_copy.get('arguments', '')
            if arguments:
                text = f"{tag} {command} {arguments}\r\n"
            else:
                text = f"{tag} {command}\r\n"

        return binascii.hexlify(text.encode('utf-8')).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    # Text protocols - use raw fallback for reliable round-trip
    from utils import source_code_raw
    return source_code_raw(val, payload_var)
