"""
RTSP (Real Time Streaming Protocol) template.
Parses RTSP requests and responses.
"""
import binascii
import copy
from utils import safe_repr

def decode(hex_data, **kwargs):
    """Decode RTSP message from hex."""
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        text = raw.decode('utf-8', errors='replace')
        result = {'_orig_hex': hex_data}

        # Split headers from body
        parts = text.split('\r\n\r\n', 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ''

        lines = header_section.split('\r\n')
        first_line = lines[0] if lines else ''

        # Check if response or request
        if first_line.startswith('RTSP/'):
            # Response
            result['type'] = 'response'
            parts = first_line.split(' ', 2)
            result['version'] = parts[0]
            result['status_code'] = int(parts[1]) if len(parts) > 1 else 0
            result['reason'] = parts[2] if len(parts) > 2 else ''
        else:
            # Request
            result['type'] = 'request'
            parts = first_line.split(' ', 2)
            result['method'] = parts[0]
            result['uri'] = parts[1] if len(parts) > 1 else ''
            result['version'] = parts[2] if len(parts) > 2 else 'RTSP/1.0'

        # Parse headers
        headers = {}
        for line in lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        result['headers'] = headers

        if body:
            result['body'] = body

        return result
    except:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode RTSP message back to hex."""
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
        lines = []

        if val_copy.get('type') == 'response':
            version = val_copy.get('version', 'RTSP/1.0')
            status_code = val_copy.get('status_code', 200)
            reason = val_copy.get('reason', 'OK')
            lines.append(f"{version} {status_code} {reason}")
        else:
            method = val_copy.get('method', 'OPTIONS')
            uri = val_copy.get('uri', '*')
            version = val_copy.get('version', 'RTSP/1.0')
            lines.append(f"{method} {uri} {version}")

        # Add headers
        headers = val_copy.get('headers', {})
        for key, value in headers.items():
            lines.append(f"{key}: {value}")

        text = '\r\n'.join(lines) + '\r\n\r\n'

        # Add body if present
        body = val_copy.get('body', '')
        if body:
            text += body

        return binascii.hexlify(text.encode('utf-8')).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    # Use raw fallback for RTSP - complex text structure
    from utils import source_code_raw
    return source_code_raw(val, payload_var)
