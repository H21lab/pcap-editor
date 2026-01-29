"""HTTPResponse template using proper Scapy encoding."""
import binascii
import copy
from utils import safe_repr

# Try to import scapy HTTP
try:
    from scapy.layers.http import HTTPResponse
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False

def decode(hex_data, **kwargs):
    """Decode HTTP response - parse for display but preserve original."""
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data, '_orig_bytes': hex_data}

    result = {'_orig_hex': hex_data, '_orig_bytes': hex_data}

    try:
        # Decode as text for display
        text = raw.decode('utf-8', errors='replace')
        lines = text.split('\r\n')

        if not lines or not lines[0].startswith('HTTP/'):
            return {'raw': hex_data, '_orig_hex': hex_data, '_orig_bytes': hex_data}

        first_line = lines[0]
        parts = first_line.split(' ', 2)
        result['Http_Version'] = parts[0] if len(parts) > 0 else 'HTTP/1.1'
        result['Status_Code'] = parts[1] if len(parts) > 1 else '200'
        result['Reason_Phrase'] = parts[2] if len(parts) > 2 else 'OK'

        # Parse headers
        headers = {}
        body_start = len(text)
        for i, line in enumerate(lines[1:], 1):
            if line == '':
                body_start = text.find('\r\n\r\n')
                if body_start >= 0:
                    body_start += 4
                break
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        if headers:
            result['headers'] = headers

        if body_start < len(text) and body_start >= 0:
            body = text[body_start:]
            if body:
                result['body'] = body

        return result

    except:
        return {'raw': hex_data, '_orig_hex': hex_data, '_orig_bytes': hex_data}

def encode(val):
    """Encode HTTP response - use original bytes unless edited."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    orig_bytes = val_copy.pop('_orig_bytes', None)
    is_edited = val_copy.pop('_edited', False)

    if not is_edited and orig_bytes:
        return orig_bytes
    if not is_edited and orig_hex:
        return orig_hex

    try:
        headers = val_copy.pop('headers', {})
        body = val_copy.pop('body', '')
        version = val_copy.get('Http_Version', 'HTTP/1.1')
        status = val_copy.get('Status_Code', '200')
        reason = val_copy.get('Reason_Phrase', 'OK')

        lines = [f"{version} {status} {reason}"]

        for key, value in headers.items():
            lines.append(f"{key}: {value}")

        lines.append('')
        if body:
            lines.append(body)

        text = '\r\n'.join(lines)
        return binascii.hexlify(text.encode('utf-8')).decode()

    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    """Generates Python code for HTTPResponse reconstruction using raw passthrough."""
    hex_str = val.get('_orig_hex', val.get('_orig_bytes', val.get('raw', '')))
    code = f"Raw(load=unhexlify('{hex_str}'))"
    if payload_var:
        code += f" / {payload_var}"
    return code
