"""WAP MMS (Multimedia Messaging Service) template.

This protocol is used for mobile multimedia messaging (pictures, videos, etc).
Uses python-messaging library when available, falls back to raw otherwise.
"""
import binascii

try:
    from messaging.mms.message import MMSMessage
    HAS_MESSAGING = True
except ImportError:
    HAS_MESSAGING = False

def decode(hex_data):
    """Decodes WAP MMS (Multimedia Messaging Service) layer."""
    if not HAS_MESSAGING:
        return {'raw': hex_data, '_orig_hex': hex_data}
    try:
        raw = binascii.unhexlify(hex_data)
        msg = MMSMessage.from_data(raw)
        val = {
            'headers': dict(msg.headers) if hasattr(msg, 'headers') else {},
            'content_type': getattr(msg, 'content_type', None),
            '_orig_hex': hex_data
        }
        return val
    except Exception as e:
        return {'raw': hex_data, '_orig_hex': hex_data, 'error': str(e)}

def encode(val):
    """Encodes WAP MMS layer."""
    if 'raw' in val or not HAS_MESSAGING:
        return val.get('_orig_hex', val.get('raw', ''))
    try:
        msg = MMSMessage()
        if 'headers' in val:
            for k, v in val['headers'].items():
                msg.headers[k] = v
        return binascii.hexlify(msg.encode()).decode()
    except:
        return val.get('_orig_hex', '')

def source_code(val, payload_var=None):
    """Generates Python code for WAP MMS reconstruction."""
    hex_str = val.get('_orig_hex', val.get('raw', ''))
    code = f"Raw(load=unhexlify('{hex_str}'))"
    if payload_var:
        code += f" / {payload_var}"
    return code
