"""
5G NAS (Non-Access Stratum) template using pycrate.
Used in 5G networks for mobility management and session management.
"""
import binascii
import copy
from utils import safe_repr

try:
    from pycrate_mobile.NAS5G import parse_NAS5G, FGMMSecProtNASMessage
    HAS_PYCRATE = True
except ImportError:
    HAS_PYCRATE = False

def decode(hex_data, **kwargs):
    """Decode 5G NAS message using pycrate."""
    if not HAS_PYCRATE:
        return {'raw': hex_data, '_orig_hex': hex_data}

    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        msg, err = parse_NAS5G(raw)
        if msg is None:
            return {'raw': hex_data, '_orig_hex': hex_data}

        val = msg.get_val()

        # Convert to JSON-serializable format
        result = {'val': val, '_orig_hex': hex_data, '_msg_type': msg.__class__.__name__}
        return result
    except Exception as e:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode 5G NAS message using pycrate."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    orig_bytes = val_copy.pop('_orig_bytes', None)
    is_edited = val_copy.pop('_edited', False)
    msg_type = val_copy.pop('_msg_type', None)

    if not HAS_PYCRATE:
        return orig_hex if orig_hex else ""

    try:
        inner_val = val_copy.get('val', val_copy)

        # Try to use the original message type
        from pycrate_mobile import NAS5G
        if msg_type and hasattr(NAS5G, msg_type):
            msg = getattr(NAS5G, msg_type)()
        else:
            msg = FGMMSecProtNASMessage()

        msg.set_val(inner_val)
        return binascii.hexlify(msg.to_bytes()).decode()
    except Exception as e:
        return orig_hex if orig_hex else ""
def source_code(val, payload_var=None):
    """Generate source code - encode to hex for Raw layer.
    
    For pycrate protocols, payload_var is ignored because the encoded
    structure already contains nested data.
    """
    hex_data = encode(val)
    if hex_data:
        return f"Raw(load=unhexlify('{hex_data}'))"
    orig_hex = val.get('_orig_hex', '')
    return f"Raw(load=unhexlify('{orig_hex}'))" if orig_hex else "Raw()"
