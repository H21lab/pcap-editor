"""
GTPv2-C (GTP Control Plane v2) template using pycrate.
Used in LTE/4G and 5G networks for signaling.
"""
import binascii
import copy
from utils import safe_repr

try:
    from pycrate_mobile.TS29274_GTPC import GTPCMsg
    HAS_PYCRATE = True
except ImportError:
    HAS_PYCRATE = False

def decode(hex_data, **kwargs):
    """Decode GTPv2-C message using pycrate."""
    if not HAS_PYCRATE:
        return {'raw': hex_data, '_orig_hex': hex_data}

    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        msg = GTPCMsg()
        msg.from_bytes(raw)
        val = msg.get_val()

        # Convert to JSON-serializable format
        result = {'val': val, '_orig_hex': hex_data}
        return result
    except Exception as e:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode GTPv2-C message using pycrate."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    orig_bytes = val_copy.pop('_orig_bytes', None)
    is_edited = val_copy.pop('_edited', False)

    if not HAS_PYCRATE:
        return orig_hex if orig_hex else ""

    try:
        inner_val = val_copy.get('val', val_copy)

        msg = GTPCMsg()
        msg.set_val(inner_val)
        return binascii.hexlify(msg.to_bytes()).decode()
    except Exception as e:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    """Generate source code - encode pycrate value to hex for Raw layer.

    Note: payload_var is IGNORED because pycrate protocols embed their payload
    in the encoded structure. The encoded hex already contains everything.
    """
    hex_data = encode(val)
    if hex_data:
        return f"Raw(load=unhexlify('{hex_data}'))"
    orig_hex = val.get('_orig_hex', '')
    return f"Raw(load=unhexlify('{orig_hex}'))" if orig_hex else "Raw()"
