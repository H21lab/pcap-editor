"""
LTE NAS (Non-Access Stratum) template using pycrate.
Handles EMM (EPS Mobility Management) and ESM (EPS Session Management) messages.
Used in 4G/LTE networks.
"""
import binascii
import copy
from utils import safe_repr

try:
    from pycrate_mobile.NASLTE import EMMSecProtNASMessage, EMMTypeMOClasses, EMMTypeMTClasses
    HAS_PYCRATE = True
except ImportError:
    HAS_PYCRATE = False

def decode(hex_data, **kwargs):
    """Decode LTE NAS message using pycrate."""
    if not HAS_PYCRATE:
        return {'raw': hex_data, '_orig_hex': hex_data}

    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        # Try to parse as EMM Security Protected NAS Message
        msg = EMMSecProtNASMessage()
        msg.from_bytes(raw)
        val = msg.get_val()

        result = {'val': val, '_orig_hex': hex_data, '_msg_type': 'EMMSecProtNASMessage'}
        return result
    except Exception as e:
        # Try plain EMM message classes
        for cls_dict in [EMMTypeMOClasses, EMMTypeMTClasses]:
            for msg_type, cls in cls_dict.items():
                try:
                    msg = cls()
                    msg.from_bytes(raw)
                    val = msg.get_val()
                    return {'val': val, '_orig_hex': hex_data, '_msg_type': cls.__name__}
                except:
                    continue
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode LTE NAS message using pycrate."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    orig_bytes = val_copy.pop('_orig_bytes', None)
    is_edited = val_copy.pop('_edited', False)
    msg_type = val_copy.pop('_msg_type', 'EMMSecProtNASMessage')

    if not HAS_PYCRATE:
        return orig_hex if orig_hex else ""

    try:
        inner_val = val_copy.get('val', val_copy)

        # Use EMMSecProtNASMessage as default
        msg = EMMSecProtNASMessage()
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
