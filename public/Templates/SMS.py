"""
SMS (Short Message Service) template using pycrate.
Handles SMS-DELIVER, SMS-SUBMIT, and other SMS PDU types.
"""
import binascii
import copy
from utils import safe_repr

try:
    from pycrate_mobile.TS23040_SMS import SMS_DELIVER, SMS_SUBMIT, SMS_STATUS_REPORT
    HAS_PYCRATE = True
except ImportError:
    HAS_PYCRATE = False

def decode(hex_data, **kwargs):
    """Decode SMS PDU using pycrate."""
    if not HAS_PYCRATE:
        return {'raw': hex_data, '_orig_hex': hex_data}

    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        # Try different SMS types
        for sms_cls in [SMS_DELIVER, SMS_SUBMIT, SMS_STATUS_REPORT]:
            try:
                msg = sms_cls()
                msg.from_bytes(raw)
                val = msg.get_val()
                return {
                    'val': val,
                    '_orig_hex': hex_data,
                    '_sms_type': sms_cls.__name__
                }
            except:
                continue

        return {'raw': hex_data, '_orig_hex': hex_data}
    except Exception as e:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode SMS PDU using pycrate."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    orig_bytes = val_copy.pop('_orig_bytes', None)
    is_edited = val_copy.pop('_edited', False)
    sms_type = val_copy.pop('_sms_type', 'SMS_DELIVER')

    if not HAS_PYCRATE:
        return orig_hex if orig_hex else ""

    try:
        inner_val = val_copy.get('val', val_copy)

        # Get the right SMS class
        sms_classes = {
            'SMS_DELIVER': SMS_DELIVER,
            'SMS_SUBMIT': SMS_SUBMIT,
            'SMS_STATUS_REPORT': SMS_STATUS_REPORT
        }
        sms_cls = sms_classes.get(sms_type, SMS_DELIVER)

        msg = sms_cls()
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
