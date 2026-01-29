import binascii
import copy
from utils import safe_repr

# CAMEL/CAP is handled by TCAP template using TCAP_CAP.GenericSSF_gsmSCF_PDUs
# This template handles the case where CAMEL is detected as a separate layer
# but the actual decoding happens in TCAP

def decode(hex_data):
    # CAMEL/CAP inner content cannot be decoded standalone (parameterized types)
    # The full TCAP-CAP message is decoded by TCAP template
    # Just preserve the raw data
    return {
        'raw': hex_data,
        '_orig_hex': hex_data
    }


def encode(val):
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    if orig_hex and not is_edited:
        return orig_hex

    return orig_hex if orig_hex else ""


def source_code(val, payload_var=None):
    # Just return raw bytes - CAMEL encoding is handled by parent TCAP layer
    raw_hex = val.get('raw') or val.get('_orig_hex', '')

    if payload_var:
        return f"bytes({payload_var})"

    return f"unhexlify('{raw_hex}')"
