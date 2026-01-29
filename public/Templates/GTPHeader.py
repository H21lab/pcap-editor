"""
GTPHeader Template - Handles TShark's GTPHeader layer naming.
Uses Raw() fallback to avoid Scapy GTPv1/GTPv2 field mapping issues.
"""
import binascii
import copy


def decode(hex_data, length=None):
    """Decode GTPHeader - returns raw data to avoid version confusion."""
    if length and len(hex_data) > length * 2:
        hex_data = hex_data[:length * 2]
    return {'raw': hex_data, '_orig_hex': hex_data}


def encode(val):
    """Encode GTPHeader - pass through raw bytes."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    if orig_hex and not is_edited:
        return orig_hex
    return orig_hex if orig_hex else ""


def source_code(val, payload_var=None):
    """Generate source code using Raw() for reliable reconstruction."""
    orig_hex = val.get('_orig_hex') or val.get('raw', '')
    if orig_hex:
        code = f"Raw(load=unhexlify('{orig_hex}'))"
        return f"{code} / {payload_var}" if payload_var else code
    return "Raw()"
