"""LDAP template - uses raw passthrough since Scapy's LDAP encoder
has string/bytes encoding issues with ASN.1 fields."""
import binascii

def decode(hex_data):
    """Decodes LDAP as raw bytes."""
    return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encodes LDAP layer."""
    return val.get('_orig_hex', val.get('raw', ''))

def source_code(val, payload_var=None):
    """Generates Python code for LDAP reconstruction."""
    hex_str = val.get('_orig_hex', val.get('raw', ''))
    code = f"Raw(load=unhexlify('{hex_str}'))"
    if payload_var:
        code += f" / {payload_var}"
    return code
