"""HTTP template - uses raw passthrough since HTTP is text-based
and Scapy's HTTP class doesn't accept Wireshark's decoded fields."""
import binascii

def decode(hex_data):
    """Decodes HTTP as raw bytes."""
    return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encodes HTTP layer."""
    return val.get('_orig_hex', val.get('raw', ''))

def source_code(val, payload_var=None):
    """Generates Python code for HTTP reconstruction."""
    hex_str = val.get('_orig_hex', val.get('raw', ''))
    code = f"Raw(load=unhexlify('{hex_str}'))"
    if payload_var:
        code += f" / {payload_var}"
    return code
