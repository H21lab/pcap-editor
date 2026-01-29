"""IEC 61850 MMS (Manufacturing Message Specification) template.

This protocol is used in industrial control systems and power grid automation.
No pure Python encoder/decoder available for WASM - uses raw passthrough.
"""

def decode(hex_data):
    """Decodes IEC 61850 MMS layer as raw bytes."""
    return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encodes IEC 61850 MMS layer."""
    return val.get('_orig_hex', val.get('raw', ''))

def source_code(val, payload_var=None):
    """Generates Python code for IEC 61850 MMS reconstruction."""
    hex_str = val.get('_orig_hex', val.get('raw', ''))
    code = f"Raw(load=unhexlify('{hex_str}'))"
    if payload_var:
        code += f" / {payload_var}"
    return code
