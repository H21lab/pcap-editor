import binascii
import copy
# CAP (CAMEL Application Part) is typically carried over TCAP.
# Pycrate might not have a dedicated CAP module exposed simply like MAP.
# We will treat it as a generic TCAP message for now, or assume it uses TCAP template.
# If we want a specific CAP template, we need to know the Pycrate module.
# Since we didn't find it in the list, we'll create a placeholder that delegates 
# or just wraps Raw if identified as CAP specifically.
# However, usually Wireshark identifies it as 'tcap' or 'camel'.
# If 'camel', we need this template.

def decode(hex_data):
    # Fallback to TCAP-like decoding or just Raw
    # If the engine detects 'camel', it calls this.
    return {'raw': hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    return ""
