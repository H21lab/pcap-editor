from utils import decode_raw, encode_raw, source_code_raw

# SMB is complex (NetBIOS + SMB layers). Scapy support varies.
# We fallback to raw for safety.

def decode(hex_data):
    return decode_raw(hex_data)

def encode(val):
    return encode_raw(val)

def source_code(val, payload_var=None):
    return source_code_raw(val, payload_var)
