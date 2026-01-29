import binascii
import copy
from utils import decode_raw, encode_raw, source_code_raw

# PPPoED_Tags is a complex list structure that's better handled as raw bytes
def decode(hex_data):
    return decode_raw(hex_data)

def encode(val):
    return encode_raw(val)

def source_code(val, payload_var):
    return source_code_raw(val, payload_var)
