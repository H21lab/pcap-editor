import binascii
import copy
from utils import safe_repr, decode_raw, encode_raw, source_code_raw

def decode(hex_data):
    return decode_raw(hex_data)

def encode(val):
    return encode_raw(val)

def source_code(val, payload_var):
    # Treat TLS as a terminal raw layer to avoid duplication/corruption of data above TCP
    return source_code_raw(val, None)
