import binascii
import copy
# Fallback template for LoRaWAN
# We wrap Raw

def decode(hex_data):
    return {'raw': hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    return ""
