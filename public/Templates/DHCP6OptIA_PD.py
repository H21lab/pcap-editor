import binascii
from scapy.layers.dhcp6 import DHCP6OptIA_PD

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    pkt = DHCP6OptIA_PD(raw)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        val[f.name] = v.hex() if isinstance(v, bytes) else v
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    payload = val.pop('load', None)
    if isinstance(payload, dict) and 'raw' in payload:
        payload = binascii.unhexlify(payload['raw'])
    try:
        pkt = DHCP6OptIA_PD(**val)
        if payload: pkt.add_payload(payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return ""
