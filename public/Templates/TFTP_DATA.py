"""TFTP_DATA template using proper Scapy encoding."""
import binascii
import copy
from scapy.layers.tftp import TFTP, TFTP_DATA
from scapy.all import Raw
from utils import safe_repr

def decode(hex_data, **kwargs):
    raw = binascii.unhexlify(hex_data)
    if not raw or len(raw) < 4:
        return {'raw': hex_data, '_orig_hex': hex_data, '_orig_bytes': hex_data}

    try:
        # Use TFTP to parse full packet with opcode
        pkt = TFTP(raw)
        val = {'op': 3}  # DATA opcode

        # Get the DATA layer if present
        if pkt.haslayer(TFTP_DATA):
            data_pkt = pkt[TFTP_DATA]
            for f in data_pkt.fields_desc:
                v = data_pkt.getfieldval(f.name)
                if isinstance(v, bytes):
                    val[f.name] = v.hex()
                else:
                    val[f.name] = v

            # Handle data payload
            if data_pkt.payload and hasattr(data_pkt.payload, 'load'):
                val['data'] = binascii.hexlify(data_pkt.payload.load).decode()

        val['_orig_hex'] = hex_data
        val['_orig_bytes'] = hex_data
        return val
    except:
        return {'raw': hex_data, '_orig_hex': hex_data, '_orig_bytes': hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    orig_bytes = val_copy.pop('_orig_bytes', None)
    is_edited = val_copy.pop('_edited', False)

    try:
        data = val_copy.pop('data', None)
        val_copy.pop('op', None)
        block = val_copy.get('block', 0)

        pkt = TFTP(op=3) / TFTP_DATA(block=block)
        if data:
            pkt = pkt / Raw(load=binascii.unhexlify(data))

        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', '_orig_hex', '_orig_bytes', '_edited']:
            continue
        fields.append(f"{k}={safe_repr(v)}")

    ctor = f"TFTP({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
