"""TFTP_OACK template using proper Scapy encoding."""
import binascii
import copy
from scapy.layers.tftp import TFTP, TFTP_OACK
from scapy.all import Raw
from utils import safe_repr

def decode(hex_data, **kwargs):
    raw = binascii.unhexlify(hex_data)
    if not raw or len(raw) < 2:
        return {'raw': hex_data, '_orig_hex': hex_data, '_orig_bytes': hex_data}

    try:
        # Use TFTP to parse full packet with opcode
        pkt = TFTP(raw)
        val = {'op': 6}  # OACK opcode

        # Get the OACK layer if present
        if pkt.haslayer(TFTP_OACK):
            oack = pkt[TFTP_OACK]
            for f in oack.fields_desc:
                v = oack.getfieldval(f.name)
                if isinstance(v, bytes):
                    val[f.name] = v.decode('utf-8', errors='replace').rstrip('\x00')
                elif isinstance(v, list):
                    # Options list
                    val[f.name] = []
                    for item in v:
                        if hasattr(item, 'fields_desc'):
                            opt = {}
                            for of in item.fields_desc:
                                ov = item.getfieldval(of.name)
                                if isinstance(ov, bytes):
                                    opt[of.name] = ov.decode('utf-8', errors='replace').rstrip('\x00')
                                else:
                                    opt[of.name] = ov
                            val[f.name].append(opt)
                        else:
                            val[f.name].append(str(item))
                else:
                    val[f.name] = v

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
        val_copy.pop('load', None)
        val_copy.pop('op', None)

        pkt = TFTP(op=6) / TFTP_OACK()
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
