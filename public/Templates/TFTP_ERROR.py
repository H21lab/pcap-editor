"""TFTP_ERROR template using proper Scapy encoding."""
import binascii
import copy
from scapy.layers.tftp import TFTP, TFTP_ERROR
from scapy.all import Raw
from utils import safe_repr

def decode(hex_data, **kwargs):
    raw = binascii.unhexlify(hex_data)
    if not raw or len(raw) < 4:
        return {'raw': hex_data, '_orig_hex': hex_data, '_orig_bytes': hex_data}

    try:
        # Use TFTP to parse full packet with opcode
        pkt = TFTP(raw)
        val = {'op': 5}  # ERROR opcode

        # Get the ERROR layer if present
        if pkt.haslayer(TFTP_ERROR):
            err = pkt[TFTP_ERROR]
            for f in err.fields_desc:
                v = err.getfieldval(f.name)
                if isinstance(v, bytes):
                    val[f.name] = v.decode('utf-8', errors='replace').rstrip('\x00')
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
        errorcode = val_copy.get('errorcode', 0)
        errormsg = val_copy.get('errormsg', '')

        if isinstance(errormsg, str):
            errormsg = errormsg.encode()

        pkt = TFTP(op=5) / TFTP_ERROR(errorcode=errorcode, errormsg=errormsg)
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
