"""
NetBIOS Session Service template.
Used for SMB over NetBIOS.
"""
import binascii
import copy
from scapy.all import Raw
from utils import safe_repr

try:
    from scapy.layers.netbios import NBTSession
    HAS_NBT = True
except ImportError:
    HAS_NBT = False

def decode(hex_data, **kwargs):
    """Decode NetBIOS Session packet."""
    if not HAS_NBT:
        return {'raw': hex_data, '_orig_hex': hex_data}

    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        pkt = NBTSession(raw)
        val = {}

        for f in pkt.fields_desc:
            try:
                v = pkt.getfieldval(f.name)
                if isinstance(v, bytes):
                    val[f.name] = v.hex()
                else:
                    val[f.name] = v
            except:
                pass

        # Handle payload
        if pkt.payload and hasattr(pkt.payload, 'load'):
            val['load'] = binascii.hexlify(pkt.payload.load).decode()
        elif len(bytes(pkt)) < len(raw):
            val['load'] = binascii.hexlify(raw[len(bytes(pkt)):]).decode()

        val['_orig_hex'] = hex_data
        val['_orig_bytes'] = hex_data
        return val
    except Exception as e:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode NetBIOS Session packet."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    if not HAS_NBT:
        return orig_hex if orig_hex else ""

    try:
        load = val_copy.pop('load', None)
        val_copy.pop('LENGTH', None)  # Let Scapy recalculate

        pkt = NBTSession(**val_copy)

        if load:
            pkt = pkt / Raw(load=binascii.unhexlify(load))

        return binascii.hexlify(bytes(pkt)).decode()
    except Exception as e:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', 'LENGTH', '_orig_hex', '_orig_bytes', '_edited']:
            continue
        fields.append(f"{k}={safe_repr(v)}")

    ctor = f"NBTSession({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
