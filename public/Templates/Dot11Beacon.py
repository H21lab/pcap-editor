"""
802.11 Beacon frame template.
Used for WiFi beacon frames.
"""
import binascii
import copy
from scapy.all import Raw
from utils import safe_repr

try:
    from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
    HAS_DOT11 = True
except ImportError:
    HAS_DOT11 = False

def _serialize_elt(elt):
    """Serialize Dot11Elt to dict."""
    result = {}
    if hasattr(elt, 'ID'):
        result['ID'] = elt.ID
    if hasattr(elt, 'len'):
        result['len'] = elt.len
    if hasattr(elt, 'info'):
        info = elt.info
        if isinstance(info, bytes):
            try:
                result['info'] = info.decode('utf-8', errors='replace')
            except:
                result['info'] = info.hex()
        else:
            result['info'] = info
    return result

def decode(hex_data, **kwargs):
    """Decode 802.11 Beacon frame."""
    if not HAS_DOT11:
        return {'raw': hex_data, '_orig_hex': hex_data}

    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        pkt = Dot11Beacon(raw)
        val = {}

        # Basic beacon fields
        for field in ['timestamp', 'beacon_interval', 'cap']:
            try:
                v = pkt.getfieldval(field)
                if isinstance(v, bytes):
                    val[field] = v.hex()
                else:
                    val[field] = v
            except:
                pass

        # Extract Information Elements
        elts = []
        layer = pkt.payload
        while layer:
            if hasattr(layer, 'ID'):
                elts.append(_serialize_elt(layer))
            if hasattr(layer, 'payload') and layer.payload:
                layer = layer.payload
            else:
                break
        if elts:
            val['elements'] = elts

        val['_orig_hex'] = hex_data
        val['_orig_bytes'] = hex_data
        return val
    except Exception as e:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode 802.11 Beacon frame."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    if not HAS_DOT11:
        return orig_hex if orig_hex else ""

    try:
        elts = val_copy.pop('elements', [])

        beacon_fields = {}
        for field in ['timestamp', 'beacon_interval', 'cap']:
            if field in val_copy:
                beacon_fields[field] = val_copy[field]

        pkt = Dot11Beacon(**beacon_fields)

        # Add Information Elements
        for elt_dict in elts:
            elt_id = elt_dict.get('ID', 0)
            info = elt_dict.get('info', '')
            if isinstance(info, str):
                # Try to encode as bytes
                try:
                    if all(c in '0123456789abcdefABCDEF' for c in info) and len(info) % 2 == 0:
                        info = binascii.unhexlify(info)
                    else:
                        info = info.encode()
                except:
                    info = info.encode()
            pkt = pkt / Dot11Elt(ID=elt_id, info=info)

        return binascii.hexlify(bytes(pkt)).decode()
    except Exception as e:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    # Dot11 beacon frames are complex - use raw fallback
    from utils import source_code_raw
    return source_code_raw(val, payload_var)
