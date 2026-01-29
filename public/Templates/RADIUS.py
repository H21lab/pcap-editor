import binascii
import copy
from scapy.layers.radius import Radius, RadiusAttribute
from scapy.all import Raw
from utils import safe_repr

def _serialize_attribute(attr):
    """Serialize a RADIUS attribute."""
    result = {}
    if hasattr(attr, 'type'):
        result['type'] = attr.type
    if hasattr(attr, 'len'):
        result['len'] = attr.len
    if hasattr(attr, 'value'):
        v = attr.value
        if isinstance(v, bytes):
            # Try to decode as string for text attributes
            try:
                result['value'] = v.decode('utf-8')
            except:
                result['value'] = v.hex()
        else:
            result['value'] = v
    return result

def decode(hex_data, **kwargs):
    """Decode RADIUS packet preserving attribute structure."""
    raw = binascii.unhexlify(hex_data)
    if not raw or len(raw) < 20:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        pkt = Radius(raw)
        val = {}

        # Basic fields
        val['code'] = pkt.code
        val['id'] = pkt.id
        val['len'] = pkt.len

        # Authenticator (16 bytes)
        if pkt.authenticator:
            val['authenticator'] = pkt.authenticator.hex() if isinstance(pkt.authenticator, bytes) else pkt.authenticator

        # Attributes
        if hasattr(pkt, 'attributes') and pkt.attributes:
            attrs = []
            for attr in pkt.attributes:
                attrs.append(_serialize_attribute(attr))
            val['attributes'] = attrs

        val['_orig_hex'] = hex_data
        val['_orig_bytes'] = hex_data
        return val
    except Exception as e:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode RADIUS packet from val dict."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    try:
        # Build RADIUS packet
        code = val_copy.get('code', 1)
        id_ = val_copy.get('id', 0)
        authenticator = val_copy.get('authenticator', '00' * 16)

        if isinstance(authenticator, str):
            authenticator = binascii.unhexlify(authenticator)

        pkt = Radius(code=code, id=id_, authenticator=authenticator)

        # Add attributes
        attrs = val_copy.get('attributes', [])
        for attr_dict in attrs:
            attr_type = attr_dict.get('type', 0)
            attr_value = attr_dict.get('value', '')

            if isinstance(attr_value, str):
                # Try to convert hex strings to bytes
                if all(c in '0123456789abcdefABCDEF' for c in attr_value) and len(attr_value) % 2 == 0:
                    attr_value = binascii.unhexlify(attr_value)
                else:
                    attr_value = attr_value.encode()

            pkt = pkt / RadiusAttribute(type=attr_type, value=attr_value)

        return binascii.hexlify(bytes(pkt)).decode()
    except Exception as e:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', '_orig_hex', '_orig_bytes', '_edited']:
            continue
        fields.append(f"{k}={safe_repr(v)}")

    ctor = f"Radius({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor
