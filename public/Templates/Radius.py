import binascii
import copy
from utils import safe_repr
try:
    from scapy.layers.radius import Radius, RadiusAttribute
    HAS_LIB = True
except ImportError:
    HAS_LIB = False

def _find_and_remove_raw(struct):
    if isinstance(struct, list):
        for i, item in enumerate(struct):
            res = _find_and_remove_raw(item)
            if res is not None: return res
    if isinstance(struct, dict):
        for k, v in list(struct.items()):
            if isinstance(v, dict) and 'raw' in v:
                val = binascii.unhexlify(v['raw'])
                del struct[k]
                return val
        for k in ['load', 'data', 'payload']:
            if k in struct and isinstance(struct[k], str):
                try:
                    val = binascii.unhexlify(struct[k])
                    del struct[k]
                    return val
                except: pass
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    if not HAS_LIB: return {'raw': hex_data}
    try:
        pkt = Radius(raw)
        val = {}
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            if f.name == 'attributes':
                attrs = []
                for attr in v:
                    attrs.append({
                        'type': attr.type,
                        'value': attr.value.hex() if isinstance(attr.value, bytes) else str(attr.value)
                    })
                val[f.name] = attrs
            elif isinstance(v, bytes):
                val[f.name] = v.hex()
            else:
                val[f.name] = v
        if pkt.payload:
            val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()
        val['_orig_hex'] = hex_data
        return val
    except:
        return {'raw': hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    if orig_hex and not is_edited: return orig_hex

    if not HAS_LIB: return orig_hex if orig_hex else ""

    raw_payload = _find_and_remove_raw(val_copy)
    val_copy.pop('len', None)
    
    if 'attributes' in val_copy:
        attrs = []
        for attr in val_copy['attributes']:
            val_to_use = attr['value']
            try:
                # Try to unhexlify if it's a hex string
                if isinstance(val_to_use, str):
                    val_to_use = binascii.unhexlify(val_to_use)
            except: pass
            attrs.append(RadiusAttribute(type=attr['type'], value=val_to_use))
        val_copy['attributes'] = attrs

    try:
        pkt = Radius(**val_copy)
        if raw_payload:
            pkt.add_payload(raw_payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except:
        return ""

def source_code(val, payload_var):
    if not HAS_LIB: return f"Raw(load=unhexlify('{val.get('raw', '')}'))"
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', 'len', '_orig_hex', '_edited']: continue
        if k == 'attributes':
            attr_list = []
            for attr in v:
                v_str = safe_repr(attr['value'])
                if isinstance(attr['value'], str):
                    # Check if it looks like hex and was unhexlified in Scapy
                    try:
                        binascii.unhexlify(attr['value'])
                        v_str = f"unhexlify('{attr['value']}')"
                    except: pass
                attr_list.append(f"RadiusAttribute(type={attr['type']}, value={v_str})")
            fields.append(f"attributes=[{', '.join(attr_list)}]")
        elif k == 'authenticator' and isinstance(v, str):
            # authenticator is a bytes field stored as hex
            fields.append(f"{k}=unhexlify('{v}')")
        elif isinstance(v, str):
            fields.append(f"{k}={safe_repr(v)}")
        else:
            fields.append(f"{k}={safe_repr(v)}")

    ctor = f"Radius({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor