import binascii
import copy
from scapy.layers.dhcp import DHCP
from utils import safe_repr

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
    pkt = DHCP(raw)
    val = {}

    def serialize_options(options):
        serialized = []
        for opt in options:
            if isinstance(opt, tuple) and len(opt) == 2:
                # Handle ('key', 'value') tuples
                key, value = opt
                if isinstance(value, bytes):
                    serialized.append((key, value.hex()))
                else:
                    serialized.append((key, value))
            else:
                serialized.append(opt)
        return serialized

    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        if f.name == "options":
            val[f.name] = serialize_options(v)
        else:
            val[f.name] = v.hex() if isinstance(v, bytes) else v
    
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    raw_payload = _find_and_remove_raw(val_copy)
    
    try:
        if 'options' in val_copy:
            opts = val_copy['options']
            new_opts = []
            for opt in opts:
                if isinstance(opt, (list, tuple)) and len(opt) == 2:
                    k, v = opt
                    # Scapy options: some are int, some str, some bytes.
                    # decode() converted bytes->hexstr, int->int, str->str.
                    # If we have a hex string that SHOULD be bytes, we try unhex.
                    if isinstance(v, str):
                        try:
                            # Try unhex if it looks like hex and has even length
                            if len(v) > 0 and len(v) % 2 == 0:
                                # strict check: only if all chars are hex
                                if all(c in "0123456789abcdefABCDEF" for c in v):
                                     v_bin = binascii.unhexlify(v)
                                     # Heuristic: if it decodes to printable ascii, keep as str?
                                     # No, scapy handles bytes fine.
                                     v = v_bin
                        except: pass
                    new_opts.append((k, v))
                elif isinstance(opt, list):
                    new_opts.append(tuple(opt))
                else:
                    new_opts.append(opt)
            val_copy['options'] = new_opts

        pkt = DHCP(**val_copy)
        if raw_payload:
            pkt.add_payload(raw_payload)
        res_hex = binascii.hexlify(bytes(pkt)).decode()
        if orig_hex and not is_edited and len(res_hex) == len(orig_hex):
            return orig_hex
        return res_hex
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    # Use proper DHCP reconstruction for field editing
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', '_orig_hex', '_edited']: continue
        if k == 'options':
            # Scapy DHCP options MUST be tuples, but JSON gives us lists.
            if isinstance(v, list):
                v_fixed = []
                for opt in v:
                    if isinstance(opt, list) and len(opt) == 2:
                        v_fixed.append(tuple(opt))
                    else:
                        v_fixed.append(opt)
                fields.append(f"{k}={safe_repr(v_fixed)}")
            else:
                fields.append(f"{k}={safe_repr(v)}")
        elif k == 'flags':
            fields.append(f"{k}={safe_repr(str(v))}")
        else:
            fields.append(f"{k}={safe_repr(v)}")

    ctor = f"DHCP({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor