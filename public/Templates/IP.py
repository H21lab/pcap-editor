import binascii
import copy
from scapy.layers.inet import IP, IPOption
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
            if k in struct:
                if isinstance(struct[k], str):
                    try:
                        val = binascii.unhexlify(struct[k])
                        del struct[k]
                        return val
                    except: pass
                elif isinstance(struct[k], (bytes, bytearray)):
                    val = struct[k]
                    del struct[k]
                    return val
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data, **kwargs):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    try:
        pkt = IP(raw)
    except Exception as e:
        return {'_decode_error': str(e), 'load': hex_data}
        
    val = {}
    try:
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            if f.name == 'options':
                # Convert IP options to hex strings of their binary representation
                opts = []
                if isinstance(v, list):
                    for opt in v:
                        opts.append(binascii.hexlify(bytes(opt)).decode())
                val[f.name] = opts
            else:
                val[f.name] = v.hex() if isinstance(v, bytes) else v
        
        if pkt.payload:
            val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()
    except Exception as e:
        # If dissection fails, at least return raw
        val['load'] = hex_data
        
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited:
        return orig_hex

    raw_payload = _find_and_remove_raw(val_copy)
    val_copy.pop('len', None)
    val_copy.pop('chksum', None)
    
    # Filter kwargs to only valid fields to avoid AttributeError
    valid_fields = set([f.name for f in IP().fields_desc])
    val_copy = {k: v for k, v in val_copy.items() if k in valid_fields}
    
    # Reconstruct options
    if 'options' in val_copy:
        opts = []
        for o in val_copy['options']:
            if isinstance(o, str):
                try: opts.append(IPOption(binascii.unhexlify(o)))
                except: pass
        val_copy['options'] = opts

    try:
        pkt = IP(**val_copy)
        if raw_payload:
            pkt.add_payload(raw_payload)
        res_hex = binascii.hexlify(bytes(pkt)).decode()
        return res_hex
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', 'len', 'chksum', '_orig_hex', '_edited']: continue
        if k == 'options':
            # Reconstruct options code: [IPOption(unhexlify('...')), ...]
            opt_list = []
            for o in v:
                opt_list.append(f"IPOption(unhexlify('{o}'))")
            fields.append(f"options=[{', '.join(opt_list)}]")
        elif k == 'flags':
            fields.append(f"flags={safe_repr(str(v))}")
        elif isinstance(v, str):
            fields.append(f"{k}={safe_repr(v)}")
        else:
            fields.append(f"{k}={safe_repr(v)}")
    
    ctor = f"IP({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor