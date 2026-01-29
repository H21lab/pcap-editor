import binascii
import copy
from scapy.layers.ppp import PPP_LCP_Configure
from scapy.packet import Raw

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    pkt = PPP_LCP_Configure(raw)
    val = {}
    for f in pkt.fields_desc:
        v = pkt.getfieldval(f.name)
        if f.name == 'options':
            # Handle LCP options list
            opts = []
            if v:
                for opt in v:
                    opt_dict = {}
                    for of in opt.fields_desc:
                        ov = opt.getfieldval(of.name)
                        if isinstance(ov, bytes):
                            opt_dict[of.name] = ov.hex()
                        else:
                            opt_dict[of.name] = ov
                    opts.append(opt_dict)
            val[f.name] = opts
        elif isinstance(v, bytes):
            val[f.name] = v.hex()
        else:
            val[f.name] = v
    if pkt.payload:
        val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    if orig_hex and not is_edited: return orig_hex

    payload = val_copy.pop('load', None)
    if isinstance(payload, str): payload = binascii.unhexlify(payload)
    val_copy.pop('len', None)
    val_copy.pop('options', None)  # Options are complex, just use Raw for now
    try:
        pkt = PPP_LCP_Configure(**val_copy)
        if payload: pkt = pkt / Raw(payload)
        return binascii.hexlify(bytes(pkt)).decode()
    except: return orig_hex if orig_hex else ""

from utils import safe_repr

def source_code(val, payload_var):
    # LCP options are complex - use Raw fallback for source_code
    orig_hex = val.get('_orig_hex', '')
    if orig_hex:
        code = f"Raw(load=unhexlify('{orig_hex}'))"
        return f"{code} / {payload_var}" if payload_var else code

    # Fallback to basic fields (excluding options which are complex)
    fields = [f"{k}={safe_repr(v)}" for k, v in val.items()
              if k not in ['raw', 'load', '_orig_hex', '_edited', 'len', 'options']]
    ctor = f"PPP_LCP_Configure({', '.join(fields)})"
    return f"{ctor} / {payload_var}" if payload_var else ctor
