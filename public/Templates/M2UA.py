import binascii
import copy
from utils import safe_repr

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    try:
        from pycrate_mobile.SIGTRAN import SIGTRAN
        pdu = SIGTRAN()
        pdu.from_bytes(raw)
        val = pdu.get_val()
        return {
            'val': val,
            '_orig_hex': hex_data
        }
    except:
        return {'raw': hex_data}


def encode(val):
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    if orig_hex and not is_edited:
        return orig_hex

    struct_val = val_copy.get('val', val_copy)

    try:
        from pycrate_mobile.SIGTRAN import SIGTRAN
        pdu = SIGTRAN()
        pdu.set_val(struct_val)
        return binascii.hexlify(pdu.to_bytes()).decode()
    except:
        return orig_hex if orig_hex else ""


def source_code(val, payload_var=None):
    val_repr = safe_repr(val)
    orig_hex = val.get('_orig_hex', '')

    # Build payload injection if needed
    if payload_var is not None:
        payload_inject = f"""
# Inject payload into Protocol Data parameter
params = v_to_set[1] if isinstance(v_to_set, list) and len(v_to_set) > 1 else []
for p in params:
    if isinstance(p, list) and len(p) >= 3 and p[0] == 768:  # Protocol Data tag
        p[2] = bytes(payload_bytes)
        break
"""
        exec_locals = f'{{"val_in": val_in, "res": res, "payload_bytes": {payload_var}}}'
    else:
        payload_inject = ""
        exec_locals = '{"val_in": val_in, "res": res}'

    return f"""(lambda val_in={val_repr}: (
    [res := [None],
     exec('''
from pycrate_mobile.SIGTRAN import SIGTRAN
v_to_set = val_in.get("val", val_in)
if isinstance(v_to_set, dict):
    v_to_set.pop("_orig_hex", None)
    v_to_set.pop("_edited", None)
    v_to_set.pop("raw", None)
{payload_inject}
pdu = SIGTRAN()
pdu.set_val(v_to_set)
res[0] = pdu.to_bytes()
''', {exec_locals}),
     res[0]][-1]
))()"""
