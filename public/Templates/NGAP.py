import binascii
import copy
from utils import safe_repr

def _find_and_remove_raw(struct):
    if isinstance(struct, list):
        for i, item in enumerate(struct):
            res = _find_and_remove_raw(item)
            if res is not None: return res
    if isinstance(struct, dict):
        for k, v in list(struct.items()):
            if isinstance(v, dict) and 'raw' in v:
                val = binascii.unhexlify(v['raw']); del struct[k]; return val
        for k in ['load', 'data', 'payload', 'value']:
            if k in struct:
                if isinstance(struct[k], str):
                    try: val = binascii.unhexlify(struct[k]); del struct[k]; return val
                    except: pass
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    try:
        from pycrate_asn1dir import NGAP
    except:
        return {'raw': hex_data, '_orig_hex': hex_data}
    raw = binascii.unhexlify(hex_data)
    try:
        msg = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        # Reset singleton state before decoding
        if hasattr(msg, '_val'):
            msg._val = None
        msg.from_aper(raw)
        res = msg.get_val()
        return {
            'val': res,
            '_orig_hex': hex_data,
            '_pycrate': True
        }
    except Exception as e:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    try:
        from pycrate_asn1dir import NGAP
    except:
        if isinstance(val, dict) and 'raw' in val: return val['raw']
        return val.get('_orig_hex', '') if isinstance(val, dict) else ""

    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    val_copy.pop('_pycrate', None)

    # If not edited, return original bytes
    if orig_hex and not is_edited:
        return orig_hex

    raw_payload = _find_and_remove_raw(val_copy)
    if isinstance(val_copy, dict) and 'val' in val_copy:
        val_copy = val_copy['val']
    try:
        msg = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
        if hasattr(msg, '_val'):
            msg._val = None
        msg.set_val(val_copy)
        return binascii.hexlify(msg.to_aper()).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    # If decode failed (no 'val' key), use Raw fallback
    if 'val' not in val and ('raw' in val or '_orig_hex' in val):
        load_val = val.get('raw', val.get('_orig_hex'))
        code = f"Raw(load=unhexlify('{load_val}'))"
        return f"{code} / {payload_var}" if payload_var else code

    # Generate Pycrate-based reconstruction code
    val_repr = safe_repr(val)
    payload_inject = ""
    if payload_var:
        payload_inject = f"""
     # Inject payload into NAS-PDU IE (id=38)
     (lambda: [
         (lambda ies: [
             (ie.__setitem__('value', ('NAS-PDU', bytes({payload_var}))) if ie.get('id') == 38 else None)
             for ie in ies
         ])(v_to_set[1]['value'][1]['protocolIEs']) if isinstance(v_to_set, (list, tuple)) and len(v_to_set) > 1 and 'value' in v_to_set[1] else None
     ])(),"""

    return f"""(lambda val_in={val_repr}: (
    [NGAP := __import__('pycrate_asn1dir.NGAP', fromlist=['NGAP']),
     PDU := NGAP.NGAP_PDU_Descriptions.NGAP_PDU,
     (setattr(PDU, '_val', None) if hasattr(PDU, '_val') else None),
     v_to_set := val_in.get('val', val_in),
     (v_to_set.pop('_orig_hex', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('_edited', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('_pycrate', None) if isinstance(v_to_set, dict) else None),
     (v_to_set.pop('raw', None) if isinstance(v_to_set, dict) else None),{payload_inject}
     PDU.set_val(v_to_set),
     PDU.to_aper()][-1]
))()"""
