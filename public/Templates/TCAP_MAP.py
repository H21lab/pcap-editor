import binascii
import copy
from utils import safe_repr

def _find_and_remove_raw(struct):
    if isinstance(struct, list):
        for i, item in enumerate(struct):
            res = _find_and_remove_raw(item)
            if res is not None: return res
    if isinstance(struct, dict):
        # 1. Check for {'raw': ...}
        for k, v in list(struct.items()):
            if isinstance(v, dict) and 'raw' in v:
                val = binascii.unhexlify(v['raw'])
                del struct[k]
                return val
        # 2. Check for load/data/payload as hex strings
        for k in ['load', 'data', 'payload', 'components']:
            if k in struct and isinstance(struct[k], str):
                try:
                    val = binascii.unhexlify(struct[k])
                    del struct[k]
                    return val
                except: pass
        # 3. Recurse
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    if isinstance(struct, tuple):
        for item in struct:
            res = _find_and_remove_raw(item)
            if res is not None: return res
    return None

def _get_comp_type(val_hint=None):
    try:
        from pycrate_asn1dir import TCAP_MAPv2v3
        mod = TCAP_MAPv2v3.TCAP_MAP_Messages
        if isinstance(val_hint, tuple) and val_hint[0] == 'begin':
             return getattr(mod, '_TCAP_MAP_Messages___TCAP_MAP_Message_begin_components__item_', None)
        return getattr(mod, '_TCAP_MAP_Messages___TCAP_MAP_Message_begin_components__item_', None)
    except:
        return None

def _fix_imsi(v):
    if isinstance(v, dict):
        if 'imsi' in v and isinstance(v['imsi'], str):
            # TBCD Encode IMSI if it is a string
            imsi = v['imsi']
            if len(imsi) % 2 != 0: imsi += 'f'
            v['imsi'] = binascii.unhexlify(''.join([imsi[i+1]+imsi[i] for i in range(0, len(imsi), 2)]))
        for key in v: _fix_imsi(v[key])
    if isinstance(v, (list, tuple)):
        for item in v: _fix_imsi(item)

def decode(hex_data):
    try:
        comp_type = _get_comp_type()
        if not comp_type: return {'raw': hex_data}
    except:
        return {'raw': hex_data}
    
    raw = binascii.unhexlify(hex_data)
    try:
        comp_type.reset_val()
        comp_type.from_ber(raw)
        res = comp_type.get_val()
        if isinstance(res, dict): res['_orig_hex'] = hex_data
        elif isinstance(res, tuple): res = {'val': res, '_orig_hex': hex_data}
        return res
    except:
        try:
            from pycrate_asn1dir import TCAP_MAPv2v3
            pdu = TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message
            pdu.reset_val()
            pdu.from_ber(raw)
            return {'val': pdu.get_val(), '_orig_hex': hex_data}
        except:
            return {'raw': hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    struct_val = val_copy.get('val', val_copy)
    _fix_imsi(struct_val)
    raw_payload = _find_and_remove_raw(struct_val)

    try:
        from pycrate_asn1dir import TCAP_MAPv2v3
        mod = TCAP_MAPv2v3.TCAP_MAP_Messages

        if isinstance(struct_val, tuple) and struct_val[0] in ['begin', 'continue', 'end', 'abort']:
            pdu = mod.TCAP_MAP_Message
            pdu.reset_val()
            pdu.set_val(struct_val)
            res_bytes = pdu.to_ber()
        else:
            comp_type = _get_comp_type(struct_val)
            comp_type.reset_val()
            comp_type.set_val(struct_val)
            res_bytes = comp_type.to_ber()

        if raw_payload:
            res_bytes += raw_payload
        res_hex = binascii.hexlify(res_bytes).decode()
        # Always return the re-encoded value - don't short-circuit based on length
        # because user edits may not change length (e.g., IMSI 22... -> 33...)
        return res_hex
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    if payload_var:
        return payload_var

    val_repr = safe_repr(val)
    orig_hex = val.get('_orig_hex', '')
    
    helper = r"""
def encode_pycrate_comp(val_in, orig_hex):
    from binascii import unhexlify
    try:
        from pycrate_asn1dir import TCAP_MAPv2v3
        mod = TCAP_MAPv2v3.TCAP_MAP_Messages
        v_to_set = val_in.get('val', val_in)
        (v_to_set.pop('_orig_hex', None) if isinstance(v_to_set, dict) else None)
        (v_to_set.pop('_edited', None) if isinstance(v_to_set, dict) else None)
        (v_to_set.pop('raw', None) if isinstance(v_to_set, dict) else None)

        if isinstance(v_to_set, tuple) and v_to_set[0] in ['begin', 'continue', 'end', 'abort']:
            pdu = mod.TCAP_MAP_Message
            pdu.reset_val()
            pdu.set_val(v_to_set)
            return pdu.to_ber()
        else:
            comp_type = getattr(mod, '_TCAP_MAP_Messages___TCAP_MAP_Message_begin_components__item_', None)
            if comp_type:
                comp_type.reset_val()
                comp_type.set_val(v_to_set)
                return comp_type.to_ber()
    except Exception:
        pass
    return unhexlify(orig_hex) if orig_hex else b''

res_list[0] = encode_pycrate_comp(val_in, orig_hex)
"""
    helper_repr = safe_repr(helper)

    return f"""(lambda val_in={val_repr}: (
    [res_list := [None],
     exec({helper_repr}, {{'val_in': val_in, 'orig_hex': '{orig_hex}', 'res_list': res_list}}),
     res_list[0]][-1]
))()"""
