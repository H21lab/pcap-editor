import binascii
import copy
from utils import safe_repr

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)

    # Try different TCAP variants in order of specificity
    decoders = []

    try:
        from pycrate_asn1dir import TCAP_CAP
        # CAP/CAMEL decoder - for GSM SSF-SCF signaling (per pycrate wiki)
        decoders.append(('CAP', TCAP_CAP.CAP_gsmSSF_gsmSCF_pkgs_contracts_acs.GenericSSF_gsmSCF_PDUs))
    except:
        pass

    try:
        from pycrate_asn1dir import TCAP_MAPv2v3
        # MAP decoder - for GSM MAP messages (per pycrate wiki)
        decoders.append(('MAP', TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message))
    except:
        pass

    try:
        from pycrate_asn1dir import TCAP
        # Generic TCAP decoder
        decoders.append(('TCAP', TCAP.TCAPMessages.TCMessage))
    except:
        pass

    for name, pdu in decoders:
        try:
            pdu.reset_val()
            pdu.from_ber(raw)
            res = pdu.get_val()
            return {
                'val': res,
                'pdu_type': name,
                '_orig_hex': hex_data
            }
        except:
            continue

    return {'raw': hex_data}


def encode(val):
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    if orig_hex and not is_edited:
        return orig_hex

    pdu_type = val_copy.pop('pdu_type', 'MAP')
    struct_val = val_copy.get('val', val_copy)

    try:
        if pdu_type == 'CAP':
            from pycrate_asn1dir import TCAP_CAP
            PDU = TCAP_CAP.CAP_gsmSSF_gsmSCF_pkgs_contracts_acs.GenericSSF_gsmSCF_PDUs
        elif pdu_type == 'MAP':
            from pycrate_asn1dir import TCAP_MAPv2v3
            PDU = TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message
        else:
            from pycrate_asn1dir import TCAP
            PDU = TCAP.TCAPMessages.TCMessage

        PDU.reset_val()
        PDU.set_val(struct_val)
        return binascii.hexlify(PDU.to_ber()).decode()
    except:
        return orig_hex if orig_hex else ""


def source_code(val, payload_var=None):
    val_repr = safe_repr(val)
    orig_hex = val.get('_orig_hex', '')
    pdu_type = val.get('pdu_type', 'MAP')

    # Select the correct PDU class based on pdu_type
    if pdu_type == 'CAP':
        pdu_import = "from pycrate_asn1dir import TCAP_CAP; PDU = TCAP_CAP.CAP_gsmSSF_gsmSCF_pkgs_contracts_acs.GenericSSF_gsmSCF_PDUs"
    elif pdu_type == 'MAP':
        pdu_import = "from pycrate_asn1dir import TCAP_MAPv2v3; PDU = TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message"
    else:
        pdu_import = "from pycrate_asn1dir import TCAP; PDU = TCAP.TCAPMessages.TCMessage"

    # If we have a payload (TCAP_MAP component), we need to encode with that component
    # TCAP_MAP outputs a full component (a12a...), TCAP needs to include it in the encoded output
    if payload_var:
        # Encode TCAP normally, then splice in the TCAP_MAP component bytes
        payload_inject = f"""
# TCAP_MAP outputs the component, we need to splice it into the TCAP BER output
# First encode TCAP normally, then find and replace the component bytes
tcap_ber = PDU.to_ber()
# The payload_obj contains the new component bytes
# We need to reconstruct the TCAP with the new component
# Find the components section (tag 0x6c = 108) and replace component content
import re
def splice_component(tcap_bytes, new_comp_bytes):
    # Find components tag (0x6c) in TCAP
    idx = tcap_bytes.find(b'\\x6c')
    if idx >= 0:
        # Parse length after 0x6c
        len_byte = tcap_bytes[idx+1]
        if len_byte < 128:
            comp_start = idx + 2
            comp_len = len_byte
        else:
            num_len_bytes = len_byte & 0x7f
            comp_len = int.from_bytes(tcap_bytes[idx+2:idx+2+num_len_bytes], 'big')
            comp_start = idx + 2 + num_len_bytes
        # Build new components section with new component
        new_comp_section = b'\\x6c' + (bytes([len(new_comp_bytes)]) if len(new_comp_bytes) < 128 else bytes([0x81, len(new_comp_bytes)])) + new_comp_bytes
        # Replace in TCAP
        return tcap_bytes[:idx] + new_comp_section
    return tcap_bytes

res[0] = splice_component(tcap_ber, payload_obj)
"""
        exec_globals = f'{{"val_in": val_in, "res": res, "payload_obj": bytes({payload_var})}}'
        # Don't use the normal PDU.to_ber() assignment
        return f"""(lambda val_in={val_repr}: (
    [res := [None],
     exec('''
{pdu_import}
v = val_in.get("val", val_in)
if isinstance(v, dict):
    v.pop("_orig_hex", None)
    v.pop("_edited", None)
    v.pop("raw", None)
    v.pop("pdu_type", None)
PDU.reset_val()
PDU.set_val(v)
{payload_inject}''', {exec_globals}),
     res[0]][-1]
))()"""
    # No payload - standard encoding
    return f"""(lambda val_in={val_repr}: (
    [res := [None],
     exec('''
{pdu_import}
v = val_in.get("val", val_in)
if isinstance(v, dict):
    v.pop("_orig_hex", None)
    v.pop("_edited", None)
    v.pop("raw", None)
    v.pop("pdu_type", None)
PDU.reset_val()
PDU.set_val(v)
res[0] = PDU.to_ber()
''', {{"val_in": val_in, "res": res}}),
     res[0]][-1]
))()"""
