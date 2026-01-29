"""
GTP Protocol Template - Uses Pycrate as primary (telecom protocol).
Supports GTPv1-C, GTPv1-U, and GTPv2-C.
Scapy available as fallback for source_code generation.
"""
import binascii
import copy

# Pycrate as primary for GTP (telecom protocol)
try:
    from pycrate_mobile.TS29060_GTP import parse_GTP
    from pycrate_mobile.TS29274_GTPC import parse_GTPC
    from pycrate_mobile.TS29281_GTPU import parse_GTPU
    HAS_PYCRATE = True
except ImportError:
    HAS_PYCRATE = False

# Scapy as fallback
try:
    from scapy.contrib.gtp import GTPHeader, GTP_U_Header
    from scapy.contrib.gtp_v2 import GTPHeader as GTPv2Header
    HAS_SCAPY_GTP = True
except ImportError:
    HAS_SCAPY_GTP = False


def decode(hex_data, length=None):
    """Decode GTP packet - uses Pycrate as primary (telecom protocol)."""
    if length and len(hex_data) > length * 2:
        hex_data = hex_data[:length * 2]

    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {}

    version = (raw[0] >> 5) & 0x7

    # Use Pycrate as primary for GTP (telecom protocol)
    if HAS_PYCRATE:
        try:
            msg = None
            if version == 1:
                msg, err = parse_GTP(raw)
                if not msg or err:
                    msg, err = parse_GTPU(raw)
            elif version == 2:
                msg, err = parse_GTPC(raw)

            if msg:
                val = msg.get_val()
                if isinstance(val, dict):
                    val['_orig_hex'] = hex_data
                else:
                    val = {'val': val, '_orig_hex': hex_data}
                val['_pycrate'] = True  # Mark as pycrate-decoded
                val['_version'] = version
                return val
        except Exception:
            pass

    # Fallback to Scapy if Pycrate fails
    if HAS_SCAPY_GTP:
        try:
            if version == 1:
                msg_type = raw[1] if len(raw) > 1 else 0
                if msg_type == 0xff:  # G-PDU (user data)
                    pkt = GTP_U_Header(raw)
                else:
                    pkt = GTPHeader(raw)
            elif version == 2:
                pkt = GTPv2Header(raw)
            else:
                return {'raw': hex_data, '_orig_hex': hex_data}

            val = {}
            for f in pkt.fields_desc:
                v = pkt.getfieldval(f.name)
                if isinstance(v, bytes):
                    val[f.name] = v.hex()
                elif isinstance(v, list):
                    val[f.name] = _serialize_ie_list(v)
                else:
                    val[f.name] = v

            if pkt.payload and bytes(pkt.payload):
                val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()

            val['_orig_hex'] = hex_data
            val['_version'] = version
            return val
        except Exception:
            pass

    return {'raw': hex_data, '_orig_hex': hex_data}


def encode(val):
    """Encode GTP packet - uses Pycrate as primary (telecom protocol)."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    if orig_hex and not is_edited:
        return orig_hex

    version = val_copy.pop('_version', 1)
    was_pycrate = val_copy.pop('_pycrate', False)
    payload = _extract_payload(val_copy)

    # Use Pycrate as primary for GTP (telecom protocol)
    if HAS_PYCRATE and was_pycrate:
        try:
            from pycrate_mobile.TS29060_GTP import GTPDispatcherSGSN, GTPDispatcherGGSN
            from pycrate_mobile.TS29274_GTPC import GTPCDispatcher

            inner_val = val_copy.get('val', val_copy)
            if isinstance(inner_val, dict):
                typ = inner_val.get('msg_type', inner_val.get('Type'))
                if version == 1:
                    if typ in GTPDispatcherSGSN:
                        msg = GTPDispatcherSGSN[typ]()
                    elif typ in GTPDispatcherGGSN:
                        msg = GTPDispatcherGGSN[typ]()
                    else:
                        return orig_hex if orig_hex else ""
                elif version == 2:
                    if typ in GTPCDispatcher:
                        msg = GTPCDispatcher[typ]()
                    else:
                        return orig_hex if orig_hex else ""
                else:
                    return orig_hex if orig_hex else ""

                msg.set_val(inner_val)
                res = msg.to_bytes()
                if payload:
                    res += payload
                return binascii.hexlify(res).decode()
        except Exception:
            pass

    return orig_hex if orig_hex else ""


def source_code(val, payload_var=None):
    """Generate source code for GTP reconstruction.

    GTP has complex version detection (v1 vs v2) with different Scapy classes
    and field names. TShark may report different layer names than what Scapy
    expects. To avoid field mapping issues, always use Raw() for reliable
    reconstruction. Editing GTP fields should be done through the decode/encode
    cycle rather than direct Scapy construction.
    """
    orig_hex = val.get('_orig_hex') or val.get('raw', '')
    if orig_hex:
        code = f"Raw(load=unhexlify('{orig_hex}'))"
        return f"{code} / {payload_var}" if payload_var else code
    return "Raw()"


def _serialize_ie_list(ie_list):
    """Serialize a list of IEs to JSON-compatible format."""
    result = []
    for ie in ie_list:
        if hasattr(ie, 'fields_desc'):
            ie_dict = {}
            for f in ie.fields_desc:
                v = ie.getfieldval(f.name)
                if isinstance(v, bytes):
                    ie_dict[f.name] = v.hex()
                else:
                    ie_dict[f.name] = v
            result.append(ie_dict)
        elif isinstance(ie, bytes):
            result.append(ie.hex())
        else:
            result.append(ie)
    return result


def _extract_payload(val_copy):
    """Extract and remove payload from val_copy."""
    for key in ('load', 'data', 'payload'):
        if key in val_copy:
            p = val_copy.pop(key)
            if isinstance(p, str):
                return binascii.unhexlify(p)
            elif isinstance(p, bytes):
                return p
    return None


def safe_repr(obj):
    """Safe repr for source code generation."""
    if isinstance(obj, bytes):
        return f"unhexlify('{binascii.hexlify(obj).decode()}')"
    if isinstance(obj, list):
        return "[" + ", ".join(safe_repr(x) for x in obj) + "]"
    if isinstance(obj, dict):
        items = [f"{repr(k)}: {safe_repr(v)}" for k, v in obj.items()]
        return "{" + ", ".join(items) + "}"
    return repr(obj)
