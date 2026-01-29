import binascii
import copy
from scapy.packet import Packet, Raw
from scapy.all import Ether # Import Ether to handle composition if needed
from utils import safe_repr

try:
    from scapy.contrib.cdp import CDPv2_HDR
    HAS_LIB = True
except ImportError:
    HAS_LIB = False

def decode(hex_data):
    if not hex_data: return {}
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}

    if not HAS_LIB:
        return {'_decode_error': 'CDPv2_HDR not found', 'raw_data': hex_data}

    try:
        pkt = CDPv2_HDR(raw)
    except Exception as e:
        return {'_decode_error': str(e), 'raw_data': hex_data}

    val = {}
    # Extract direct fields
    for f in pkt.fields_desc:
        if f.name == 'msg':
            # msg is a PacketListField, needs special handling
            msg_list = []
            for item in pkt.msg:
                # Recursively decode each item in msg list if it's a Packet
                # For simplicity, let's just store its hex representation for now
                if isinstance(item, Packet):
                    msg_list.append(binascii.hexlify(bytes(item)).decode())
                else:
                    # Fallback for non-Packet items, though unlikely for PacketListField
                    msg_list.append(str(item)) 
            val['msg'] = msg_list
        else:
            v = pkt.getfieldval(f.name)
            val[f.name] = binascii.hexlify(v).decode() if isinstance(v, bytes) else v
    
    # Handle any remaining raw payload
    if pkt.payload:
        val['raw_payload'] = binascii.hexlify(bytes(pkt.payload)).decode()
        
    val['_orig_hex'] = hex_data
    return val

def encode(val):
    if not HAS_LIB:
        # Fallback if CDPv2_HDR is not available, essentially treating it as raw
        return val.get('raw_data', '')

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited:
        return orig_hex
    
    # Extract fields for CDPv2_HDR constructor
    cdp_fields = {}
    for f_name in ['vers', 'ttl', 'cksum']:
        if f_name in val_copy:
            cdp_fields[f_name] = val_copy.pop(f_name)

    # Handle 'msg' field
    msg_list = val_copy.pop('msg', [])
    if msg_list:
        reconstructed_msg = []
        for item_hex in msg_list:
            try:
                reconstructed_msg.append(Raw(load=binascii.unhexlify(item_hex)))
            except:
                reconstructed_msg.append(item_hex) # Keep as string if not hex, likely an error
        cdp_fields['msg'] = reconstructed_msg

    # Handle raw payload
    raw_payload_hex = val_copy.pop('raw_payload', None)
    
    try:
        pkt = CDPv2_HDR(**cdp_fields)
        if raw_payload_hex:
            pkt = pkt / Raw(load=binascii.unhexlify(raw_payload_hex))
        return binascii.hexlify(bytes(pkt)).decode()
    except Exception as e:
        return f"error: CDPv2_HDR encode failed: {e}"

def source_code(val, payload_var):
    orig_hex = val.get('_orig_hex', '')
    is_edited = val.get('_edited', False)

    if orig_hex and not is_edited:
        # If not edited, just use the original hex data for simplicity
        return f"CDPv2_HDR(unhexlify('{orig_hex}'))"
    
    # Otherwise, reconstruct the source code from the edited fields
    cdp_fields = {}
    msg_list_str = '[]'
    raw_payload_str = ''

    for f_name in ['vers', 'ttl', 'cksum']:
        if f_name in val:
            cdp_fields[f_name] = val[f_name]
    
    if 'msg' in val and isinstance(val['msg'], list):
        msg_items = []
        for item in val['msg']:
            if isinstance(item, str):
                msg_items.append(f"Raw(load=unhexlify('{item}'))")
            else:
                msg_items.append(str(item))
        msg_list_str = f"[{', '.join(msg_items)}]"
        cdp_fields['msg'] = msg_list_str # Store as string for direct inclusion

    if 'raw_payload' in val and val['raw_payload']:
        raw_payload_str = f" / Raw(load=unhexlify('{val['raw_payload']}'))"

    ctor_args = []
    for k, v in cdp_fields.items():
        if k == 'msg':
            ctor_args.append(f"{k}={safe_repr(v)}") # msg_list_str is already correctly formatted
        elif isinstance(v, str):
            ctor_args.append(f"{k}='{v}'")
        else:
            ctor_args.append(f"{k}={safe_repr(v)}")

    ctor = f"CDPv2_HDR({', '.join(ctor_args)})"
    return f"{ctor}{raw_payload_str} / {payload_var}" if payload_var else f"{ctor}{raw_payload_str}"
