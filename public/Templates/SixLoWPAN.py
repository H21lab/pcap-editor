import binascii
import copy
from scapy.layers.sixlowpan import SixLoWPAN, LoWPAN_IPHC, LoWPANFragmentationFirst
from scapy.packet import Packet
from scapy.all import Raw
from utils import safe_repr

def _find_and_remove_raw(struct):
    if isinstance(struct, list):
        for item in struct:
            res = _find_and_remove_raw(item)
            if res is not None: return res
    if isinstance(struct, dict):
        # 1. Check for {'raw': ...} or layer_name.raw_payload
        for k, v in list(struct.items()):
            if isinstance(v, dict) and 'raw' in v:
                val = binascii.unhexlify(v['raw'])
                del struct[k]
                return val
            if k.endswith('.raw_payload') and isinstance(v, str):
                try:
                    val = binascii.unhexlify(v)
                    del struct[k]
                    return val
                except: pass
        # 2. Check for load/data/payload as hex strings
        for k in ['load', 'data', 'payload']:
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
    return None

def decode(hex_data, length=None, **kwargs):
    if length is not None:
        hex_data = hex_data[:length*2]
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    
    try:
        pkt = SixLoWPAN(raw)
    except Exception as e:
        return {'_decode_error': str(e), 'load': hex_data}

    val = {}
    current_layer = pkt
    
    while current_layer:
        try:
            layer_name = current_layer.name.lower().replace(' ', '')
        except:
            layer_name = "unknown"
        
        if hasattr(current_layer, 'fields_desc'):
            for f in current_layer.fields_desc:
                try:
                    v = current_layer.getfieldval(f.name)
                    field_value = binascii.hexlify(v).decode() if isinstance(v, bytes) else v
                    val[f"{layer_name}.{f.name}"] = field_value
                except Exception:
                    pass 
        
        if isinstance(current_layer.payload, Packet):
            # If the next layer is a known SixLoWPAN sub-layer, its fields will be processed
            current_layer = current_layer.payload
        else:
            if current_layer.payload:
                # Store the remaining payload as raw data for the current layer
                val[f"{layer_name}.raw_payload"] = binascii.hexlify(bytes(current_layer.payload)).decode()
            current_layer = None

    val['_orig_hex'] = hex_data
    return val

def encode(val):
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    
    if orig_hex and not is_edited:
        return orig_hex

    sixlowpan_fields = {}
    iphc_fields = {}
    rfrag_fields = {}
    raw_payload_of_last_layer_hex = None # This will store the ultimate Raw payload

    # Categorize fields based on prefixes
    for k, v in list(val_copy.items()):
        if k.startswith('sixlowpan.iphc.'):
            iphc_fields[k.replace('sixlowpan.iphc.', '')] = v
        elif k.startswith('sixlowpan.rfrag.'):
            rfrag_fields[k.replace('sixlowpan.rfrag.', '')] = v
        elif k.startswith('sixlowpan.'):
            if k.endswith('.raw_payload'):
                # Handle raw payload explicitly for the main sixlowpan layer if present
                raw_payload_of_last_layer_hex = v
            else:
                sixlowpan_fields[k.replace('sixlowpan.', '')] = v
        
    # Build innermost payload first (if it exists)
    current_pkt = None
    if raw_payload_of_last_layer_hex:
        try: current_pkt = Raw(load=binascii.unhexlify(raw_payload_of_last_layer_hex))
        except Exception as e: return f"error: Raw payload constructor failed: {e}"

    # Build IPHC or RFRAG layer if fields are present
    if iphc_fields:
        try: 
            iphc_pkt = LoWPAN_IPHC(**iphc_fields)
            if current_pkt: current_pkt = iphc_pkt / current_pkt
            else: current_pkt = iphc_pkt
        except Exception as e: return f"error: LoWPAN_IPHC constructor failed: {e}"
    
    # Assuming RFRAG is LoWPANFragmentationFirst for this pcap
    if rfrag_fields:
        try: 
            rfrag_pkt = LoWPANFragmentationFirst(**rfrag_fields)
            if current_pkt: current_pkt = rfrag_pkt / current_pkt
            else: current_pkt = rfrag_pkt
        except Exception as e: return f"error: LoWPANFragmentationFirst constructor failed: {e}"

    # Build the main SixLoWPAN layer
    try:
        sixlowpan_pkt = SixLoWPAN(**sixlowpan_fields)
        if current_pkt: final_pkt = sixlowpan_pkt / current_pkt
        else: final_pkt = sixlowpan_pkt
    except Exception as e:
        return f"error: SixLoWPAN main constructor failed: {e}"

    return binascii.hexlify(bytes(final_pkt)).decode()

def source_code(val, payload_var):
    orig_hex = val.get('_orig_hex', '')
    is_edited = val.get('_edited', False)

    if orig_hex and not is_edited:
        return f"SixLoWPAN(unhexlify('{orig_hex}'))" # Returning only the main SixLoWPAN if not edited
    
    # Otherwise, reconstruct the source code for the edited packet
    sixlowpan_fields = {}
    iphc_fields = {}
    rfrag_fields = {}
    raw_payload_of_last_layer_hex = None

    for k, v in val.items():
        if k.startswith('sixlowpan.iphc.'):
            iphc_fields[k.replace('sixlowpan.iphc.', '')] = v
        elif k.startswith('sixlowpan.rfrag.'):
            rfrag_fields[k.replace('sixlowpan.rfrag.', '')] = v
        elif k.startswith('sixlowpan.'):
            if k.endswith('.raw_payload'):
                raw_payload_of_last_layer_hex = v
            else:
                sixlowpan_fields[k.replace('sixlowpan.', '')] = v

    ctor_parts = []
    # Main SixLoWPAN constructor
    sixlowpan_ctor_args = []
    for k, v in sixlowpan_fields.items():
        if isinstance(v, str): sixlowpan_ctor_args.append(f"{k}='{v}'")
        else: sixlowpan_ctor_args.append(f"{k}={safe_repr(v)}")
    
    ctor_parts.append(f"SixLoWPAN({', '.join(sixlowpan_ctor_args)})")

    # IPHC or RFRAG constructor
    payload_ctor = None
    if rfrag_fields:
        rfrag_ctor_args = []
        for k, v in rfrag_fields.items():
            if isinstance(v, str): rfrag_ctor_args.append(f"{k}='{v}'")
            else: rfrag_ctor_args.append(f"{k}={safe_repr(v)}")
        payload_ctor = f"LoWPANFragmentationFirst({', '.join(rfrag_ctor_args)})"
    elif iphc_fields:
        iphc_ctor_args = []
        for k, v in iphc_fields.items():
            if isinstance(v, str): iphc_ctor_args.append(f"{k}='{v}'")
            else: iphc_ctor_args.append(f"{k}={safe_repr(v)}")
        payload_ctor = f"LoWPAN_IPHC({', '.join(iphc_ctor_args)})"
    
    if payload_ctor:
        ctor_parts.append(payload_ctor)

    # Attach raw payload if present
    if raw_payload_of_last_layer_hex:
        ctor_parts.append(f"Raw(load=unhexlify('{raw_payload_of_last_layer_hex}'))")

    # Compose all parts
    full_ctor = " / ".join(ctor_parts)
    
    return f"{full_ctor} / {payload_var}" if payload_var else full_ctor
