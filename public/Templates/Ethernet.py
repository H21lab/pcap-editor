import binascii
import copy
from scapy.layers.l2 import Ether
from scapy.packet import Raw
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

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    try:
        pkt = Ether(raw)
        val = {}
        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            # Handle Dot3 'len' field by mapping it to 'type'
            name = 'type' if f.name == 'len' else f.name
            val[name] = v.hex() if isinstance(v, bytes) else v
        
        # Get the bytes for the Ethernet header itself
        # This is a bit tricky with Scapy, safest is to reconstruct
        # If it dissected as Dot3, we need to map len -> type for Ether constructor
        header_fields = {}
        for f in pkt.fields_desc:
            if f.name == 'load': continue
            name = 'type' if f.name == 'len' else f.name
            header_fields[name] = pkt.getfieldval(f.name)

        ether_header_only_pkt = Ether(**header_fields)
        ether_header_len = len(bytes(ether_header_only_pkt))
        
        # All remaining data after the Ethernet header is considered the payload
        if len(raw) > ether_header_len:
            val['load'] = binascii.hexlify(raw[ether_header_len:]).decode()

        val['_orig_hex'] = hex_data # Store the original full hex for fidelity
        return val
    except Exception:
        # If standard Ether decode fails, return raw
        return {"raw": hex_data}

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)

    # If not edited, return original hex for full fidelity, including any padding/trailer
    if orig_hex and not is_edited:
        return orig_hex
        
    # Extract the main payload (next layer)
    raw_payload_next_layer = _find_and_remove_raw(val_copy)
    
    try:
        # Create the Ethernet header without 'load'
        ether_pkt_fields = {k: v for k, v in val_copy.items() if k != 'load'}
        ether_pkt = Ether(**ether_pkt_fields)
        
        # Add the next layer's raw payload
        if raw_payload_next_layer:
            ether_pkt.add_payload(raw_payload_next_layer)
            
        res_bytes = bytes(ether_pkt)
        res_hex = binascii.hexlify(res_bytes).decode()

        # If the re-encoded packet is shorter than the original, and we have the original,
        # it implies Scapy's padding differs. Append original trailing bytes to match length.
        if orig_hex and len(res_hex) < len(orig_hex):
            original_trailer_bytes = binascii.unhexlify(orig_hex[len(res_hex):])
            res_bytes += original_trailer_bytes
            res_hex = binascii.hexlify(res_bytes).decode()
        
        return res_hex
    except Exception: 
        return ""

def source_code(val, payload_var):
    fields = []
    for k, v in val.items():
        if k in ['raw', 'load', 'payload', '_orig_hex', '_edited']: continue
        fields.append(f"{k}={safe_repr(v)}")
    
    ctor = f"Ether({', '.join(fields)})"
    if payload_var:
        return f"{ctor} / {payload_var}"
    return ctor