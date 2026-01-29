import binascii
import copy
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3, IGMPv3mr, IGMPv3mq

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
            if k in struct and isinstance(struct[k], str):
                try:
                    val = binascii.unhexlify(struct[k])
                    del struct[k]
                    return val
                except: pass
        for k, v in struct.items():
            res = _find_and_remove_raw(v)
            if res is not None: return res
    return None

def decode(hex_data):
    raw = binascii.unhexlify(hex_data)
    if not raw: return {}
    
    # Try generic IGMP (v1/v2)
    pkt = IGMP(raw)
    
    # Check if it looks like IGMPv3
    # IGMPv3 Membership Report type is 0x22 (34)
    # IGMPv3 Membership Query type is 0x11 (17), same as v1/v2 but length differs
    if pkt.type == 0x22:
        try: pkt = IGMPv3(raw)
        except: pass
    elif pkt.type == 0x11 and len(raw) >= 12:
         # v3 query is longer than v2 (8 bytes)
        try: pkt = IGMPv3mq(raw)
        except: pass

    val = {}
    val['type'] = pkt.type # ensure type is present
    
    for f in pkt.fields_desc:
        try:
            v = pkt.getfieldval(f.name)
            # Handle list of groups for v3
            if isinstance(v, list):
                val[f.name] = []
                for item in v:
                    # v3 records are objects, need serialization if so
                    if hasattr(item, 'fields_desc'):
                        rec = {}
                        for rf in item.fields_desc:
                            rv = item.getfieldval(rf.name)
                            rec[rf.name] = rv.hex() if isinstance(rv, bytes) else rv
                        val[f.name].append(rec)
                    else:
                        val[f.name].append(str(item))
            else:
                val[f.name] = v.hex() if isinstance(v, bytes) else v
        except: pass
    
    if pkt.payload:
        val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()
    val['_orig_hex'] = hex_data
    val['_cls_name'] = pkt.__class__.__name__
    return val

def encode(val):
    if isinstance(val, dict) and 'raw' in val: return val['raw']
    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    is_edited = val_copy.pop('_edited', False)
    cls_name = val_copy.pop('_cls_name', 'IGMP')
    
    raw_payload = _find_and_remove_raw(val_copy)
    val_copy.pop('chksum', None)

    # Reconstruct correct class
    if cls_name == 'IGMPv3': cls = IGMPv3
    elif cls_name == 'IGMPv3mq': cls = IGMPv3mq
    elif cls_name == 'IGMPv3mr': cls = IGMPv3mr
    else: cls = IGMP

    try:
        # For v3 records, we might need to reconstruct objects from dicts
        if 'grps' in val_copy and isinstance(val_copy['grps'], list):
            # This is complex for IGMPv3 reconstruction without explicit classes
            # For now, let's rely on scapy to handle dicts if it supports it, 
            # or fail back to orig_hex if not edited.
            pass

        pkt = cls(**val_copy)
        if raw_payload:
            pkt.add_payload(raw_payload)
        res_hex = binascii.hexlify(bytes(pkt)).decode()
        if orig_hex and not is_edited and len(res_hex) == len(orig_hex):
            return orig_hex
        return res_hex
    except:
        return orig_hex if orig_hex else ""