import binascii
import importlib
from scapy.all import *

# Ensure common layers are available
try:
    import scapy.layers.inet, scapy.layers.inet6, scapy.layers.ppp, scapy.layers.l2
    import scapy.layers.tls.all, scapy.layers.dhcp, scapy.layers.dhcp6, scapy.layers.http
    import scapy.layers.dot11, scapy.layers.dot15d4, scapy.layers.sixlowpan
    import scapy.layers.ipx, scapy.layers.smb, scapy.layers.smb2, scapy.layers.ntlm
    try:
        from scapy.contrib.igmp import IGMP
    except:
        pass
    try:
        from scapy.contrib.mpls import MPLS
    except:
        pass
except:
    pass

try:
    conf.dot15d4_protocol = 'zigbee'
except:
    pass

class WTAP(Packet):
    name = "WTAP"
    fields_desc = [ StrFixedLenField("header", b"", length=100) ]

# DLT 204 direction byte layer
class PPPDirection(Packet):
    name = "PPPDirection"
    fields_desc = [ ByteField("direction", 0) ]

try:
    from scapy.layers.ppp import HDLC, PPP
    bind_layers(PPPDirection, HDLC)
except:
    pass

def reconstruct(hex_data, hint=None, wpan_dlt=None):
    raw = binascii.unhexlify(hex_data)
    if not raw: return Raw(b'')

    # Priority 0: Detect SLL (Linux Cooked Capture) regardless of linktype
    # This handles cases where the web UI passes incorrect linktype=1
    # SLL signature: pkttype (00 00 or 00 04) + arphrd (00 01) + halen (00 06)
    if len(raw) >= 16:
        pkttype = int.from_bytes(raw[0:2], 'big')
        arphrd = int.from_bytes(raw[2:4], 'big')
        halen = int.from_bytes(raw[4:6], 'big')
        proto = int.from_bytes(raw[14:16], 'big')
        # Valid SLL: pkttype in [0,1,2,3,4], arphrd=1 (Ethernet), halen=6, proto is valid ethertype
        if pkttype <= 4 and arphrd == 1 and halen == 6 and proto in [0x0800, 0x0806, 0x86DD, 0x8100]:
            return CookedLinux(raw)

    # Priority 1: Auto-detection based on DLT (Link Layer)
    if wpan_dlt is not None and wpan_dlt != 0:
        try:
            if wpan_dlt == 1: return Ether(raw)
            if wpan_dlt == 113: return CookedLinux(raw)
            if wpan_dlt in [9, 204, 50, 51, 19]:
                try:
                    from scapy.layers.ppp import HDLC, PPP
                    # DLT 204 has a 1-byte direction prefix (00 or 01) followed by HDLC
                    if wpan_dlt == 204 and len(raw) >= 3 and raw[1] == 0xff and raw[2] == 0x03:
                        return PPPDirection(raw)
                    # Check if bytes look like HDLC (ff 03)
                    if len(raw) >= 2 and raw[0] == 0xff and raw[1] == 0x03:
                        return HDLC(raw)
                    return PPP(raw)
                except:
                    pass
            if wpan_dlt == 206:
                try:
                    from scapy.layers.dot15d4 import Dot15d4
                    return WTAP(raw) / Dot15d4(raw[100:])
                except:
                    return WTAP(raw)
            if wpan_dlt in [195, 230]:
                try:
                    from scapy.layers.dot15d4 import Dot15d4
                    return Dot15d4(raw)
                except:
                    pass
            if wpan_dlt == 127:
                try:
                    from scapy.layers.dot11 import RadioTap
                    return RadioTap(raw)
                except:
                    pass
            if wpan_dlt == 105:
                try:
                    from scapy.layers.dot11 import Dot11
                    return Dot11(raw)
                except:
                    pass
            if wpan_dlt == 101:
                version = (raw[0] >> 4) & 0x0f
                if version == 4: return IP(raw)
                if version == 6: return IPv6(raw)
        except:
            pass

    # Priority 2: Explicit Hint
    if hint:
        if hint == "DHCP": hint = "BOOTP"
        if hint == "ICMPv6": hint = "ICMPv6Unknown"
        
        # Special case: PPP hint might really be HDLC/PPP
        if hint == "PPP" and len(raw) >= 2 and raw[0] == 0xff and raw[1] == 0x03:
            try:
                from scapy.layers.ppp import HDLC
                return HDLC(raw)
            except: pass
        
        # Try finding the class in common scapy namespaces
        import scapy.all as scapy_all
        mods = [scapy_all]
        for mname in ["inet", "inet6", "ppp", "l2", "tls.all", "dhcp", "dhcp6", "http", "dot11", "dot15d4", "sixlowpan", "ipx", "smb", "smb2", "ntlm"]:
            try:
                m = importlib.import_module(f"scapy.layers.{mname}")
                mods.append(m)
            except:
                try:
                    if mname == "tls.all":
                        import scapy.layers.tls.all as tls_all
                        mods.append(tls_all)
                except: pass
        
        for mod in mods:
            if hasattr(mod, hint):
                cls = getattr(mod, hint)
                if isinstance(cls, type) and issubclass(cls, Packet):
                    try:
                        return cls(raw)
                    except:
                        pass
        if hint == "WTAP": return WTAP(raw)

    # Priority 3: Generic Auto-detection
    try:
        # Check if it's SLL (Linux Cooked Capture)
        if len(raw) >= 16:
            if raw[:2] in [b'\x00\x00', b'\x00\x04'] and raw[2:4] in [b'\x00\x01']:
                return CookedLinux(raw)

        # Check if it's 802.3
        if len(raw) >= 14:
            length = int.from_bytes(raw[12:14], "big")
            if length <= 1500:
                return Dot3(raw)
        
        # Check if it's PPP
        if len(raw) >= 2 and raw[0] == 0xff and raw[1] == 0x03:
            try:
                from scapy.layers.ppp import HDLC
                return HDLC(raw)
            except: pass
            
        return Ether(raw)
    except:
        pass
        
    try: 
        version = (raw[0] >> 4) & 0x0f
        if version == 4: return IP(raw)
        if version == 6: return IPv6(raw)
    except: pass
    
    return Raw(raw)

def get_layer_hex(pkt, layer_cls):
    """Returns the hex representation of a specific layer including its payload."""
    if pkt.haslayer(layer_cls):
        return binascii.hexlify(bytes(pkt.getlayer(layer_cls))).decode()
    return None
