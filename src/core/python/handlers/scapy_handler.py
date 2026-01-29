import binascii
import json
import struct
import sys
from scapy.packet import Raw, NoPayload, Packet
from scapy.all import * # Import all layers for easier access
from models import Layer, ModelField
from scapy_ext import reconstruct
from registry import PROTOCOL_METADATA, PROTOCOL_MAP

# authoritative map for Wireshark names to metadata keys
WS_NAME_MAP = {
    "eth": "Ethernet", "ip": "IP", "ipv6": "IPv6", "tcp": "TCP", "udp": "UDP",
    "sctp": "SCTP", "m3ua": "M3UA", "sccp": "SCCP", "tcap": "TCAP",
    "gsm_map": "TCAP_MAP", "gtp": "GTP", "gtpv2": "GTP", "gtpheader": "GTP", "gtp_u_header": "GTP", "dhcpv6": "DHCP6",
    "icmpv6ndoptsrclladdr": "ICMPv6NDOptSrcLLAddr",
    "icmpv6ndoptdstlladdr": "ICMPv6NDOptDstLLAddr",
    "icmpv6nd_ns": "ICMPv6ND_NS",
    "icmpv6nd_na": "ICMPv6ND_NA",
    "sctpchunkdata": "SCTPChunkData", "sctpchunksack": "SCTPChunkSACK",
    "sctpchunkinit": "SCTPChunkInit", "sctpchunkinitack": "SCTPChunkInitAck",
    "sctpchunkcookieecho": "SCTPChunkCookieEcho", "sctpchunkcookieack": "SCTPChunkCookieAck",
    "padding": "Padding", "6lowpan": "SixLoWPAN", "wpan-tap": "WTAP", "wpan": "Dot15d4",
    "pppoe": "PPPoE", "ppp": "PPP", "pppoed": "PPPoED",
    "pppoed_tags": "PPPoED_Tags", "ppp_lcp_configure": "PPP_LCP_Configure",
    "ppp_lcp_terminate": "PPP_LCP_Terminate",
    "ppp_pap_request": "PPP_PAP_Request",
    "rip": "RIP", "ripentry": "RIPEntry",
    "bootp": "BOOTP", "dhcp": "DHCP", "igmp": "IGMP",
    "sll": "CookedLinux", "tls": "TLS",
    "trailer": "Padding", "ntp": "NTP", "ntpheader": "NTP",
    "tftp": "TFTP", "coap": "CoAP", "dns": "DNS", "smb": "SMB", "smb2": "SMB2",
    "sip": "SIP", "rtp": "RTP", "http": "HTTP", "ftp": "FTP", "smtp": "SMTP"
}

class ScapyDissector:
    def _dissect_m3ua_stack(self, layers, chunk_idx, hex_data):
        try:
            from pycrate_mobile.SIGTRAN import SIGTRAN
            from pycrate_mobile.SCCP import parse_SCCP
            try: from pycrate_mobile.ISUP import parse_ISUP
            except: parse_ISUP = None
            
            chunk_layer = layers[chunk_idx]
            m3ua_offset = chunk_layer.offset + 16
            m3ua_length = chunk_layer.length - 16
            if m3ua_length <= 0: return

            m3ua_hex = hex_data[m3ua_offset*2 : (m3ua_offset + m3ua_length)*2]
            raw_bin = binascii.unhexlify(m3ua_hex)
            
            # Check M3UA version (must be 1)
            if not raw_bin or raw_bin[0] != 1: return

            msg = SIGTRAN()
            msg.from_bytes(raw_bin)
            m3ua_val = msg.get_val()
            
            payload_bin = b''
            si = None
            for param in m3ua_val[1]:
                # 528=ProtocolData
                if isinstance(param, list) and len(param) > 0 and param[0] == 528:
                    pd_val = param[2]
                    # ProtocolData is a dict/list with fields: opc, dpc, si, ni, mp, sls, data
                    if isinstance(pd_val, dict):
                        si = pd_val.get('si')
                        payload_bin = pd_val.get('data', b'')
                    elif isinstance(pd_val, list):
                        # Heuristic for list representation: [opc, dpc, si, ni, mp, sls, data]
                        if len(pd_val) >= 7:
                            si = pd_val[2]
                            payload_bin = pd_val[6]
                    elif isinstance(pd_val, bytes):
                        # Manually parse ProtocolData bytes:
                        # OPC(4), DPC(4), SI(1), NI(1), MP(1), SLS(1), DATA(var)
                        if len(pd_val) >= 12:
                            si = pd_val[8]
                            payload_bin = pd_val[12:]
                    break
                # Fallback for other data-carrying parameters
                elif isinstance(param, list) and len(param) > 0 and param[0] in [272, 768, 2]:
                    if isinstance(param[2], (bytes, bytearray)): payload_bin = param[2]
                    elif isinstance(param[2], list): payload_bin = param[2][-1]
                    break
            
            sccp_rel_offset = raw_bin.find(payload_bin) if payload_bin else len(raw_bin)
            if sccp_rel_offset == -1: sccp_rel_offset = 8
            
            layers.append(Layer(index=len(layers), name="M3UA", protocol="M3UA", fields=[], offset=m3ua_offset, length=len(raw_bin)))
            
            payload_offset = m3ua_offset + sccp_rel_offset
            if not payload_bin: return

            # Try SCCP directly first
            if si == 3 or not si:
                sccp_msg = None
                try: sccp_msg, rest = parse_SCCP(payload_bin)
                except: pass
                
                if sccp_msg:
                    self._dissect_sccp_stack(layers, sccp_msg, payload_bin, payload_offset)
                    return

            # Try MTP3 wrapped (if SI was not 3 or SCCP failed)
            try:
                # If we don't have an SI from M3UA, we try to guess from the payload
                if si is None:
                    sio = payload_bin[0]
                    si = sio & 0x0F
                
                if si == 5 and parse_ISUP: # ISUP
                    isup_msg, rest = parse_ISUP(payload_bin)
                    if isup_msg:
                        self._dissect_isup_stack(layers, isup_msg, payload_bin, payload_offset)
                
                elif si == 3: # SCCP
                    sccp_msg, rest = parse_SCCP(payload_bin)
                    if sccp_msg:
                        self._dissect_sccp_stack(layers, sccp_msg, payload_bin, payload_offset)
                else:
                    # Generic MTP3 layer if we have data but SI is unknown/other
                    from pycrate_mobile.SIGTRAN import MTP3
                    mtp3 = MTP3()
                    mtp3.from_bytes(payload_bin)
                    layers.append(Layer(index=len(layers), name="MTP3", protocol="MTP3", fields=[], offset=payload_offset, length=5))
                    
                    inner_bin = payload_bin[5:]
                    inner_offset = payload_offset + 5
                    sio = payload_bin[0]
                    si_inner = sio & 0x0F
                    
                    if si_inner == 5 and parse_ISUP:
                        isup_msg, rest = parse_ISUP(inner_bin)
                        if isup_msg: self._dissect_isup_stack(layers, isup_msg, inner_bin, inner_offset)
                    elif si_inner == 3:
                        sccp_msg, rest = parse_SCCP(inner_bin)
                        if sccp_msg: self._dissect_sccp_stack(layers, sccp_msg, inner_bin, inner_offset)
            except Exception: pass

        except Exception: pass

    def _dissect_m2ua_stack(self, layers, chunk_idx, hex_data):
        """
        Dissect M2UA stack: M2UA -> MTP3 -> SCCP -> TCAP -> CAMEL/MAP
        M2UA Data 1 parameter (tag 768) contains raw MTP3 message.
        """
        try:
            from pycrate_mobile.SIGTRAN import SIGTRAN
            from pycrate_mobile.SCCP import parse_SCCP

            chunk_layer = layers[chunk_idx]
            m2ua_offset = chunk_layer.offset + 16  # Skip SCTP chunk header
            m2ua_length = chunk_layer.length - 16
            if m2ua_length <= 0: return

            m2ua_hex = hex_data[m2ua_offset*2 : (m2ua_offset + m2ua_length)*2]
            raw_bin = binascii.unhexlify(m2ua_hex)

            # Check M2UA version (must be 1)
            if not raw_bin or raw_bin[0] != 1: return

            msg = SIGTRAN()
            msg.from_bytes(raw_bin)
            m2ua_val = msg.get_val()

            # Add M2UA layer
            layers.append(Layer(index=len(layers), name="M2UA", protocol="M2UA", fields=[], offset=m2ua_offset, length=len(raw_bin)))

            # Find Data 1 parameter (tag 768 = 0x0300)
            mtp3_bin = b''
            for param in m2ua_val[1]:
                if isinstance(param, list) and len(param) >= 3 and param[0] == 768:
                    # param = [tag, length, data, padding]
                    if isinstance(param[2], (bytes, bytearray)):
                        mtp3_bin = param[2]
                    break

            if not mtp3_bin or len(mtp3_bin) < 6:
                return

            # Find MTP3 offset within M2UA
            mtp3_rel_offset = raw_bin.find(mtp3_bin)
            if mtp3_rel_offset == -1:
                mtp3_rel_offset = 8  # Fallback: M2UA header is typically 8 bytes
            mtp3_offset = m2ua_offset + mtp3_rel_offset

            # Parse MTP3: SIO (1 byte) + Routing Label (4 bytes for ITU) + payload
            # SIO format: NI (2 bits) + spare (2 bits) + SI (4 bits)
            sio = mtp3_bin[0]
            si = sio & 0x0F  # Service Indicator

            # Add MTP3 layer (5 bytes header for ITU-T)
            mtp3_header_len = 5
            layers.append(Layer(index=len(layers), name="MTP3", protocol="MTP3", fields=[], offset=mtp3_offset, length=mtp3_header_len))

            # Extract payload after MTP3 header
            sccp_bin = mtp3_bin[mtp3_header_len:]
            sccp_offset = mtp3_offset + mtp3_header_len

            if si == 3 and sccp_bin:  # SI=3 is SCCP
                try:
                    sccp_msg, rest = parse_SCCP(sccp_bin)
                    if sccp_msg:
                        self._dissect_sccp_stack(layers, sccp_msg, sccp_bin, sccp_offset)
                except:
                    pass

        except Exception:
            pass

    def _dissect_isup_stack(self, layers, isup_msg, isup_bin, isup_offset):
        try:
            layers.append(Layer(index=len(layers), name="ISUP", protocol="ISUP", fields=[], offset=isup_offset, length=len(isup_bin)))
        except: pass

    def _dissect_sccp_stack(self, layers, sccp_msg, sccp_bin, sccp_offset):
        try:
            sccp_val = sccp_msg.get_val()
            layers.append(Layer(index=len(layers), name="SCCP", protocol="SCCP", fields=[], offset=sccp_offset, length=len(sccp_bin)))
            
            if sccp_val[0] == 9 and len(sccp_val) > 5:
                tcap_bin = sccp_val[-1][1]
                tcap_rel_offset = sccp_bin.find(tcap_bin)
                if tcap_rel_offset == -1: tcap_rel_offset = len(sccp_bin) - len(tcap_bin)
                self._dissect_tcap_stack(layers, tcap_bin, sccp_offset + tcap_rel_offset)
        except: pass

    def _dissect_s1ap_stack(self, layers, chunk_idx, hex_data):
        try:
            from pycrate_asn1dir import S1AP
            
            chunk_layer = layers[chunk_idx]
            payload_offset = chunk_layer.offset + 16
            payload_length = chunk_layer.length - 16
            if payload_length <= 0: return

            payload_hex = hex_data[payload_offset*2 : (payload_offset + payload_length)*2]
            raw_bin = binascii.unhexlify(payload_hex)
            
            msg = S1AP.S1AP_PDU_Descriptions.S1AP_PDU
            msg.from_aper(raw_bin)
            
            layers.append(Layer(index=len(layers), name="S1AP", protocol="S1AP", fields=[], offset=payload_offset, length=len(raw_bin)))
            
        except Exception: pass

    def _dissect_ngap_stack(self, layers, chunk_idx, hex_data):
        try:
            from pycrate_asn1dir import NGAP
            
            chunk_layer = layers[chunk_idx]
            payload_offset = chunk_layer.offset + 16
            payload_length = chunk_layer.length - 16
            if payload_length <= 0: return

            payload_hex = hex_data[payload_offset*2 : (payload_offset + payload_length)*2]
            raw_bin = binascii.unhexlify(payload_hex)
            
            msg = NGAP.NGAP_PDU_Descriptions.NGAP_PDU
            msg.from_aper(raw_bin)
            
            layers.append(Layer(index=len(layers), name="NGAP", protocol="NGAP", fields=[], offset=payload_offset, length=len(raw_bin)))

        except Exception: pass

    def _dissect_diameter_stack(self, layers, chunk_idx, hex_data):
        """Dissect Diameter protocol over SCTP."""
        try:
            from pycrate_diameter.Diameter3GPP import Diameter3GPP

            chunk_layer = layers[chunk_idx]
            payload_offset = chunk_layer.offset + 16
            payload_length = chunk_layer.length - 16
            if payload_length <= 0: return

            payload_hex = hex_data[payload_offset*2 : (payload_offset + payload_length)*2]
            raw_bin = binascii.unhexlify(payload_hex)

            # Basic Diameter message validation: version must be 1, length must match
            if len(raw_bin) < 20: return  # Minimum Diameter header size
            if raw_bin[0] != 1: return  # Diameter version must be 1

            msg = Diameter3GPP()
            msg.from_bytes(raw_bin)

            layers.append(Layer(index=len(layers), name="Diameter", protocol="Diameter", fields=[], offset=payload_offset, length=len(raw_bin)))

        except Exception: pass

    def _dissect_sccp_stack(self, layers, sccp_msg, sccp_bin, sccp_offset):
        try:
            sccp_val = sccp_msg.get_val()
            layers.append(Layer(index=len(layers), name="SCCP", protocol="SCCP", fields=[], offset=sccp_offset, length=len(sccp_bin)))
            
            if sccp_val[0] == 9 and len(sccp_val) > 5:
                tcap_bin = sccp_val[-1][1]
                tcap_rel_offset = sccp_bin.find(tcap_bin)
                if tcap_rel_offset == -1: tcap_rel_offset = len(sccp_bin) - len(tcap_bin)
                self._dissect_tcap_stack(layers, tcap_bin, sccp_offset + tcap_rel_offset)
        except: pass

    def _dissect_tcap_stack(self, layers, tcap_bin, tcap_offset):
        """
        Dissect TCAP and detect whether it's CAMEL (CAP) or MAP.
        CAMEL/CAP is handled by TCAP layer using TCAP_CAP encoder - no separate CAMEL layer needed.
        """
        tcap_val = None
        is_camel = False
        is_map = False

        # Try TCAP_CAP first (for CAMEL)
        try:
            from pycrate_asn1dir import TCAP_CAP
            cap_pdu = TCAP_CAP.CAP_gsmSSF_gsmSCF_pkgs_contracts_acs.GenericSSF_gsmSCF_PDUs
            cap_pdu.from_ber(tcap_bin)
            tcap_val = cap_pdu.get_val()
            is_camel = True
        except:
            pass

        # If CAP failed, try TCAP_MAP
        if not is_camel:
            try:
                from pycrate_asn1dir import TCAP_MAPv2v3
                map_pdu = TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message
                map_pdu.from_ber(tcap_bin)
                tcap_val = map_pdu.get_val()
                is_map = True
            except:
                pass

        # Add TCAP layer (handles both CAP and MAP encoding via TCAP template)
        # The TCAP template auto-detects CAP vs MAP and uses the correct encoder
        layers.append(Layer(index=len(layers), name="TCAP", protocol="TCAP", fields=[], offset=tcap_offset, length=len(tcap_bin)))

        # Note: No separate CAMEL layer - TCAP_CAP handles CAP/CAMEL encoding
        # Only add TCAP_MAP layer for MAP protocol identification
        if is_map:
            # Check for IMSI to confirm it's MAP
            def _find_imsi(v):
                if isinstance(v, dict):
                    if 'imsi' in v: return v['imsi']
                    for vv in v.values():
                        res = _find_imsi(vv)
                        if res: return res
                if isinstance(v, (list, tuple)):
                    for i in v:
                        res = _find_imsi(i)
                        if res: return res
                return None

            imsi = _find_imsi(tcap_val) if tcap_val else None
            if imsi and isinstance(imsi, bytes):
                layers.append(Layer(index=len(layers), name="TCAP_MAP", protocol="TCAP_MAP", fields=[], offset=tcap_offset, length=len(tcap_bin)))

    def _get_authoritative_name(self, name):
        if not name: return None
        name_low = name.lower()
        if name_low in WS_NAME_MAP: return WS_NAME_MAP[name_low]
        if name_low in PROTOCOL_MAP: return PROTOCOL_MAP[name_low]
        for k in PROTOCOL_METADATA:
            if k.lower() == name_low: return k
        return None

    def _get_ws_protocol_at_offset(self, ws_info, offset: int) -> str:
        """Get Wireshark-identified protocol name at a given offset."""
        if not ws_info:
            return None
        try:
            info_list = ws_info if isinstance(ws_info, list) else json.loads(ws_info)
            for lyr in info_list:
                # Support both formats: offset/length and pos/size
                lyr_offset = lyr.get('offset', lyr.get('pos', -1))
                lyr_len = lyr.get('length', lyr.get('size', 0))
                if lyr_offset <= offset < lyr_offset + lyr_len:
                    ws_name = lyr.get('name', '')
                    auth = self._get_authoritative_name(ws_name)
                    if auth and auth != "Raw":
                        return auth
        except:
            pass
        return None

    def dissect_hex(self, hex_data: str, ws_info=None, wpan_dlt: int = 1):
        raw_bin = binascii.unhexlify(hex_data)
        hint = None
        if ws_info:
            try:
                info_list = ws_info if isinstance(ws_info, list) else json.loads(ws_info)
                if info_list and len(info_list) > 0:
                    hint = self._get_authoritative_name(info_list[0]['name'])
            except: pass

        pkt = reconstruct(hex_data, hint=hint, wpan_dlt=wpan_dlt)
        layers = []; curr = pkt; off = 0; idx = 0
        while curr and not isinstance(curr, NoPayload):
            fields = []
            if hasattr(curr, "fields_desc"):
                for f_desc in curr.fields_desc:
                    try:
                        val = curr.getfieldval(f_desc.name)
                        vs = ""
                        if isinstance(val, bytes): vs = val.hex()
                        elif hasattr(val, 'val') and not isinstance(val, type):
                            vs = str(val.val)
                        elif isinstance(val, list):
                            items = []
                            for item in val:
                                if hasattr(item, "command"): items.append(item.command())
                                else: items.append(repr(item))
                            vs = "[" + ", ".join(items) + "]"
                        else: vs = str(val)
                        fields.append(ModelField(f_desc.name, vs, f_desc.__class__.__name__))
                    except: pass

            if isinstance(curr, Raw) and not any(f.name == 'load' for f in fields):
                if hasattr(curr, 'load'):
                    fields.append(ModelField('load', curr.load.hex(), 'StrField'))

            name = getattr(curr, "name", curr.__class__.__name__)
            auth_name = self._get_authoritative_name(curr.__class__.__name__) or self._get_authoritative_name(name) or curr.__class__.__name__

            # When Scapy returns Raw, check Wireshark for protocol identification
            if auth_name == "Raw" and ws_info:
                ws_proto = self._get_ws_protocol_at_offset(ws_info, off)
                if ws_proto:
                    auth_name = ws_proto
                    name = ws_proto
            
            # Skip misidentified layers
            if auth_name == "CAN" and idx > 0:
                curr = curr.payload; idx += 1; continue
                
            l_len = len(curr)
            if curr.payload and not isinstance(curr.payload, NoPayload):
                l_len = len(curr) - len(curr.payload)
            
            # Re-check Raw load if not in fields
            if auth_name == "Raw" and not any(f.name == "load" for f in fields):
                if hasattr(curr, 'load'):
                    fields.append(ModelField('load', curr.load.hex(), 'StrField'))

            layers.append(Layer(index=idx, name=name, protocol=auth_name, fields=fields, offset=off, length=l_len))
            # POPULATE VAL DICT FOR RECONSTRUCTION
            layer_val = {}
            if hasattr(curr, "fields_desc"):
                for f_desc in curr.fields_desc:
                    v = curr.getfieldval(f_desc.name)
                    if isinstance(v, (bytes, bytearray)):
                        layer_val[f_desc.name] = v.hex()
                    else:
                        layer_val[f_desc.name] = v
            layers[-1].val = layer_val
            off += l_len
            curr = curr.payload; idx += 1

        # Check for IP fragments - don't try to parse their payload as protocols
        is_ip_fragment = False
        for l in layers:
            if l.protocol == "IP":
                for f in l.fields:
                    if f.name == "frag":
                        try:
                            frag_val = int(f.val) if isinstance(f.val, (int, str)) else 0
                            if frag_val > 0:
                                is_ip_fragment = True
                                break
                        except: pass

        # GTP detection based on UDP ports (skip for IP fragments)
        if not is_ip_fragment:
            try:
                for i in range(len(layers)):
                    if layers[i].protocol == "UDP":
                        sport = dport = None
                        for f in layers[i].fields:
                            if f.name == "sport": sport = int(f.val)
                            if f.name == "dport": dport = int(f.val)
                        # GTP-U port 2152, GTP-C port 2123
                        if sport in [2152, 2123] or dport in [2152, 2123]:
                            # Find the Raw layer immediately after UDP
                            for j in range(i + 1, len(layers)):
                                if layers[j].protocol == "Raw":
                                    layers[j].protocol = "GTP"
                                    layers[j].name = "GTP"
                                    break
                                elif layers[j].protocol not in ["Padding"]:
                                    break
            except Exception: pass

        sctp_payload_map = {60: "NGAP", 18: "S1AP", 3: "M3UA", 2: "M2UA", 46: "Diameter", 47: "Diameter"}
        try:
            # Get SCTP ports for protocol detection when PPID is 0
            sctp_sport, sctp_dport = None, None
            for l in layers:
                if l.protocol == "SCTP":
                    for f in l.fields:
                        if f.name == "sport":
                            try: sctp_sport = int(f.val)
                            except: pass
                        elif f.name == "dport":
                            try: sctp_dport = int(f.val)
                            except: pass
                    break

            # We need to use a static copy of the layer indices because we might append to the list
            for i in range(len(layers)):
                if layers[i].protocol == "SCTPChunkData":
                    proto_id = None
                    for f in layers[i].fields:
                        if f.name == "proto_id":
                            try:
                                # Use split()[0] to handle values like '3 (M3UA)'
                                p_str = str(f.val).split()[0]
                                proto_id = int(p_str)
                            except: pass
                            break
                    if proto_id == 18:
                        self._dissect_s1ap_stack(layers, i, hex_data)
                    elif proto_id == 60:
                        self._dissect_ngap_stack(layers, i, hex_data)
                    elif proto_id == 2:  # M2UA
                        self._dissect_m2ua_stack(layers, i, hex_data)
                    elif proto_id in [46, 47]:  # Diameter
                        self._dissect_diameter_stack(layers, i, hex_data)
                    elif proto_id == 3:  # M3UA
                        self._dissect_m3ua_stack(layers, i, hex_data)
                    elif proto_id == 0:  # PPID 0 - check port to determine protocol
                        # Diameter uses port 3868
                        if sctp_sport == 3868 or sctp_dport == 3868:
                            self._dissect_diameter_stack(layers, i, hex_data)
                        else:
                            # Fallback to M3UA for PPID 0 (seen in sigtran.pcap)
                            self._dissect_m3ua_stack(layers, i, hex_data)
        except Exception: pass

        if ws_info:
            try:
                info_list = ws_info if isinstance(ws_info, list) else json.loads(ws_info)

                # Detect IP fragments - their payload is fragment data, not actual protocols
                # TShark's ws_layers for fragments may show reassembled protocols which don't exist in the frame
                ip_fragment_payload_offset = None
                for l in layers:
                    if l.protocol == "IP":
                        # Check if this IP has a fragment offset > 0
                        for f in l.fields:
                            if f.name == "frag":
                                try:
                                    frag_val = int(f.val) if isinstance(f.val, (int, str)) else 0
                                    if frag_val > 0:
                                        # This is an IP fragment - payload after IP header is fragment data
                                        ip_fragment_payload_offset = l.offset + l.length
                                        break
                                except: pass

                # Build coverage map of Scapy-detected layers
                scapy_coverage = []
                for l in layers:
                    scapy_coverage.append((l.offset, l.offset + l.length, l.protocol))

                tshark_layers = []
                raw_layer_offsets = set()
                for l in layers:
                    if l.protocol == "Raw":
                        raw_layer_offsets.add(l.offset)

                for info in info_list:
                    # Skip ws_layers that are inside an IP fragment payload
                    # These would be from TShark's reassembled view, not the actual frame
                    if ip_fragment_payload_offset is not None and info['pos'] >= ip_fragment_payload_offset:
                        continue
                    auth_name = self._get_authoritative_name(info['name'])
                    if not auth_name: continue

                    ws_start = info['pos']
                    ws_end = info['pos'] + info['size']
                    skip = False
                    for (sc_start, sc_end, sc_proto) in scapy_coverage:
                        # Skip if same offset as a non-Raw Scapy layer (Scapy already detected specific protocol)
                        if ws_start == sc_start and sc_proto != "Raw":
                            skip = True
                            break
                        # Skip if same protocol and overlapping
                        if auth_name == sc_proto and not (ws_end <= sc_start or ws_start >= sc_end):
                            skip = True
                            break
                    if skip:
                        continue

                    tshark_layers.append(Layer(index=len(layers) + len(tshark_layers), name=auth_name, protocol=auth_name, fields=[], offset=info['pos'], length=info['size']))

                # Remove Raw layers that are superseded by TShark-detected specific layers
                tshark_offsets = {l.offset for l in tshark_layers}
                layers = [l for l in layers if not (l.protocol == "Raw" and l.offset in tshark_offsets)]
                layers.extend(tshark_layers)
            except Exception: pass
        
        layers.sort(key=lambda x: (x.offset, -x.length))
        
        unique = []
        seen = set()
        
        for l in layers:
            # Allow multiple layers at same offset if they have different protocol names
            # This is common in SIGTRAN (M3UA/SCCP/TCAP all starting at same data offset)
            key = (int(l.offset), str(l.protocol))
            if key not in seen:
                unique.append(l)
                seen.add(key)
        
        # Remove Padding layers if they overlap with any non-Padding layer
        final_layers = []
        # Calculate coverage of non-padding layers
        covered_ranges = []
        for l in unique:
            if l.protocol != "Padding":
                covered_ranges.append((l.offset, l.offset + l.length))
        
        for l in unique:
            if l.protocol == "Padding":
                is_overlapping = False
                l_end = l.offset + l.length
                for (start, end) in covered_ranges:
                    # Check for overlap: not (end <= l.offset or start >= l_end)
                    if not (end <= l.offset or start >= l_end):
                        is_overlapping = True
                        break
                if not is_overlapping:
                    final_layers.append(l)
            else:
                final_layers.append(l)

        for i, l in enumerate(final_layers):
            l.index = i

        return final_layers
