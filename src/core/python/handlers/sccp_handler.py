from pycrate_mobile.SCCP import parse_SCCP
from handlers.base import PycrateDissector
from registry import register_dissector

@register_dissector
class SCCPDissector(PycrateDissector):
    def check(self, data, ctx):
        if any(l.lower() == 'sccp' for l in ctx.ws_layers): return True
        return len(data) > 0 and data[0] in (0x09, 0x11, 0x12)

    def dissect(self, data, ctx, idx, offset, parent_idx=-1):
        s, err = parse_SCCP(data)
        if err: return None, 0
        
        sccp_idx = idx
        layer = self.create_layer(s, "SCCP", ctx, sccp_idx, offset, len(data), parent_idx)
        res_layers = [layer]
        
        # Determine TCAP payload
        tcap_data = None
        try:
            val = s.get_val()
            # In UDT, the last element is often the data
            if isinstance(val, list):
                # For Type 9 (UDT), index 5 is data
                if val[0] == 9 and len(val) > 5:
                    tcap_data = val[5][1] # [Len, Bytes]
        except: pass
        
        if not tcap_data:
            # Fallback binary search for TCAP Begin (0x62)
            idx_62 = data.find(b'\x62')
            if idx_62 != -1: tcap_data = data[idx_62:]
        
        if tcap_data:
            if isinstance(tcap_data, (list, tuple)): tcap_data = bytes(tcap_data)
            from handlers.tcap_map_handler import TcapMapDissector
            tcap_off_within = data.find(tcap_data)
            if tcap_off_within != -1:
                t_layers, _ = TcapMapDissector().dissect(tcap_data, ctx, sccp_idx + 1, offset + tcap_off_within, sccp_idx)
                if t_layers: res_layers.extend(t_layers)
                
        return res_layers, len(data)
