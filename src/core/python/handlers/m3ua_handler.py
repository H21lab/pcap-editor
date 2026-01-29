from pycrate_mobile.M3UA import parse_M3UA
from handlers.base import PycrateDissector
from registry import register_dissector
import sys, traceback

@register_dissector
class M3UADissector(PycrateDissector):
    def check(self, data, ctx):
        if any(l.lower() == 'm3ua' for l in ctx.ws_layers): return True
        return len(data) > 4 and data[0] == 1 and data[2] in (1, 2, 3, 4, 9, 132)

    def dissect(self, data, ctx, idx, offset):
        m, err = parse_M3UA(data)
        if err: return None, 0
        m3ua_idx = idx
        layer = self.create_layer(m, "M3UA", ctx, m3ua_idx, offset, len(data))
        res_layers = [layer]
        
        # 09 80 03 is common SCCP UDT start in many sigtran captures
        sccp_off = data.find(b'\x09\x80\x03')
        if sccp_off != -1:
            sccp_data = data[sccp_off:]
            from handlers.sccp_handler import SCCPDissector
            sccp_dis = SCCPDissector()
            s_layers, _ = sccp_dis.dissect(sccp_data, ctx, m3ua_idx + 1, offset + sccp_off, m3ua_idx)
            if s_layers:
                res_layers.extend(s_layers)
                
        return res_layers, len(data)
