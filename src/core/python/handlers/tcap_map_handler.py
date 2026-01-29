from pycrate_asn1dir import TCAP_MAPv2v3
from handlers.base import PycrateDissector
from registry import register_dissector
import copy

@register_dissector
class TcapMapDissector(PycrateDissector):
    def check(self, data, ctx):
        if any(l.lower() in ('tcap', 'map', 'gsm_map') for l in ctx.ws_layers): return True
        return len(data) > 0 and data[0] in (0x62, 0x64, 0x65, 0x67)

    def dissect(self, data, ctx, idx, offset, parent_idx=-1):
        try:
            tcap = TCAP_MAPv2v3.TCAP_MAP_Messages.TCAP_MAP_Message
            tcap.from_ber(data)
            layer = self.create_layer(tcap, "TCAP/MAP", ctx, idx, offset, len(data), parent_idx)
            return [layer], len(data)
        except: return None, 0
