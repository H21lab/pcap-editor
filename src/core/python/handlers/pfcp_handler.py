from pycrate_mobile.TS29244_PFCP import parse_PFCP
from handlers.base import PycrateDissector
from registry import register_dissector

@register_dissector
class PfcpDissector(PycrateDissector):
    def check(self, data, ctx):
        if any(l.lower() == 'pfcp' for l in ctx.ws_layers): return True
        return len(data) > 4 and (data[0] & 0xE0) == 0x20

    def dissect(self, data, ctx, idx, offset):
        try:
            m, err = parse_PFCP(data)
            if err: return None, 0
            layer = self.create_layer(m, "PFCP", ctx, idx, offset)
            return [layer], len(data)
        except: return None, 0
