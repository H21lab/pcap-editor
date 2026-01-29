from pycrate_mobile.TS29060_GTP import parse_GTP
from handlers.base import PycrateDissector
from registry import register_dissector

@register_dissector
class GTPDissector(PycrateDissector):
    def check(self, data, ctx):
        if any(l.lower() in ('gtp', 'gtpv2') for l in ctx.ws_layers): return True
        return len(data) > 8 and (data[0] & 0xF0) in (0x30, 0x40)

    def dissect(self, data, ctx, idx, offset):
        try:
            m, err = parse_GTP(data)
            if err: return None, 0
            layer = self.create_layer(m, "GTP", ctx, idx, offset, data)
            return [layer], len(data)
        except: return None, 0