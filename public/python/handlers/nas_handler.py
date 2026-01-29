from pycrate_mobile.NAS5G import parse_NAS5G
from pycrate_mobile.NASLTE import parse_NASLTE_MO
from handlers.base import PycrateDissector
from registry import register_dissector

@register_dissector
class NasDissector(PycrateDissector):
    def check(self, data, ctx):
        return any(l.lower() in ('nas_5gs', 'nas-5gs', 'nas_eps', 'nas-eps', 'nas') for l in ctx.ws_layers)

    def dissect(self, data, ctx, idx, offset):
        try:
            m = None
            err = None
            proto_name = "NAS"
            
            if any('5gs' in l.lower() for l in ctx.ws_layers):
                m, err = parse_NAS5G(data)
                proto_name = "NAS-5GS"
            else:
                m, err = parse_NASLTE_MO(data)
                proto_name = "NAS-EPS"
                
            if m and not err:
                layer = self.create_layer(m, proto_name, ctx, idx, offset)
                return [layer], len(data)
        except: pass
        return None, 0
