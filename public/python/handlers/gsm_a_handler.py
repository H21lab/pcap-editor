from handlers.base import PycrateDissector
from registry import register_dissector, PROTOCOL_METADATA
import copy

@register_dissector
class GsmAHandler(PycrateDissector):
    def check(self, data, ctx):
        return any(l.lower() in ('gsm_a.dtap', 'bssmap', 'bssap') for l in ctx.ws_layers)

    def dissect(self, data, ctx, idx, offset):
        for wl in ctx.ws_layers:
            proto_name = wl.upper().replace('_', '-').replace('GSM-A.DTAP', 'BSSAP')
            if "DTAP" in wl.upper(): proto_name = "BSSAP" # Pycrate handles via BSSMAP/BSSAP usually
            
            if proto_name in PROTOCOL_METADATA:
                meta = PROTOCOL_METADATA[proto_name]
                try:
                    exec(meta['import'], globals())
                    cls_parts = meta['class'].split('.')
                    obj = globals().get(cls_parts[0])
                    for p in cls_parts[1:]: obj = getattr(obj, p)
                    
                    inst = obj()
                    inst.from_bytes(data)
                    
                    layer = self.create_layer(inst, proto_name, ctx, idx, offset)
                    return [layer], len(data)
                except:
                    continue
        return None, 0