import copy
from handlers.base import PycrateDissector
from registry import register_dissector, PROTOCOL_METADATA

@register_dissector
class ApDissector(PycrateDissector):
    def check(self, data, ctx):
        # Broad check for most common Access/Application Protocols
        ap_keywords = ['s1ap', 'ngap', 'x2ap', 'f1ap', 'e1ap', 'ranap', 'bssmap', 'bssap']
        return any(k in l.lower() for k in ap_keywords for l in ctx.ws_layers)

    def dissect(self, data, ctx, idx, offset):
        for wl in ctx.ws_layers:
            # Normalize name for registry lookup (e.g. RANAP, S1AP)
            proto_name = wl.upper().replace('_', '-')
            if proto_name in PROTOCOL_METADATA:
                meta = PROTOCOL_METADATA[proto_name]
                if meta.get('is_asn1'):
                    try:
                        # Execute import
                        exec(meta['import'], globals())
                        # Get class
                        cls_path = meta['class'].split('.')
                        obj = globals().get(cls_path[0])
                        for p in cls_path[1:]: obj = getattr(obj, p)
                        
                        inst = copy.deepcopy(obj)
                        inst.from_ber(data)
                        
                        layer = self.create_layer(inst, proto_name, ctx, idx, offset)
                        return [layer], len(data)
                    except:
                        continue # Try next hint
        return None, 0
