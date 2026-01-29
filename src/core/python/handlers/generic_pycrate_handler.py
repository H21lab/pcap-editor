import copy
from handlers.base import PycrateDissector
from registry import register_dissector, PROTOCOL_METADATA

@register_dissector
class GenericPycrateDissector(PycrateDissector):
    """Fallback dissector that uses PROTOCOL_METADATA to handle any registered protocol."""
    
    def check(self, data, ctx):
        if not ctx.ws_layers: return False
        return any(l.upper() in PROTOCOL_METADATA for l in ctx.ws_layers)

    def dissect(self, data, ctx, idx, offset):
        for wl in ctx.ws_layers:
            proto_name = wl.upper().replace('_', '-')
            # Only proceed if the hinted protocol is one we handle via Pycrate
            if proto_name in PROTOCOL_METADATA and PROTOCOL_METADATA[proto_name]['provider'] == Provider.PYCRATE:
                try:
                    meta = PROTOCOL_METADATA[proto_name]
                    # Execute import if needed
                    exec(meta['import'], globals())
                    
                    # Initialize class
                    cls_parts = meta['class'].split('.')
                    if len(cls_parts) > 1:
                        mod_name = cls_parts[0]
                        mod = globals().get(mod_name)
                        obj = mod
                        for part in cls_parts[1:]:
                            obj = getattr(obj, part)
                        inst = copy.deepcopy(obj)
                    else:
                        cls = globals().get(meta['class'])
                        inst = cls()
                    
                    # Parse binary
                    parse_method = getattr(inst, meta['method'])
                    parse_method(data)
                    
                    # Create layer - registration happens here
                    layer = self.create_layer(inst, proto_name, ctx, idx, offset, len(data))
                    return [layer], len(data)
                except:
                    continue 
                    
        return None, 0