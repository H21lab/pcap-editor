from handlers.base import PycrateDissector
from registry import register_dissector, PROTOCOL_METADATA, Provider, PROTOCOL_MAP
import json

PPI_MAP = {
    '3': "M3UA",
    '46': "Diameter",
    '47': "Diameter"
}

@register_dissector
class GenericPycrateDissector(PycrateDissector):
    def __init__(self):
        self.current_msg = None
        self.current_proto = None

    def check(self, data, ctx):
        self.current_msg = None
        self.current_proto = None
        
        # 1. WS Layers Hint - Use PROTOCOL_MAP mapping
        if ctx.ws_layers:
            # Iterate in reverse to catch the most specific protocol
            for layer in reversed(ctx.ws_layers):
                l_lower = layer.lower()
                proto_key = PROTOCOL_MAP.get(l_lower)
                if not proto_key:
                    proto_key = next((k for k in PROTOCOL_METADATA if k.lower() == l_lower), None)
                
                if proto_key and PROTOCOL_METADATA[proto_key]['provider'] == Provider.PYCRATE:
                    if self._verify(data, proto_key): return True
        
        # 2. Context-Aware Heuristics
        parent = ctx.layers[-1] if ctx.layers else None
        if parent:
            if parent.protocol == "SCTPChunkData":
                ppi_field = parent.find_field("proto_id")
                if ppi_field:
                    ppi_val = str(ppi_field.value).split()[0]
                    if ppi_val in PPI_MAP:
                        target = PPI_MAP[ppi_val]
                        if self._verify(data, target): return True

            if parent.name == "SCTP":
                for cand in ["M3UA", "Diameter"]:
                    if self._verify(data, cand): return True
            
            if parent.name == "M3UA":
                if self._verify(data, "SCCP"): return True
            
            if parent.name == "SCCP":
                 for cand in ["TCAP", "TCAP/MAP"]:
                    if self._verify(data, cand): return True

            if parent.name == "UDP":
                if self._verify(data, "GTP"): return True
                if self._verify(data, "GTPv2"): return True
        
        return False

    def _verify(self, data, proto_name):
        try:
            meta = PROTOCOL_METADATA[proto_name]
            local_scope = {}
            exec(meta['import'], {}, local_scope)
            
            cls_path = meta['class']
            parts = cls_path.split(".")
            cls = local_scope.get(parts[0])
            if cls is None:
                # If not in local scope, try global or import it
                try:
                    mod = __import__(meta['import'].split()[3], fromlist=[parts[0]])
                    cls = getattr(mod, parts[0])
                except: return False
            
            for p in parts[1:]:
                if cls is not None:
                    cls = getattr(cls, p)
            
            if cls is None: return False
            
            # If it's a Pycrate class, we instantiate it. 
            # Some like TCAP_MAP_Message are classes, some are objects.
            try:
                msg = cls()
            except:
                msg = cls
                
            if meta.get('method') == 'from_ber':
                msg.from_ber(data)
            else:
                # Version check for GTP to avoid false positives on zeros
                if proto_name == "GTP" and (data[0] >> 5) != 1: return False
                if proto_name == "GTPv2" and (data[0] >> 5) != 2: return False
                msg.from_bytes(data)
            
            val = msg.get_val()
            if val is None: return False
            
            self.current_proto = proto_name
            self.current_msg = msg
            return True
        except Exception: return False

    def dissect(self, data, ctx, idx, offset):
        if not self.current_msg: return None, 0
        
        meta = PROTOCOL_METADATA.get(self.current_proto, {})
        payload_field = meta.get('payload_field')
        
        # Calculate actual bytes consumed
        try:
            total_bytes = self.current_msg.to_ber() if hasattr(self.current_msg, 'to_ber') else self.current_msg.to_bytes()
            
            if payload_field:
                p_len = self._find_payload_len(self.current_msg, payload_field)
                if p_len is not None:
                    consumed = len(total_bytes) - p_len
                else:
                    consumed = len(total_bytes)
            else:
                consumed = len(total_bytes)
        except Exception:
            consumed = len(data)
            
        layer = self.create_layer(self.current_msg, self.current_proto, ctx, idx, offset, consumed)
        return [layer], consumed

    def _find_payload_len(self, msg_obj, field_name):
        """Recursively find the encoded length of a specific field in Pycrate object."""
        if not hasattr(msg_obj, '__iter__') and not hasattr(msg_obj, 'keys'):
            return None
            
        # If it's an envelope/choice/sequence
        try:
            if field_name in msg_obj:
                p_field = msg_obj[field_name]
                p_bytes = p_field.to_ber() if hasattr(p_field, 'to_ber') else p_field.to_bytes()
                return len(p_bytes)
        except: pass

        # Iterate through children
        try:
            items = []
            if hasattr(msg_obj, 'values'): items = msg_obj.values()
            elif hasattr(msg_obj, '__iter__'): items = msg_obj
            
            for sub in items:
                res = self._find_payload_len(sub, field_name)
                if res is not None: return res
        except: pass
        
        return None