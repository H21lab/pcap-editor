from models import Layer
from core_utils.pycrate_utils import pycrate_to_fields

class PycrateDissector:
    def create_layer(self, inst, name, ctx, idx, offset, length, parent_idx=-1):
        # Ensure length is an integer (diagnostic showed bytes were being passed)
        if isinstance(length, (bytes, bytearray)):
            safe_length = len(length)
        else:
            safe_length = int(length)

        l = Layer(
            index=idx,
            name=f"{name} (Pycrate)",
            protocol=name,
            fields=pycrate_to_fields(inst),
            offset=int(offset),
            length=safe_length,
            source="pycrate"
        )
        ctx.register_instance(idx, inst, int(offset), safe_length, name, parent_idx)
        return l