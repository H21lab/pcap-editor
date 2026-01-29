import binascii, string, json
from typing import List, Any
from models import ModelField

def pycrate_to_fields(inst) -> List[ModelField]:
    """Lightweight field extractor for the UI table."""
    fields = []
    
    def safe_str(v):
        if isinstance(v, (bytes, bytearray)):
            return binascii.hexlify(v).decode()
        return str(v)

    try:
        val = inst.get_val()
        if isinstance(val, dict):
            # Diameter/TCAP/MAP often return dicts
            count = 0
            for k, v in val.items():
                if count > 20: break
                if not isinstance(v, (list, dict)):
                    fields.append(ModelField(name=str(k), value=safe_str(v), type=type(v).__name__))
                    count += 1
        elif isinstance(val, list) and len(val) >= 1:
            header = val[0]
            if isinstance(header, list):
                for i, v in enumerate(header[:10]):
                    if not isinstance(v, (list, dict)):
                        fields.append(ModelField(name=f"Hdr[{i}]", value=safe_str(v), type=type(v).__name__))
    except: pass
    
    return fields

def convert_value(node_type: str, raw_value: str) -> Any:
    return raw_value