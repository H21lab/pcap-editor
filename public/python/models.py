import json
import copy

def _fix_serializable(obj):
    """
    Recursively convert bytes/bytearrays to hex strings and other non-serializable objects
    to strings to ensure JSON compatibility.
    """
    if isinstance(obj, (bytes, bytearray)):
        return obj.hex()
    
    if isinstance(obj, dict):
        return { (k.hex() if isinstance(k, (bytes, bytearray)) else str(k)): _fix_serializable(v) for k, v in obj.items() }
    
    if isinstance(obj, list):
        return [_fix_serializable(item) for item in obj]
    
    if isinstance(obj, (int, float, bool, type(None))):
        return obj

    # For everything else, attempt string conversion
    try:
        json.dumps(obj)
        return obj
    except (TypeError, OverflowError):
        try:
            s = str(obj)
            if isinstance(s, bytes):
                return s.decode('utf-8', errors='replace')
            return s
        except Exception:
            return repr(obj)

class ModelField:
    def __init__(self, name, val, type_name="StrField", offset=0, length=0):
        self.name = name
        self.val = val
        self.type_name = type_name
        self.offset = offset
        self.length = length

    def to_dict(self):
        return {
            "name": self.name,
            "val": _fix_serializable(self.val),
            "type": self.type_name,
            "offset": self.offset,
            "length": self.length
        }

class Layer:
    def __init__(self, protocol, index, offset, length, name=None, fields=None):
        self.protocol = protocol
        self.index = index
        self.offset = offset
        self.length = length
        self.name = name or protocol
        self.fields = fields or []
        self.val = {}

    def to_dict(self):
        return {
            "protocol": self.protocol,
            "name": self.name,
            "index": self.index,
            "offset": self.offset,
            "length": self.length,
            "val": _fix_serializable(self.val),
            "fields": [f.to_dict() for f in self.fields]
        }

class DissectionResult:
    def __init__(self, layers, command=""):
        self.layers = layers
        self.command = command

    def to_json(self):
        return json.dumps({
            "layers": [l.to_dict() for l in self.layers],
            "command": self.command
        })
