from typing import List, Dict, Any, Optional
from models import Layer

class DissectionContext:
    def __init__(self, hex_data: str, pkt_id: str, ws_layers: Optional[List[str]] = None):
        self.hex_data = hex_data
        self.pkt_id = pkt_id
        self.ws_layers = ws_layers or []
        self.layers: List[Layer] = []
        # Store metadata for hierarchical reconstruction:
        # idx -> { 'inst': obj, 'offset': int, 'length': int, 'name': str, 'parent_idx': int }
        self.instances: Dict[int, dict] = {}

    def register_instance(self, idx: int, inst: Any, offset: int, length: int, name: str, parent_idx: int = -1):
        self.instances[idx] = {
            'inst': inst, 'offset': offset, 'length': length, 'name': name, 'parent_idx': parent_idx
        }

    def get_instance(self, idx: int) -> Optional[dict]:
        return self.instances.get(idx)