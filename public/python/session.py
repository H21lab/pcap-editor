import json, binascii
from engine import DissectionEngine
from patcher import Patcher
from models import DissectionResult
from runner import ScriptRunner
from registry import get_dissectors, load_handlers

class SessionManager:
    def __init__(self):
        load_handlers()
        self.dissectors = [cls() for cls in get_dissectors()]
        self.engine = DissectionEngine(self.dissectors)
        self.contexts = {}

    def dissect(self, hex_data: str, pkt_id: str, ws_layers_json: str = "[]", wpan_dlt: int = 1, debug_mode: bool = False) -> str:
        try:
            ws_layers = json.loads(ws_layers_json)
        except:
            ws_layers = []
        result = self.engine.dissect(hex_data, pkt_id, ws_layers, wpan_dlt, debug_mode)
        self.contexts[pkt_id] = result.layers
        return result.to_json()

    def edit(self, pkt_id: str, edits_json: str) -> str:
        ctx = self.contexts.get(pkt_id)
        if not ctx: 
            return json.dumps({"error": "Session not found for edit"})
        try:
            edits = json.loads(edits_json)
            new_bytes = Patcher.apply_edits(ctx, edits)
            return binascii.hexlify(new_bytes).decode('ascii')
        except Exception as e:
            return json.dumps({"error": str(e)})
    
    def run_script(self, hex_data: str, script: str, ws_layers_json: str = "[]", wpan_dlt: int = 1, debug_mode: bool = False) -> str:
        try:
            new_bytes = ScriptRunner.run(hex_data, script, ws_layers_json, wpan_dlt)
            return binascii.hexlify(new_bytes).decode('ascii')
        except Exception as e:
            import traceback
            return json.dumps({"error": str(e), "trace": traceback.format_exc()})

session_manager = SessionManager()