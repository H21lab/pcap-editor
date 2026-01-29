import sys
import os

# This is the single entry point for the Pyodide environment.
# It ensures that all necessary paths are set up for local imports to work.

def init_paths():
    # Get the directory where this api.py file is located
    # In Pyodide, this will be relative to the root
    core_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Add core and handlers to the path
    if core_dir not in sys.path:
        sys.path.append(core_dir)
    
    handlers_dir = os.path.join(core_dir, 'handlers')
    if handlers_dir not in sys.path:
        sys.path.append(handlers_dir)

# Initialize paths immediately so subsequent imports work
init_paths()

# Now that paths are set, we can import the session manager
from session import session_manager

# The functions remain the same, they are just accessed via the session_manager
def dissect(hex_data, pkt_id, ws_layers_json):
    return session_manager.dissect(hex_data, pkt_id, ws_layers_json)

def edit(original_hex, edits_json, ws_layers_json):
    # Note: ws_layers_json is not used in the current edit logic but kept for API consistency
    pkt_id = original_hex # Use hex as ID if no other ID is available
    return session_manager.edit(pkt_id, edits_json)

def run_script(hex_data, script, ws_layers_json):
    return session_manager.run_script(hex_data, script)
