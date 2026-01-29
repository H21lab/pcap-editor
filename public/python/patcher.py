import binascii
import copy
import json
from scapy.packet import Raw, NoPayload
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP
from scapy.layers.sctp import SCTP, SCTPChunkData
from core_utils.pycrate_utils import convert_value
from models import Layer, DissectionResult # Import DissectionResult
from context import DissectionContext # Import DissectionContext

class Patcher:
    @staticmethod
    def apply_edits(dissection_result: DissectionResult, edits: list) -> DissectionContext:
        # We need a deep copy of the layers to modify them
        modified_layers = copy.deepcopy(dissection_result.layers)
        
        # Create a map for quicker access to layers by index
        layer_map = {layer.index: layer for layer in modified_layers}

        for ed in edits:
            target_layer_index = ed['layer_index']
            field_path = ed['field'].split('.')
            new_value_str = ed['value']
            
            if target_layer_index not in layer_map:
                continue # Layer not found, skip edit

            target_layer = layer_map[target_layer_index]
            
            # Mark this layer as edited
            if isinstance(target_layer.val, dict):
                target_layer.val['_edited'] = True
            elif hasattr(target_layer, 'val') and isinstance(target_layer.val, dict): # Check if .val exists and is a dict
                target_layer.val['_edited'] = True


            # Recursively mark parent layers as edited
            for i in range(target_layer_index, -1, -1):
                parent_layer = layer_map[i]
                if isinstance(parent_layer.val, dict):
                    parent_layer.val['_edited'] = True
                elif hasattr(parent_layer, 'val') and isinstance(parent_layer.val, dict):
                    parent_layer.val['_edited'] = True

            # Apply the edit to the target layer's value dictionary
            current_val = target_layer.val # This is the full pythonic dict for the layer
            current_node = current_val # This will be the node we traverse

            # Navigate to the target field using the path
            for i, p_segment in enumerate(field_path):
                is_last_segment = (i == len(field_path) - 1)
                
                # Handle dictionary keys
                if isinstance(current_node, dict):
                    if is_last_segment:
                        current_node[p_segment] = new_value_str # Apply final value
                        break
                    else:
                        if p_segment not in current_node:
                            current_node = None # Stop navigation
                            break
                        current_node = current_node.get(p_segment)
                # Handle list/tuple indices (assuming numeric path segments)
                elif isinstance(current_node, (list, tuple)):
                    try:
                        idx = int(p_segment)
                        if is_last_segment:
                            if isinstance(current_node, list):
                                current_node[idx] = new_value_str
                            else: # Tuple, convert to list, modify, convert back
                                temp_list = list(current_node)
                                temp_list[idx] = new_value_str
                                current_node = tuple(temp_list)
                            break
                        else:
                            current_node = current_node[idx]
                    except (ValueError, IndexError):
                        # Handle cases where list/tuple might contain dicts or specific structures
                        # e.g., pycrate's (type, value) tuples or parameter lists
                        found_next = False
                        if isinstance(current_node, list):
                            for j, item in enumerate(current_node):
                                if isinstance(item, (list, tuple)) and item and str(item[0]) == p_segment: # Compare as string
                                    # This is a (key, value) tuple in a list. We need to replace the value part.
                                    if is_last_segment:
                                        current_node[j] = (item[0], new_value_str) # Replace the value part
                                    else:
                                        current_node = item[1] # Move to the value part
                                    found_next = True
                                    break
                            if not found_next:
                                # Fallback for lists where segment might be a key in a dict within the list
                                for item in current_node:
                                    if isinstance(item, dict) and p_segment in item:
                                        current_node = item
                                        found_next = True
                                        break
                        if not found_next:
                            current_node = None # Stop navigation
                            break # Stop processing this edit
                else:
                    current_node = None # Stop navigation
                    break # Stop processing this edit
            
            if current_node is None:
                pass # Edit not applied due to navigation failure
            else:
                # Ensure the modified layer.val is updated (if it was a sub-element that was replaced)
                target_layer.val = current_val # Reassign in case current_val was modified in place

        # Return a new DissectionContext with the modified layers
        new_ctx = DissectionContext(dissection_result.original_hex_data, dissection_result.pkt_id)
        new_ctx.layers = modified_layers
        return new_ctx
