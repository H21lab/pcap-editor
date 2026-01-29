"""
Base template class for protocol encoding/decoding.

All protocol templates should inherit from ProtocolTemplate and override:
- _decode_protocol(raw_bytes) -> dict or None
- _encode_protocol(val_copy) -> bytes or None
- _source_code_protocol(val, payload_var) -> str or None

The base class handles:
- hex <-> bytes conversion
- _orig_hex preservation for unedited packets
- is_edited flag checking
- Fallback to Raw when protocol-specific logic fails
"""

import binascii
import copy


class ProtocolTemplate:
    """Base class for all protocol templates."""

    # Override in subclass
    protocol_name = "Unknown"

    # Fields to exclude from source_code generation
    excluded_fields = {'raw', 'load', 'payload', 'data', '_orig_hex', '_edited'}

    # Fields that are checksums (auto-calculated, should be excluded)
    checksum_fields = {'chksum', 'cksum', 'crc', 'len'}

    def decode(self, hex_data: str) -> dict:
        """
        Decode hex data into a dictionary of fields.
        Returns {'raw': hex_data} as fallback if protocol decode fails.
        """
        if not hex_data:
            return {}

        try:
            raw_bytes = binascii.unhexlify(hex_data)
        except:
            return {'raw': hex_data}

        try:
            result = self._decode_protocol(raw_bytes)
            if result is not None:
                result['_orig_hex'] = hex_data
                return result
        except Exception as e:
            pass

        # Fallback to raw
        return {'raw': hex_data, '_orig_hex': hex_data}

    def encode(self, val: dict) -> str:
        """
        Encode dictionary back to hex string.
        Returns original hex if not edited, or fallback to _orig_hex on failure.
        """
        if not isinstance(val, dict):
            return ""

        # Quick path: raw fallback
        if 'raw' in val and len(val) <= 2:  # only 'raw' and maybe '_orig_hex'
            return val['raw']

        val_copy = copy.deepcopy(val)
        orig_hex = val_copy.pop('_orig_hex', None)
        is_edited = val_copy.pop('_edited', False)

        # If not edited, return original bytes
        if orig_hex and not is_edited:
            return orig_hex

        # Remove computed fields that will be recalculated
        for field in self.checksum_fields:
            val_copy.pop(field, None)

        # Extract payload for later
        payload_hex = self._extract_payload(val_copy)

        try:
            result_bytes = self._encode_protocol(val_copy)
            if result_bytes is not None:
                if payload_hex:
                    result_bytes += binascii.unhexlify(payload_hex)
                return binascii.hexlify(result_bytes).decode()
        except Exception as e:
            pass

        # Fallback to original
        return orig_hex if orig_hex else ""

    def source_code(self, val: dict, payload_var: str = None) -> str:
        """
        Generate Python source code to reconstruct this layer.
        Falls back to Raw(load=unhexlify('...')) if protocol-specific fails.
        """
        try:
            result = self._source_code_protocol(val, payload_var)
            if result is not None:
                return result
        except Exception as e:
            pass

        # Fallback to Raw
        return self._source_code_raw(val, payload_var)

    def _decode_protocol(self, raw_bytes: bytes) -> dict:
        """Override in subclass. Return dict of fields or None to fallback."""
        return None

    def _encode_protocol(self, val_copy: dict) -> bytes:
        """Override in subclass. Return bytes or None to fallback."""
        return None

    def _source_code_protocol(self, val: dict, payload_var: str) -> str:
        """Override in subclass. Return code string or None to fallback."""
        return None

    def _extract_payload(self, val_copy: dict) -> str:
        """Extract and remove payload from val_copy, return as hex string."""
        for key in ['load', 'data', 'payload']:
            if key in val_copy:
                payload = val_copy.pop(key)
                if isinstance(payload, str):
                    return payload
                elif isinstance(payload, bytes):
                    return binascii.hexlify(payload).decode()
        return None

    def _source_code_raw(self, val: dict, payload_var: str) -> str:
        """Generate Raw fallback source code."""
        load_val = val.get('load') or val.get('raw') or val.get('_orig_hex', '')
        if load_val:
            code = f"Raw(load=unhexlify('{load_val}'))"
        else:
            code = "Raw()"

        if payload_var:
            return f"{code} / {payload_var}"
        return code

    def _build_constructor(self, class_name: str, val: dict, payload_var: str = None) -> str:
        """Helper to build Scapy-style constructor code."""
        fields = []
        for k, v in val.items():
            if k in self.excluded_fields or k in self.checksum_fields:
                continue
            fields.append(f"{k}={safe_repr(v)}")

        ctor = f"{class_name}({', '.join(fields)})"
        if payload_var:
            return f"{ctor} / {payload_var}"
        return ctor


def safe_repr(obj):
    """Safe repr that handles bytes, nested structures, etc."""
    try:
        if isinstance(obj, (bytes, bytearray)):
            return f"unhexlify('{binascii.hexlify(obj).decode()}')"
        if isinstance(obj, list):
            return "[" + ", ".join(safe_repr(x) for x in obj) + "]"
        if isinstance(obj, tuple):
            items = [safe_repr(x) for x in obj]
            if len(items) == 1:
                return "(" + items[0] + ",)"
            return "(" + ", ".join(items) + ")"
        if isinstance(obj, dict):
            items = []
            for k in sorted(obj.keys(), key=str):
                items.append(f"{repr(k)}: {safe_repr(obj[k])}")
            return "{" + ", ".join(items) + "}"
        if isinstance(obj, (int, float, bool, type(None))):
            return repr(obj)
        if isinstance(obj, str):
            return repr(obj)
        return repr(str(obj))
    except:
        return repr(str(obj))


# Convenience functions for templates that don't use the class
def decode_raw(hex_data):
    """Simple raw decode fallback."""
    return {"raw": hex_data, "_orig_hex": hex_data}


def encode_raw(val):
    """Simple raw encode fallback."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']
    val_copy = copy.deepcopy(val) if isinstance(val, dict) else {}
    orig_hex = val_copy.get('_orig_hex')
    is_edited = val_copy.get('_edited', False)
    if orig_hex and not is_edited:
        return orig_hex
    return orig_hex if orig_hex else ""


def source_code_raw(val, payload_var=None):
    """Simple raw source_code fallback."""
    load_val = val.get('load') or val.get('raw') or val.get('_orig_hex', '')
    if load_val:
        s = f"Raw(load=unhexlify('{load_val}'))"
    else:
        s = "Raw()"
    if payload_var:
        s += f" / {payload_var}"
    return s
