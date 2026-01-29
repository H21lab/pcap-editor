"""
Helper for creating Scapy-based protocol templates with minimal boilerplate.

Usage:
    # In your template file:
    from scapy_template import create_scapy_template
    from scapy.layers.inet import TCP

    template = create_scapy_template(TCP, 'TCP', checksum_fields={'chksum'})
    decode = template.decode
    encode = template.encode
    source_code = template.source_code
"""

import binascii
import copy
from base import ProtocolTemplate, safe_repr


class ScapyTemplate(ProtocolTemplate):
    """Template for Scapy-based protocols."""

    def __init__(self, scapy_class, class_name: str,
                 checksum_fields: set = None,
                 bytes_fields: set = None,
                 excluded_fields: set = None):
        """
        Args:
            scapy_class: The Scapy packet class (e.g., TCP, UDP)
            class_name: String name for source_code generation
            checksum_fields: Fields that are auto-calculated (excluded from encode)
            bytes_fields: Fields that need unhexlify in source_code
            excluded_fields: Additional fields to exclude
        """
        self.scapy_class = scapy_class
        self.class_name = class_name
        self.protocol_name = class_name

        if checksum_fields:
            self.checksum_fields = self.checksum_fields | checksum_fields
        if excluded_fields:
            self.excluded_fields = self.excluded_fields | excluded_fields

        self.bytes_fields = bytes_fields or set()

    def _decode_protocol(self, raw_bytes: bytes) -> dict:
        """Decode using Scapy class."""
        pkt = self.scapy_class(raw_bytes)
        val = {}

        for f in pkt.fields_desc:
            v = pkt.getfieldval(f.name)
            if isinstance(v, bytes):
                val[f.name] = v.hex()
            elif isinstance(v, list):
                # Handle list fields (like options)
                val[f.name] = self._serialize_list(v)
            else:
                val[f.name] = v

        # Handle payload
        if pkt.payload and bytes(pkt.payload):
            val['load'] = binascii.hexlify(bytes(pkt.payload)).decode()

        return val

    def _encode_protocol(self, val_copy: dict) -> bytes:
        """Encode using Scapy class."""
        # Convert hex strings back to bytes for bytes fields
        for field in self.bytes_fields:
            if field in val_copy and isinstance(val_copy[field], str):
                try:
                    val_copy[field] = binascii.unhexlify(val_copy[field])
                except:
                    pass

        pkt = self.scapy_class(**val_copy)
        return bytes(pkt)

    def _source_code_protocol(self, val: dict, payload_var: str) -> str:
        """Generate Scapy constructor code."""
        fields = []

        for k, v in val.items():
            if k in self.excluded_fields or k in self.checksum_fields:
                continue

            # Handle bytes fields
            if k in self.bytes_fields and isinstance(v, str):
                fields.append(f"{k}=unhexlify('{v}')")
            else:
                fields.append(f"{k}={safe_repr(v)}")

        ctor = f"{self.class_name}({', '.join(fields)})"
        if payload_var:
            return f"{ctor} / {payload_var}"
        return ctor

    def _serialize_list(self, lst):
        """Serialize a list field (e.g., options)."""
        result = []
        for item in lst:
            if hasattr(item, 'fields_desc'):
                # It's a Scapy packet/layer
                item_dict = {}
                for f in item.fields_desc:
                    v = item.getfieldval(f.name)
                    if isinstance(v, bytes):
                        item_dict[f.name] = v.hex()
                    else:
                        item_dict[f.name] = v
                result.append(item_dict)
            elif isinstance(item, tuple):
                result.append(tuple(
                    x.hex() if isinstance(x, bytes) else x for x in item
                ))
            elif isinstance(item, bytes):
                result.append(item.hex())
            else:
                result.append(item)
        return result


def create_scapy_template(scapy_class, class_name: str, **kwargs) -> ScapyTemplate:
    """
    Factory function to create a Scapy template.

    Args:
        scapy_class: The Scapy packet class
        class_name: String name for the class
        **kwargs: Additional options (checksum_fields, bytes_fields, etc.)

    Returns:
        ScapyTemplate instance with decode, encode, source_code methods
    """
    return ScapyTemplate(scapy_class, class_name, **kwargs)


# Example of how a minimal template would look:
"""
# Templates/TCP_minimal.py
from scapy_template import create_scapy_template
from scapy.layers.inet import TCP

_template = create_scapy_template(
    TCP, 'TCP',
    checksum_fields={'chksum'},
    bytes_fields={'options'}
)

decode = _template.decode
encode = _template.encode
source_code = _template.source_code
"""
