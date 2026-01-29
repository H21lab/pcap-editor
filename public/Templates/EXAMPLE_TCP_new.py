"""
EXAMPLE: New minimal TCP template using the base class.

Compare this to the old approach which would be ~80 lines with repeated boilerplate.
"""

from scapy_template import create_scapy_template
from scapy.layers.inet import TCP

# Create template with 3 lines instead of 80
_template = create_scapy_template(
    TCP, 'TCP',
    checksum_fields={'chksum'},
)

# Export the standard interface
decode = _template.decode
encode = _template.encode
source_code = _template.source_code
