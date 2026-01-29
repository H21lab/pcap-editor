"""
SSH (Secure Shell) template.
Parses SSH protocol messages (version exchange, key exchange, etc.)
Note: Encrypted payload cannot be decoded without keys.
"""
import binascii
import copy
from utils import safe_repr

def decode(hex_data, **kwargs):
    """Decode SSH message from hex."""
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        result = {'_orig_hex': hex_data}

        # Check for version string (plaintext at start of connection)
        if raw.startswith(b'SSH-'):
            try:
                text = raw.decode('utf-8', errors='replace').strip()
                result['type'] = 'version_exchange'
                parts = text.split('-', 2)
                if len(parts) >= 3:
                    result['protocol'] = parts[0]  # SSH
                    result['version'] = parts[1]    # 2.0 or 1.99
                    # Third part may contain software info and comments
                    remaining = parts[2]
                    if '\r\n' in remaining:
                        remaining = remaining.split('\r\n')[0]
                    result['software'] = remaining
                return result
            except:
                pass

        # Binary SSH packet format
        if len(raw) >= 5:
            packet_length = int.from_bytes(raw[0:4], 'big')
            padding_length = raw[4]

            result['type'] = 'binary_packet'
            result['packet_length'] = packet_length
            result['padding_length'] = padding_length

            if len(raw) >= 6:
                msg_type = raw[5]
                result['message_type'] = msg_type

                # Common message types
                MSG_TYPES = {
                    1: 'SSH_MSG_DISCONNECT',
                    2: 'SSH_MSG_IGNORE',
                    3: 'SSH_MSG_UNIMPLEMENTED',
                    4: 'SSH_MSG_DEBUG',
                    5: 'SSH_MSG_SERVICE_REQUEST',
                    6: 'SSH_MSG_SERVICE_ACCEPT',
                    20: 'SSH_MSG_KEXINIT',
                    21: 'SSH_MSG_NEWKEYS',
                    30: 'SSH_MSG_KEX_DH_GEX_REQUEST_OLD',
                    31: 'SSH_MSG_KEX_DH_GEX_REQUEST',
                    32: 'SSH_MSG_KEX_DH_GEX_GROUP',
                    33: 'SSH_MSG_KEX_DH_GEX_INIT',
                    34: 'SSH_MSG_KEX_DH_GEX_REPLY',
                    50: 'SSH_MSG_USERAUTH_REQUEST',
                    51: 'SSH_MSG_USERAUTH_FAILURE',
                    52: 'SSH_MSG_USERAUTH_SUCCESS',
                    80: 'SSH_MSG_GLOBAL_REQUEST',
                    90: 'SSH_MSG_CHANNEL_OPEN',
                    91: 'SSH_MSG_CHANNEL_OPEN_CONFIRMATION',
                    94: 'SSH_MSG_CHANNEL_DATA',
                }
                result['message_type_name'] = MSG_TYPES.get(msg_type, f'UNKNOWN_{msg_type}')

            # Store payload as hex (likely encrypted)
            if len(raw) > 6:
                result['payload'] = raw[6:].hex()

        return result
    except:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode SSH message back to hex."""
    if isinstance(val, dict) and 'raw' in val:
        return val['raw']

    val_copy = copy.deepcopy(val)
    orig_hex = val_copy.pop('_orig_hex', None)
    orig_bytes = val_copy.pop('_orig_bytes', None)
    is_edited = val_copy.pop('_edited', False)

    if not is_edited:
        if orig_bytes: return orig_bytes
        if orig_hex: return orig_hex

    try:
        msg_type = val_copy.get('type', '')

        if msg_type == 'version_exchange':
            version = val_copy.get('version', '2.0')
            software = val_copy.get('software', 'OpenSSH_8.0')
            text = f"SSH-{version}-{software}\r\n"
            return binascii.hexlify(text.encode('utf-8')).decode()

        elif msg_type == 'binary_packet':
            # Reconstruct binary packet (without recalculating MAC)
            output = bytearray()
            packet_length = val_copy.get('packet_length', 0)
            padding_length = val_copy.get('padding_length', 0)
            message_type = val_copy.get('message_type', 0)

            output.extend(packet_length.to_bytes(4, 'big'))
            output.append(padding_length)
            output.append(message_type)

            payload = val_copy.get('payload', '')
            if payload:
                output.extend(binascii.unhexlify(payload))

            return binascii.hexlify(bytes(output)).decode()

        return orig_hex if orig_hex else ""
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    # SSH encrypted data can't be meaningfully reconstructed field-by-field
    # Use raw load approach
    from utils import source_code_raw
    return source_code_raw(val, payload_var)
