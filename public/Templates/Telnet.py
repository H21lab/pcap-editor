"""
Telnet template.
Parses Telnet data and control sequences.
"""
import binascii
import copy
from utils import safe_repr

# Telnet command codes
IAC = 255  # Interpret As Command
WILL = 251
WONT = 252
DO = 253
DONT = 254
SB = 250  # Subnegotiation Begin
SE = 240  # Subnegotiation End

# Common option codes
OPTION_NAMES = {
    0: 'BINARY',
    1: 'ECHO',
    3: 'SGA',  # Suppress Go Ahead
    5: 'STATUS',
    24: 'TERMINAL_TYPE',
    31: 'WINDOW_SIZE',
    32: 'TERMINAL_SPEED',
    33: 'REMOTE_FLOW_CONTROL',
    34: 'LINEMODE',
    36: 'ENVIRON',
    39: 'NEW_ENVIRON',
}

def decode(hex_data, **kwargs):
    """Decode Telnet data from hex."""
    raw = binascii.unhexlify(hex_data)
    if not raw:
        return {'raw': hex_data, '_orig_hex': hex_data}

    try:
        result = {'_orig_hex': hex_data, 'commands': [], 'data': ''}

        i = 0
        data_bytes = []
        while i < len(raw):
            if raw[i] == IAC and i + 1 < len(raw):
                cmd = raw[i + 1]
                if cmd == IAC:
                    # Escaped IAC
                    data_bytes.append(IAC)
                    i += 2
                elif cmd in (WILL, WONT, DO, DONT) and i + 2 < len(raw):
                    opt = raw[i + 2]
                    cmd_name = {WILL: 'WILL', WONT: 'WONT', DO: 'DO', DONT: 'DONT'}[cmd]
                    opt_name = OPTION_NAMES.get(opt, str(opt))
                    result['commands'].append({'cmd': cmd_name, 'option': opt_name, 'option_code': opt})
                    i += 3
                elif cmd == SB and i + 2 < len(raw):
                    # Find SE
                    se_idx = i + 2
                    while se_idx < len(raw) - 1:
                        if raw[se_idx] == IAC and raw[se_idx + 1] == SE:
                            break
                        se_idx += 1
                    opt = raw[i + 2]
                    sub_data = raw[i + 3:se_idx]
                    opt_name = OPTION_NAMES.get(opt, str(opt))
                    result['commands'].append({
                        'cmd': 'SB',
                        'option': opt_name,
                        'option_code': opt,
                        'data': sub_data.hex()
                    })
                    i = se_idx + 2
                else:
                    i += 2
            else:
                data_bytes.append(raw[i])
                i += 1

        if data_bytes:
            try:
                result['data'] = bytes(data_bytes).decode('utf-8', errors='replace')
            except:
                result['data'] = bytes(data_bytes).hex()

        return result
    except:
        return {'raw': hex_data, '_orig_hex': hex_data}

def encode(val):
    """Encode Telnet data back to hex."""
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
        output = bytearray()

        # Encode commands
        for cmd in val_copy.get('commands', []):
            cmd_name = cmd.get('cmd', '')
            opt_code = cmd.get('option_code', 0)

            output.append(IAC)
            if cmd_name == 'WILL':
                output.append(WILL)
                output.append(opt_code)
            elif cmd_name == 'WONT':
                output.append(WONT)
                output.append(opt_code)
            elif cmd_name == 'DO':
                output.append(DO)
                output.append(opt_code)
            elif cmd_name == 'DONT':
                output.append(DONT)
                output.append(opt_code)
            elif cmd_name == 'SB':
                output.append(SB)
                output.append(opt_code)
                if 'data' in cmd:
                    output.extend(binascii.unhexlify(cmd['data']))
                output.append(IAC)
                output.append(SE)

        # Encode data
        data = val_copy.get('data', '')
        if data:
            if isinstance(data, str):
                try:
                    # Try as hex first
                    output.extend(binascii.unhexlify(data))
                except:
                    # Treat as text
                    output.extend(data.encode('utf-8'))

        return binascii.hexlify(bytes(output)).decode()
    except:
        return orig_hex if orig_hex else ""

def source_code(val, payload_var=None):
    """Generate source code for Telnet packet (no Scapy support, use Raw)."""
    orig_hex = val.get('_orig_hex') or val.get('raw', '')
    if orig_hex:
        code = f"Raw(load=unhexlify('{orig_hex}'))"
        return f"{code} / {payload_var}" if payload_var else code
    return "Raw()"
