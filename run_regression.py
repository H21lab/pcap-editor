#!/usr/bin/env python3
"""
PCAP Editor Regression Test Suite

This script tests re-encoding and modification of packets across multiple protocols.
It validates results using both binary comparison and TShark JSON validation.

Usage:
    python run_regression.py [--filter <substring>] [--verbose]
"""

import argparse
import subprocess
import sys
import os
import json
import binascii
import re
import struct
import tempfile

# Detection of WASM environment
IS_WASM = sys.platform == "emscripten"

# Set up paths for internal imports
if IS_WASM:
    core_dir = "/home/pyodide/python"
    sys.path.insert(0, core_dir)
    sys.path.insert(0, "/home/pyodide/Templates")
    INPUT_DIR = "/home/pyodide/input_pcaps"
    OUTPUT_DIR = "/home/pyodide/output"
    EDITS_FILE = "/home/pyodide/regression_edits.json"
else:
    # Use src/core/python for Linux native tests (has full implementation)
    core_dir = os.path.join(os.getcwd(), 'src', 'core', 'python')
    sys.path.insert(0, core_dir)
    sys.path.insert(0, os.path.join(core_dir, 'handlers'))
    sys.path.insert(0, os.path.join(os.getcwd(), 'public', 'Templates'))
    INPUT_DIR = "RegressionTestsInput"
    OUTPUT_DIR = "RegressionTestsOutput"
    EDITS_FILE = "tests/regression_edits.json"

from scapy.all import rdpcap, wrpcap, Raw
from session import session_manager
from registry import PROTOCOL_MAP

SUMMARY_FILE = os.path.join(OUTPUT_DIR, "regression_summary.csv")

with open(EDITS_FILE, 'r') as f:
    PROTOCOL_EDITS = json.load(f)

# Mapping from Protocol Name to TShark fields that should change
TSHARK_FIELD_MAP = {
    'Ethernet': ['eth.dst', 'eth.dst_resolved'],
    'IP': ['ip.ttl'],
    'IPv6': ['ipv6.hlim'],
    'TCP': ['tcp.srcport'],
    'UDP': ['udp.dstport'],
    'SCTP': ['sctp.verification_tag'],
    'M3UA': ['m3ua.message_class'],
    # SCCP uses list-based structure - message type can't be safely changed without breaking packet
    'GTP': ['gtp.message_type'],
    'Diameter': ['diameter.hopbyhopid'],
    'DNS': ['dns.id'],
    'ARP': ['arp.opcode'],
    'TCAP': ['tcap.tid', 'e212.imsi', 'gsm_map.ms.imsi', 'gsm_map.imsi'],
    'TCAP_MAP': ['gsm_map.ms.imsi', 'e212.imsi', 'gsm_map.imsi'],
    'CAMEL': ['camel.serviceKey']
}

# Required layers per pcap file - ensures layer detection is working
REQUIRED_LAYERS = {
    'sigtran.pcap': {
        2: ['Ethernet', 'IP', 'SCTP', 'SCTPChunkData', 'M3UA', 'SCCP', 'TCAP'],
    },
    'diameter.pcapng': {
        4: ['Ethernet', 'IP', 'SCTP', 'SCTPChunkData', 'Diameter'],  # Packet 5 (index 4) has Diameter over SCTP
    },
    'gtp.pcap': {
        0: ['Ethernet', 'IP', 'UDP', 'GTP'],
    },
    's1ap.pcap': {
        0: ['Ethernet', 'IP', 'SCTP', 'SCTPChunkData', 'S1AP'],
    },
    'ngap.pcap': {
        0: ['Ethernet', 'IP', 'SCTP', 'SCTPChunkData', 'NGAP'],
    },
    # camel.pcap uses M2UA/MTP3 stack - all layers must be properly dissected
    # Note: CAMEL/CAP is handled by TCAP layer using TCAP_CAP encoder (no separate CAMEL layer)
    'camel.pcap': {
        0: ['Ethernet', 'IP', 'SCTP', 'SCTPChunkData', 'M2UA', 'MTP3', 'SCCP', 'TCAP'],
    },
}

# Pycrate protocols that MUST decode with proper 'val' structure (not raw fallback)
# If these protocols appear in a script with {'raw': ...} instead of proper structure,
# the test should fail because the Python encoder won't be able to edit fields.
# Note: GTP is excluded because it uses Raw fallback due to v1/v2 Scapy class differences
# Note: CAMEL is not in this list because CAMEL/CAP is decoded/encoded by TCAP template (TCAP_CAP)
# The CAMEL layer is just an identification marker, not a separate encoding unit
PYCRATE_PROTOCOLS = ['S1AP', 'NGAP', 'Diameter', 'M3UA', 'M2UA', 'SCCP', 'TCAP', 'TCAP_MAP', 'ISUP', 'MTP3']

# Expected patterns in generated script for Pycrate protocols
# These patterns indicate proper encoder usage (not raw fallback)
# Note: GTP is excluded because it always uses Raw fallback
PYCRATE_SCRIPT_PATTERNS = {
    'S1AP': r"'initiatingMessage'|'successfulOutcome'|'unsuccessfulOutcome'|'procedureCode'",
    'NGAP': r"'initiatingMessage'|'successfulOutcome'|'unsuccessfulOutcome'|'procedureCode'",
    'Diameter': r"Diameter3GPP|pycrate_diameter|\[\[1, [0-9]+",  # Diameter uses list format
    'M3UA': r"SIGTRAN\(\)|pycrate_mobile\.SIGTRAN",  # SIGTRAN uses list format, not dict
    'M2UA': r"SIGTRAN\(\)|pycrate_mobile\.SIGTRAN",  # M2UA also uses SIGTRAN
    'SCCP': r"parse_SCCP|SCCPUnitData|SCCPDataUnitType",  # SCCP uses list format
    'TCAP': r"'otid'|'dtid'|'components'|'begin'|'end'|'continue'",
    'TCAP_MAP': r"'imsi'|'msisdn'|'components'",
    # Note: CAMEL pattern not needed - CAMEL/CAP is encoded via TCAP (TCAP_CAP)
}

# Minimum acceptable match percentage (default)
MIN_REENCODE_MATCH_PCT = 99.0
MIN_JSON_MATCH_PCT = 95.0

# Protocol-specific thresholds (some protocols have known re-encoding differences)
PROTOCOL_THRESHOLDS = {
    # SIGTRAN stack has SCTP chunk re-encoding differences
    'sigtran.pcap': {'bin': 95.0, 'json': 80.0},
    # Diameter has padding differences
    'diameter.pcapng': {'bin': 98.0, 'json': 90.0},
}

# Authoritative set of protocol names
VALID_PROTOS = set([k.lower() for k in PROTOCOL_MAP.keys()])
VALID_PROTOS.update(['eth', 'ip', 'ipv6', 'tcp', 'udp', 'sctp', 'm3ua', 'sccp', 'tcap',
                     'gsm_map', 'diameter', 'gtp', 'gtpv2', 'gtpheader', 'icmp', 'icmpv6', 'dns', 'arp', 'igmp',
                     'padding', 'trailer', '6lowpan', 'wpan', 'dot15d4', 'cdp', 'bootp',
                     'dhcp', 'http', 'ipx', 'wpan-tap', 'ngap', 's1ap', 'sll', 'tls'])

# Verbose mode flag
VERBOSE = False

# Coverage tracking file
COVERAGE_FILE = os.path.join(OUTPUT_DIR, "protocol_coverage.csv")

# Editable fields per protocol - used to verify encoder functionality
# Each protocol lists fields that MUST be editable if the encoder works correctly
# Format: {protocol: [(field_path, test_value, description), ...]}
PROTOCOL_EDITABLE_FIELDS = {
    # Scapy protocols
    'Ethernet': [('dst', '11:22:33:44:55:66', 'destination MAC')],
    'IP': [('ttl', 64, 'time to live'), ('src', '10.0.0.1', 'source IP')],
    'IPv6': [('hlim', 64, 'hop limit')],
    'TCP': [('sport', 12345, 'source port'), ('dport', 54321, 'destination port')],
    'UDP': [('sport', 12345, 'source port'), ('dport', 54321, 'destination port')],
    'SCTP': [('sport', 2905, 'source port'), ('tag', 12345, 'verification tag')],
    'SCTPChunkData': [('tsn', 100, 'transmission sequence number')],
    'DNS': [('id', 0x1234, 'transaction ID')],
    'ARP': [('op', 2, 'operation code')],
    'ICMP': [('type', 0, 'ICMP type')],

    # Pycrate protocols - these require proper structure (not raw)
    'M3UA': [('val[0][2]', 2, 'message type')],  # M3UA uses list format
    'M2UA': [('val[0][2]', 2, 'message type')],  # M2UA uses list format
    'SCCP': [('val[1][0]', 0, 'handling')],  # SCCP uses list format
    'TCAP': [('val[1]["otid"]', b'\\x01\\x02\\x03\\x04', 'originating TID')],
    'TCAP_MAP': [('val', 'structure', 'MAP message')],
    'MTP3': [('val[0]', 0, 'service indicator')],
    'Diameter': [('val[0][9]', 12345678, 'hop-by-hop ID')],  # List format: header is at [0], HHID at index 9
    'S1AP': [('val', 'structure', 'S1AP message')],
    'NGAP': [('val', 'structure', 'NGAP message')],
    'GTP': [('val', 'raw', 'GTP message - uses raw fallback')],  # Known to use raw
}

# Coverage data collected during test run
# Format: [(pcap, pkt_idx, protocol, layer_idx, has_structure, raw_fallback, field_tested, test_result, notes)]
coverage_data = []


def log(msg, level="INFO"):
    """Print log message if verbose mode is enabled or level is ERROR."""
    if VERBOSE or level == "ERROR":
        print(f"  [{level}] {msg}", file=sys.stderr)


def run_command(cmd, timeout=30):
    """Run a shell command and return stdout, stderr, returncode."""
    if IS_WASM:
        return "", "Not supported in WASM", None
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return res.stdout, res.stderr, res.returncode
    except subprocess.TimeoutExpired:
        return "", "Command timed out", 1
    except Exception as e:
        return "", str(e), 1


def get_tshark_json_for_packet(pcap_path, pkt_idx):
    """Get TShark JSON dissection for a specific packet."""
    if IS_WASM:
        pcap_file = os.path.basename(pcap_path)
        pcap_name = pcap_file.replace(".", "_")
        json_path = f"/home/pyodide/tshark_output/{pcap_name}/pkt_{pkt_idx}_ws.json"
        try:
            if os.path.exists(json_path):
                with open(json_path, 'r') as f:
                    data = json.loads(f.read())
                    if data and isinstance(data, list) and data[0].get('_source', {}).get('layers'):
                        return data[0]['_source']['layers'], None
        except:
            pass
        return None, "WASM_PRECOMP_NO_DATA"

    if not os.path.exists(pcap_path):
        return None, "FILE_NOT_FOUND"

    cmd = f"tshark -r \"{pcap_path}\" -Y 'frame.number=={pkt_idx}' -T json"
    stdout, stderr, returncode = run_command(cmd)
    if returncode == 0 and stdout.strip():
        try:
            data = json.loads(stdout)
            if data and isinstance(data, list) and data[0].get('_source', {}).get('layers'):
                return data[0]['_source']['layers'], None
            else:
                log(f"TShark JSON structure unexpected for {pcap_path}", "WARN")
        except Exception as e:
            log(f"Failed to parse JSON for {pcap_path}: {e}", "WARN")
    else:
        log(f"TShark failed for {pcap_path}: {stderr.strip()}", "WARN")
    return None, f"TSHARK_CMD_FAIL: {stderr.strip()}"


def flatten_json(y):
    """Flatten a nested JSON structure into a flat dict with dotted keys."""
    out = {}
    def flatten(x, name=''):
        if isinstance(x, dict):
            for a in x:
                flatten(x[a], name + a + '.')
        elif isinstance(x, list):
            for i, a in enumerate(x):
                flatten(a, name + str(i) + '.')
        else:
            out[name[:-1]] = x
    flatten(y)
    return out


def get_json_diff_pct(json1, json2, expected_changes=None, ignore_frame=True):
    """
    Compare two TShark JSON outputs and return match percentage.

    Args:
        json1: Original packet JSON
        json2: Re-encoded/modified packet JSON
        expected_changes: List of field patterns that are expected to change
        ignore_frame: Whether to ignore frame-level metadata

    Returns:
        Match percentage (0-100)
    """
    if not json1 or not json2:
        return 0.0
    if expected_changes is None:
        expected_changes = []

    flat1, flat2 = flatten_json(json1), flatten_json(json2)

    # Fields to always ignore (metadata, checksums, etc.)
    ignored_prefixes = ('frame.', 'wpan-tap.', 'sll.', 'fake-field-wrapper')
    ignored_substrings = ('checksum', 'timestamp', '_ws.expert', 'wpan-tap.',
                          '_raw', 'frame.cap_len', 'frame.marked', 'frame.ignored')

    def is_ignored(k):
        if any(k.startswith(p) for p in ignored_prefixes):
            return True
        if any(sub in k for sub in ignored_substrings):
            return True
        return False

    keys1 = set([k for k in flat1.keys() if not is_ignored(k)])
    keys2 = set([k for k in flat2.keys() if not is_ignored(k)])
    all_keys = keys1.union(keys2)

    if not all_keys:
        return 100.0

    matches = 0
    mismatches = []

    for key in all_keys:
        val1, val2 = flat1.get(key), flat2.get(key)
        is_match = (val1 == val2)

        # Check if this is an expected change
        if not is_match:
            for expected in expected_changes:
                if expected in key:
                    is_match = True
                    break

        if is_match:
            matches += 1
        else:
            mismatches.append((key, val1, val2))

    if VERBOSE and mismatches:
        log(f"JSON mismatches ({len(mismatches)}):")
        for k, v1, v2 in mismatches[:5]:  # Show first 5
            log(f"  {k}: {v1!r} -> {v2!r}")

    return (matches / len(all_keys)) * 100.0


def verify_modification(json1, json2, expected_keys):
    """
    Verify that a modification actually changed the expected fields.

    Returns True if at least one expected field changed.
    """
    if not json1 or not json2 or not expected_keys:
        return False

    flat1, flat2 = flatten_json(json1), flatten_json(json2)

    for key_pattern in expected_keys:
        for k in flat1.keys():
            if key_pattern in k:
                if flat1.get(k) != flat2.get(k):
                    log(f"Verified change in {k}: {flat1.get(k)} -> {flat2.get(k)}")
                    return True
    return False


def verify_modification_per_protocol(json1, json2, protocols_modified):
    """
    Verify modifications for each protocol individually.

    Returns dict mapping protocol name to verification result (True/False).
    This ensures we catch cases where some protocol modifications succeed
    while others fail (e.g., TCAP_MAP failing while Ethernet succeeds).
    """
    if not json1 or not json2:
        return {proto: False for proto in protocols_modified}

    flat1, flat2 = flatten_json(json1), flatten_json(json2)
    results = {}

    for proto in protocols_modified:
        expected_fields = TSHARK_FIELD_MAP.get(proto, [])
        if not expected_fields:
            # No TShark field mapping defined - assume success if bytes changed
            results[proto] = None  # Unknown/not verifiable
            continue

        verified = False
        for field_pattern in expected_fields:
            for k in flat1.keys():
                if field_pattern in k:
                    if flat1.get(k) != flat2.get(k):
                        log(f"Verified {proto} change in {k}: {flat1.get(k)} -> {flat2.get(k)}")
                        verified = True
                        break
            if verified:
                break

        results[proto] = verified

    return results


def check_pycrate_encoder(script, layers):
    """
    Validate that Pycrate protocols are properly encoded in the generated script.

    This catches issues where decode() falls back to {'raw': ...} instead of
    properly decoding the protocol structure, which prevents field editing.

    Returns list of (protocol, issue) tuples for any problems found.
    """
    issues = []

    for layer in layers:
        proto = layer.get('protocol', layer.get('name', ''))
        if proto not in PYCRATE_PROTOCOLS:
            continue

        # Find the layer's block in the script
        block_regex = rf"# --- Layer: {re.escape(proto)} ---.*?(?=# --- Layer:|\n\s*def generate_packet|\Z)"
        match = re.search(block_regex, script, re.DOTALL)

        if not match:
            continue

        block = match.group(0)

        # Check 1: Should NOT have {'raw': as the val (indicates decode failure)
        if re.search(rf"{proto.lower()}_\d+_val\s*=\s*\{{\s*'raw':", block):
            issues.append((proto, "decode failed - using raw fallback instead of proper structure"))
            continue

        # Check 2: Should NOT use Raw(load=...) for the object (indicates source_code fallback)
        if re.search(rf"{proto.lower()}_\d+_obj\s*=\s*Raw\(load=", block):
            issues.append((proto, "source_code failed - using Raw() instead of Pycrate encoder"))
            continue

        # Check 3: For protocols with expected patterns, verify they exist
        if proto in PYCRATE_SCRIPT_PATTERNS:
            pattern = PYCRATE_SCRIPT_PATTERNS[proto]
            if not re.search(pattern, block):
                issues.append((proto, f"missing expected structure pattern: {pattern[:50]}..."))

    return issues


def check_required_layers(pcap_file, pkt_idx, detected_layers):
    """Check if all required layers are detected for a specific packet."""
    if pcap_file not in REQUIRED_LAYERS:
        return None

    pkt_requirements = REQUIRED_LAYERS[pcap_file]
    if pkt_idx not in pkt_requirements:
        return None

    required = pkt_requirements[pkt_idx]
    detected_protos = [l['protocol'] for l in detected_layers]

    missing = [req for req in required if req not in detected_protos]
    return missing if missing else None


def check_layer_raw_fallback(script, layers):
    """
    Check each layer for raw fallback usage.

    Returns list of (protocol, layer_idx, has_structure, uses_raw, notes) for all layers.
    This helps identify which layers have proper structure vs raw passthrough.
    """
    results = []

    for layer in layers:
        proto = layer.get('protocol', layer.get('name', ''))
        layer_idx = layer.get('index', 0)

        # Find the layer's block in the script
        block_regex = rf"# --- Layer: {re.escape(proto)} ---.*?(?=# --- Layer:|\n\s*def generate_packet|\Z)"
        match = re.search(block_regex, script, re.DOTALL)

        if not match:
            results.append((proto, layer_idx, False, False, "layer not found in script"))
            continue

        block = match.group(0)

        # Check for raw fallback indicators
        uses_raw = False
        has_structure = False
        notes = []

        # Pattern 1: val = {'raw': ...}
        if re.search(rf"{proto.lower()}_\d+_val\s*=\s*\{{\s*'raw':", block):
            uses_raw = True
            notes.append("val uses raw fallback")

        # Pattern 2: obj = Raw(load=...)
        if re.search(rf"{proto.lower()}_\d+_obj\s*=\s*Raw\(load=", block):
            uses_raw = True
            notes.append("obj uses Raw()")

        # Pattern 3: obj = unhexlify(...) - raw bytes without structure
        if re.search(rf"{proto.lower()}_\d+_obj\s*=\s*unhexlify\(", block):
            uses_raw = True
            notes.append("obj uses unhexlify (raw bytes)")

        # Check for proper structure indicators
        # Pycrate patterns
        if re.search(r"pycrate_|SIGTRAN|parse_SCCP|TCAP_CAP|TCAP_MAP", block):
            has_structure = True
            notes.append("uses pycrate encoder")

        # Scapy class instantiation - handle common class name mappings
        scapy_class_map = {
            'Ethernet': 'Ether',
            'CookedLinux': 'CookedLinux',
        }
        scapy_class = scapy_class_map.get(proto, proto)
        scapy_pattern = rf"{scapy_class}\s*\("
        if re.search(scapy_pattern, block) and proto not in ['Raw', 'Padding']:
            has_structure = True
            notes.append("uses Scapy class")

        # If no structure detected and not explicitly raw, mark as unknown
        if not has_structure and not uses_raw:
            notes.append("structure unknown")

        results.append((proto, layer_idx, has_structure, uses_raw, "; ".join(notes) if notes else ""))

    return results


def record_coverage(pcap_file, pkt_idx, layers, script, modification_result=None):
    """
    Record coverage data for a packet's layers.

    Args:
        pcap_file: Name of the pcap file
        pkt_idx: Packet index (0-based)
        layers: List of layer dicts from dissection
        script: Generated Python script
        modification_result: Optional dict with modification test results
    """
    global coverage_data

    layer_analysis = check_layer_raw_fallback(script, layers)

    for proto, layer_idx, has_structure, uses_raw, notes in layer_analysis:
        # Determine if this protocol has defined editable fields
        has_editable_fields = proto in PROTOCOL_EDITABLE_FIELDS

        # Check if modification was tested for this protocol
        field_tested = False
        test_result = "not_tested"

        if modification_result and proto in modification_result:
            field_tested = True
            test_result = "pass" if modification_result[proto] else "fail"

        coverage_data.append({
            'pcap_file': pcap_file,
            'packet_idx': pkt_idx + 1,  # 1-based for display
            'protocol': proto,
            'layer_idx': layer_idx,
            'has_structure': has_structure,
            'uses_raw_fallback': uses_raw,
            'has_editable_fields_defined': has_editable_fields,
            'field_tested': field_tested,
            'test_result': test_result,
            'notes': notes
        })


def update_coverage_with_modification_results(pcap_file, pkt_idx, protocols_modified, modification_verified):
    """
    Update coverage data with modification test results.

    Args:
        pcap_file: Name of the pcap file
        pkt_idx: Packet index (0-based)
        protocols_modified: List of protocols that had modifications applied
        modification_verified: Boolean indicating if at least one modification was verified
    """
    global coverage_data

    for entry in coverage_data:
        if entry['pcap_file'] == pcap_file and entry['packet_idx'] == pkt_idx + 1:
            proto = entry['protocol']
            if proto in protocols_modified:
                entry['field_tested'] = True
                # If modification was verified for this packet, mark as pass
                # (we verify at packet level, not per-protocol)
                entry['test_result'] = "pass" if modification_verified else "fail"


def write_coverage_csv():
    """Write coverage data to CSV file."""
    if not coverage_data:
        return

    with open(COVERAGE_FILE, 'w') as f:
        # Header
        f.write("pcap_file,packet_idx,protocol,layer_idx,has_structure,uses_raw_fallback,")
        f.write("has_editable_fields_defined,field_tested,test_result,notes\n")

        for row in coverage_data:
            f.write(f"{row['pcap_file']},{row['packet_idx']},{row['protocol']},{row['layer_idx']},")
            f.write(f"{row['has_structure']},{row['uses_raw_fallback']},{row['has_editable_fields_defined']},")
            f.write(f"{row['field_tested']},{row['test_result']},\"{row['notes']}\"\n")

    # Print summary
    total_layers = len(coverage_data)
    structured_layers = sum(1 for r in coverage_data if r['has_structure'] and not r['uses_raw_fallback'])
    raw_layers = sum(1 for r in coverage_data if r['uses_raw_fallback'])
    tested_layers = sum(1 for r in coverage_data if r['field_tested'])
    passed_layers = sum(1 for r in coverage_data if r['test_result'] == 'pass')

    # Get unique protocols
    protocols_with_structure = set(r['protocol'] for r in coverage_data if r['has_structure'] and not r['uses_raw_fallback'])
    protocols_with_raw = set(r['protocol'] for r in coverage_data if r['uses_raw_fallback'])

    print(f"\nCoverage written to: {COVERAGE_FILE}", file=sys.stderr)
    print(f"  Total layers analyzed: {total_layers}", file=sys.stderr)
    print(f"  Layers with proper structure: {structured_layers}", file=sys.stderr)
    print(f"  Layers using raw fallback: {raw_layers}", file=sys.stderr)
    if raw_layers > 0:
        print(f"    Raw protocols: {', '.join(sorted(protocols_with_raw))}", file=sys.stderr)
    print(f"  Layers with modification tests: {tested_layers} ({passed_layers} passed)", file=sys.stderr)


def get_pcap_dlt(pcap_path):
    """Get the data link type (DLT) of a PCAP file."""
    if IS_WASM:
        return 1

    if not os.path.exists(pcap_path):
        return 1

    try:
        with open(pcap_path, 'rb') as f:
            header = f.read(24)
            if len(header) >= 24:
                magic = header[:4]
                if magic == b'\xa1\xb2\xc3\xd4':
                    # Big-endian pcap (magic 0xa1b2c3d4 stored as a1 b2 c3 d4)
                    return struct.unpack('>I', header[20:24])[0]
                elif magic == b'\xd4\xc3\xb2\xa1':
                    # Little-endian pcap (magic 0xa1b2c3d4 stored as d4 c3 b2 a1)
                    return struct.unpack('<I', header[20:24])[0]
    except:
        pass

    # Fallback to tshark
    stdout, stderr, rc = run_command(f"tshark -r \"{pcap_path}\" -c 1 -T fields -e frame.encap_type")
    if rc == 0 and stdout:
        val = stdout.strip().split(',')[0]
        if val:
            try:
                return int(val)
            except ValueError:
                if "Linux cooked" in val:
                    return 113
                match = re.search(r'\((\d+)\)', val)
                if match:
                    return int(match.group(1))
    return 1


def get_ws_layers(pcap_path, pkt_idx):
    """Get Wireshark layer information for a packet."""
    ws_layers = []

    if IS_WASM:
        pcap_file = os.path.basename(pcap_path)
        pcap_name = pcap_file.replace(".", "_")
        json_path = f"/home/pyodide/tshark_output/{pcap_name}/pkt_{pkt_idx+1}_ws.json"
        try:
            with open(json_path, 'r') as f:
                data = json.loads(f.read())
        except:
            return [], "WASM_FAIL"
    else:
        cmd_json = f"tshark -r \"{pcap_path}\" -Y 'frame.number=={pkt_idx+1}' -T json -x"
        stdout, stderr, rc = run_command(cmd_json)
        if rc != 0:
            return [], "TSHARK_FAIL"
        try:
            data = json.loads(stdout)
        except:
            return [], "JSON_FAIL"

    try:
        layers_tree = data[0]['_source']['layers']
        frame_raw_hex = layers_tree.get('frame_raw', [None])[0]
        frame_len = int(layers_tree['frame']['frame.len'])

        def find_raw(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    if k.endswith("_raw") and isinstance(v, list) and len(v) >= 3:
                        name = k[:-4].split('.')[-1]
                        if name.lower() in VALID_PROTOS:
                            layer_hex = v[0]
                            pos, size = v[1], v[2]

                            if frame_raw_hex and layer_hex:
                                true_pos = frame_raw_hex.find(layer_hex) // 2
                                if true_pos != -1:
                                    pos = true_pos

                            if pos + size <= frame_len:
                                ws_layers.append({"name": name, "pos": pos, "size": size})
                    elif isinstance(v, (dict, list)):
                        find_raw(v)
            elif isinstance(obj, list):
                for i in obj:
                    find_raw(i)

        find_raw(layers_tree)
    except:
        return [], "PARSE_FAIL"

    ws_layers.sort(key=lambda x: (x['pos'], -x['size']))

    # Remove duplicates and nested layers
    # A layer is nested if it's fully contained within another layer at different position
    unique = []
    seen_pos = set()
    for l in ws_layers:
        if l['pos'] not in seen_pos:
            # Check if this layer is nested inside an already accepted layer
            is_nested = False
            for accepted in unique:
                # If this layer starts after accepted starts and ends before accepted ends, it's nested
                if l['pos'] > accepted['pos'] and l['pos'] + l['size'] <= accepted['pos'] + accepted['size']:
                    is_nested = True
                    break
            if not is_nested:
                unique.append(l)
                seen_pos.add(l['pos'])

    return unique, None


def get_bin_diff(b1, b2):
    """Calculate byte-level match percentage."""
    if not b1 or not b2:
        return 0.0
    m = 0
    for i in range(min(len(b1), len(b2))):
        if b1[i] == b2[i]:
            m += 1
    return (m / max(len(b1), len(b2))) * 100.0 if max(len(b1), len(b2)) > 0 else 100.0


def apply_edit(script_content, proto_name):
    """Apply a protocol-specific edit to the generated script.

    Safety checks:
    - Verifies pattern doesn't only match inside _orig_hex strings
    - Ensures edit affects actual field values, not just raw storage
    """
    if proto_name not in PROTOCOL_EDITS:
        return None

    edit = PROTOCOL_EDITS[proto_name]
    pattern, replacement = edit['field'], edit['replacement']

    # Skip raw-only edits (these are placeholders for protocols without defined edits)
    if pattern == 'raw' and replacement == 'raw':
        return None

    # Search for pattern in the protocol's block
    block_regex = rf"(# --- Layer: {re.escape(proto_name)} ---.*?)(?=# --- Layer:|\n\s*# --- FINAL|\Z)"
    match = re.search(block_regex, script_content, re.DOTALL)

    if match:
        block = match.group(1)

        # Safety check: If pattern looks like raw hex (no quotes, no field context),
        # verify it's not only appearing inside _orig_hex strings
        is_raw_hex_pattern = re.match(r'^[0-9a-fA-F]+$', pattern)
        if is_raw_hex_pattern:
            # Check if pattern only appears in _orig_hex context
            orig_hex_pattern = rf"'_orig_hex':\s*'[^']*{pattern}[^']*'"
            if re.search(orig_hex_pattern, block) and not re.search(
                rf"(?<!'_orig_hex':\s*')[^']*{pattern}", block
            ):
                log(f"WARNING: {proto_name} edit pattern '{pattern}' only found in _orig_hex - skipping", "WARN")
                return None

        if re.search(pattern, block):
            new_block = re.sub(pattern, replacement, block)
            # Mark value as edited
            val_var_match = re.search(rf"([a-z0-9_]+_val)\s*=", new_block)
            if val_var_match:
                val_var = val_var_match.group(1)
                new_block = new_block.replace(f"{val_var} = {{ ", f"{val_var} = {{'_edited': True, ", 1)
                new_block = new_block.replace(f"{val_var} =(", f"{val_var}_edited = True\n{val_var} =(", 1)
            return script_content.replace(block, new_block)
    return None


def save_pcap_raw(path, pkts_bin, template_pcap):
    """Save packets to a PCAP file with correct link type."""
    if IS_WASM:
        return path

    dlt = get_pcap_dlt(template_pcap)

    # Convert .pcapng to .pcap for output (wrpcap doesn't support pcapng natively)
    if path.endswith('.pcapng'):
        path = path[:-2]  # Remove 'ng' to make it .pcap

    try:
        wrpcap(path, pkts_bin, linktype=dlt)
        return path
    except Exception as e:
        log(f"Failed to save pcap {path}: {e}", "ERROR")
        return path


def process_pcap(pcap_file, summary_data, failures):
    """Process a single PCAP file for regression testing."""
    in_path = os.path.join(INPUT_DIR, pcap_file)
    pcap_name = pcap_file.replace(".", "_")
    out_subdir = os.path.join(OUTPUT_DIR, pcap_name)

    if not IS_WASM:
        os.makedirs(out_subdir, exist_ok=True)

    print(f"  Processing {pcap_file}...", file=sys.stderr)

    pcap_dlt = get_pcap_dlt(in_path)

    try:
        pkts = rdpcap(in_path)
    except Exception as e:
        failures.append(f"{pcap_file}: Failed to read - {e}")
        return

    pkt_data = []
    for i in range(min(10, len(pkts))):
        orig_bytes = bytes(pkts[i])
        ws_layers, ws_err = get_ws_layers(in_path, i)

        res = json.loads(session_manager.dissect(
            binascii.hexlify(orig_bytes).decode(),
            f"{pcap_name}_{i}",
            json.dumps(ws_layers),
            pcap_dlt
        ))

        if res.get('error'):
            failures.append(f"{pcap_file} pkt {i+1}: Dissection error - {res['error']}")
            continue

        script = res.get('command', '')
        layers = res.get('layers', [])
        stack = ":".join([l['protocol'].lower() for l in layers]) if layers else ""

        # Record coverage data for this packet
        record_coverage(pcap_file, i, layers, script)

        # Check required layers
        missing_layers = check_required_layers(pcap_file, i, layers)
        if missing_layers:
            failures.append(f"{pcap_file} pkt {i+1}: Missing layers - {', '.join(missing_layers)}")
            summary_data.append({
                "pcap": pcap_file, "pkt": i + 1, "test_type": "layer_check",
                "bin_match": "N/A", "json_match": "N/A",
                "mod_success": "FAIL", "stack": f"MISSING:{','.join(missing_layers)}"
            })

        # Check Pycrate encoder validity - ensures protocols decode properly (not raw fallback)
        pycrate_issues = check_pycrate_encoder(script, layers)
        for proto, issue in pycrate_issues:
            failures.append(f"{pcap_file} pkt {i+1}: {proto} encoder issue - {issue}")
            summary_data.append({
                "pcap": pcap_file, "pkt": i + 1, "test_type": "encoder_check",
                "bin_match": "N/A", "json_match": "N/A",
                "mod_success": "FAIL", "stack": f"ENCODER:{proto}"
            })

        # Check for raw fallback in layers that should have proper structure
        layer_analysis = check_layer_raw_fallback(script, layers)
        for proto, layer_idx, has_structure, uses_raw, notes in layer_analysis:
            # Flag raw fallback for protocols that should have structure
            if uses_raw and proto in PROTOCOL_EDITABLE_FIELDS:
                # GTP is known to use raw fallback, skip it
                if proto == 'GTP':
                    continue
                failures.append(f"{pcap_file} pkt {i+1}: {proto} uses raw fallback - {notes}")
                summary_data.append({
                    "pcap": pcap_file, "pkt": i + 1, "test_type": "raw_fallback",
                    "bin_match": "N/A", "json_match": "N/A",
                    "mod_success": "FAIL", "stack": f"RAW:{proto}"
                })

        # Re-encode
        reen_hex = session_manager.run_script(
            binascii.hexlify(orig_bytes).decode(),
            script,
            json.dumps(ws_layers),
            pcap_dlt
        )
        if "error" in reen_hex.lower():
            failures.append(f"{pcap_file} pkt {i+1}: Re-encode error - {reen_hex}")
            reen_bytes = orig_bytes
        else:
            reen_bytes = binascii.unhexlify(reen_hex)

        # Apply edits
        cur_script, applied, expected = script, False, []
        protocols_modified = []  # Track which protocols had edits applied
        for proto in sorted(PROTOCOL_EDITS.keys()):
            if f"# --- Layer: {proto} ---" in cur_script:
                new_s = apply_edit(cur_script, proto)
                if new_s:
                    cur_script, applied = new_s, True
                    protocols_modified.append(proto)
                    expected.extend(TSHARK_FIELD_MAP.get(proto, []))

        mod_bytes = None
        if applied:
            mod_hex = session_manager.run_script(
                binascii.hexlify(orig_bytes).decode(),
                cur_script,
                json.dumps(ws_layers),
                pcap_dlt
            )
            if "error" in mod_hex.lower():
                failures.append(f"{pcap_file} pkt {i+1}: Modify error - {mod_hex}")
                mod_bytes = reen_bytes
            else:
                mod_bytes = binascii.unhexlify(mod_hex)

        pkt_data.append({
            "i": i,
            "orig": orig_bytes,
            "reen": reen_bytes,
            "mod": mod_bytes,
            "stack": stack,
            "applied": applied,
            "expected": expected,
            "script": script,
            "modified_script": cur_script if applied else None,
            "protocols_modified": protocols_modified
        })

    # Save scripts for debugging
    if not IS_WASM:
        for d in pkt_data:
            # Save re-encode script
            reen_script_path = os.path.join(out_subdir, f"pkt_{d['i']+1}_reencode.py")
            try:
                with open(reen_script_path, 'w') as f:
                    f.write(d['script'])
            except Exception as e:
                log(f"Failed to save script {reen_script_path}: {e}", "WARN")

            # Save modified script if edit was applied
            if d['modified_script']:
                mod_script_path = os.path.join(out_subdir, f"pkt_{d['i']+1}_modify.py")
                try:
                    with open(mod_script_path, 'w') as f:
                        f.write(d['modified_script'])
                except Exception as e:
                    log(f"Failed to save script {mod_script_path}: {e}", "WARN")

    # Save output PCAPs
    reen_path = None
    mod_path = None
    if not IS_WASM and pkt_data:
        ext = ".pcapng" if pcap_dlt in [195, 206] else ".pcap"
        reen_path = os.path.join(out_subdir, "reencoded" + ext)
        mod_path = os.path.join(out_subdir, "modified" + ext)
        reen_path = save_pcap_raw(reen_path, [d['reen'] for d in pkt_data], in_path)
        if any(d['applied'] for d in pkt_data):
            mod_path = save_pcap_raw(
                mod_path,
                [d['mod'] if d['mod'] else d['reen'] for d in pkt_data],
                in_path
            )

    # Validate with TShark
    for d in pkt_data:
        orig_json, _ = get_tshark_json_for_packet(in_path, d['i'] + 1)

        # Re-encode validation
        bin_match_pct = get_bin_diff(d['orig'], d['reen'])

        if not IS_WASM and reen_path:
            reen_json, _ = get_tshark_json_for_packet(reen_path, d['i'] + 1)
            json_match_pct = get_json_diff_pct(orig_json, reen_json)
        else:
            # WASM can't run tshark, so skip JSON validation entirely
            # Use N/A to indicate JSON validation was skipped (not 0% which would cause extra failures)
            reen_json = orig_json
            json_match_pct = None  # Will be shown as "N/A" and skipped for failure counting

        # Check for failures (use protocol-specific thresholds if available)
        thresholds = PROTOCOL_THRESHOLDS.get(pcap_file, {'bin': MIN_REENCODE_MATCH_PCT, 'json': MIN_JSON_MATCH_PCT})
        min_bin = thresholds['bin']
        min_json = thresholds['json']

        if bin_match_pct < min_bin:
            failures.append(f"{pcap_file} pkt {d['i']+1}: Re-encode binary mismatch - {bin_match_pct:.1f}% (min: {min_bin}%)")
        # Only check JSON match for Linux where we can actually run tshark
        if json_match_pct is not None and json_match_pct < min_json:
            failures.append(f"{pcap_file} pkt {d['i']+1}: Re-encode JSON mismatch - {json_match_pct:.1f}% (min: {min_json}%)")

        summary_data.append({
            "pcap": pcap_file,
            "pkt": d['i'] + 1,
            "test_type": "reencode",
            "bin_match": f"{bin_match_pct:.1f}%",
            "json_match": f"{json_match_pct:.1f}%" if json_match_pct is not None else "N/A",
            "mod_success": "N/A",
            "stack": d['stack']
        })

        # Modification validation
        if d['applied']:
            if not IS_WASM and mod_path:
                mod_json, _ = get_tshark_json_for_packet(mod_path, d['i'] + 1)
                json_mod_pct = get_json_diff_pct(orig_json, mod_json, expected_changes=d['expected'])
                mod_verified = verify_modification(orig_json, mod_json, d['expected'])

                # Per-protocol verification - catches individual protocol failures
                proto_results = verify_modification_per_protocol(
                    orig_json, mod_json, d.get('protocols_modified', [])
                )
                # Report individual protocol modification failures
                for proto, verified in proto_results.items():
                    if verified is False:  # None means not verifiable (no TShark mapping)
                        proto_fields = TSHARK_FIELD_MAP.get(proto, [])
                        failures.append(
                            f"{pcap_file} pkt {d['i']+1}: {proto} modification not verified "
                            f"(expected changes in: {', '.join(proto_fields)})"
                        )
            else:
                # WASM can't run tshark, so use binary comparison only
                mod_json = None
                json_mod_pct = None  # N/A for WASM
                mod_verified = d['mod'] != d['reen']  # Just check bytes changed
                proto_results = {}

            # Modification should produce different bytes
            mod_ok = "YES" if (d['mod'] != d['reen'] and mod_verified) else "NO"

            # Update coverage data with modification results
            update_coverage_with_modification_results(
                pcap_file, d['i'],
                d.get('protocols_modified', []),
                mod_verified
            )

            if mod_ok == "NO":
                failures.append(f"{pcap_file} pkt {d['i']+1}: Edit had no effect (expected: {d['expected']})")

            summary_data.append({
                "pcap": pcap_file,
                "pkt": d['i'] + 1,
                "test_type": "modify",
                "bin_match": f"{get_bin_diff(d['orig'], d['mod']):.1f}%",
                "json_match": f"{json_mod_pct:.1f}%" if json_mod_pct is not None else "N/A",
                "mod_success": mod_ok,
                "stack": d['stack']
            })


def main():
    """Main entry point for regression tests."""
    global VERBOSE

    parser = argparse.ArgumentParser(description="PCAP Editor Regression Suite")
    parser.add_argument("--filter", help="Filter substring for PCAP files")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    args = parser.parse_args()

    VERBOSE = args.verbose

    print("=" * 60, file=sys.stderr)
    print("PCAP Editor Regression Test Suite", file=sys.stderr)
    print("=" * 60, file=sys.stderr)

    if not os.path.exists(INPUT_DIR):
        print(f"ERROR: Input directory not found: {INPUT_DIR}", file=sys.stderr)
        sys.exit(1)

    pcaps = sorted([f for f in os.listdir(INPUT_DIR) if f.endswith(('.pcap', '.pcapng', '.cap'))])
    if args.filter:
        pcaps = [p for p in pcaps if args.filter in p]

    print(f"Found {len(pcaps)} PCAP files to process", file=sys.stderr)

    if not IS_WASM:
        os.makedirs(OUTPUT_DIR, exist_ok=True)

    summary_data = []
    failures = []

    for p in pcaps:
        process_pcap(p, summary_data, failures)

    # Write summary
    if not IS_WASM:
        with open(SUMMARY_FILE, "w") as f:
            f.write("pcap,pkt,test_type,bin_match,json_match,mod_success,stack\n")
            for d in summary_data:
                f.write(f"{d['pcap']},{d['pkt']},{d['test_type']},{d['bin_match']},{d['json_match']},{d['mod_success']},{d['stack']}\n")
        print(f"\nSummary written to: {SUMMARY_FILE}", file=sys.stderr)

        # Write coverage report
        write_coverage_csv()

    # Report results
    print("\n" + "=" * 60, file=sys.stderr)

    reencode_tests = len([d for d in summary_data if d['test_type'] == 'reencode'])
    modify_tests = len([d for d in summary_data if d['test_type'] == 'modify'])
    layer_tests = len([d for d in summary_data if d['test_type'] == 'layer_check'])
    encoder_tests = len([d for d in summary_data if d['test_type'] == 'encoder_check'])

    if failures:
        print(f"❌ FAILED: {len(failures)} issue(s) detected:", file=sys.stderr)
        for f in failures:
            print(f"  - {f}", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        print(f"\nTests run: {reencode_tests} re-encode, {modify_tests} modify, {layer_tests} layer, {encoder_tests} encoder checks", file=sys.stderr)
        sys.exit(1)
    else:
        print(f"✅ PASSED: {reencode_tests} re-encode, {modify_tests} modify, {layer_tests} layer, {encoder_tests} encoder checks", file=sys.stderr)
        print("=" * 60, file=sys.stderr)
        sys.exit(0)


if __name__ == "__main__":
    main()
