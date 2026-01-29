# Regression Testing Framework

This directory contains the regression testing infrastructure for PCAP Editor.

## Quick Start

1. **Install Python dependencies:**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install scapy pycrate
   ```

2. **Add PCAP files to test:**
   ```bash
   mkdir -p RegressionTestsInput
   # Copy your PCAP files here
   cp /path/to/your/*.pcap RegressionTestsInput/
   ```

3. **Run regression tests:**
   ```bash
   python run_regression.py
   ```

## Test Structure

- `run_regression.py` - Main regression test runner (in project root)
- `tests/regression_edits.json` - Protocol-specific field edit patterns
- `RegressionTestsInput/` - Place PCAP files here (gitignored)
- `RegressionTestsOutput/` - Test results (gitignored)

## What the Tests Do

For each PCAP file:
1. **Re-encode test**: Dissect packet, generate Python script, execute it, compare output binary
2. **Modify test**: Edit specific protocol fields, verify changes are applied correctly

## Configuration

Edit `tests/regression_edits.json` to define test patterns for each protocol:

```json
{
  "Ethernet": {
    "field": "dst='([^']+)'",
    "replacement": "dst='11:22:33:44:55:66'"
  }
}
```

## E2E Tests (Browser)

```bash
npx playwright test
```

## Output

Results are written to:
- `RegressionTestsOutput/regression_summary.csv` - Per-packet test results
- `RegressionTestsOutput/protocol_coverage.csv` - Protocol coverage analysis
