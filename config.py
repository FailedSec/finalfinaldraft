"""
FinalFinal Configuration Module
Configuration settings for the exploit framework
"""

import os
from pathlib import Path

# ============================================================================
# SAFETY SETTINGS - DO NOT MODIFY FOR PRODUCTION RESEARCH
# ============================================================================
RESEARCH_MODE = True  # Always keep True for safety
LOCALHOST_ONLY = True  # Restrict to localhost
SIMULATE_INJECTION = True  # Simulate process injection instead of real
VERBOSE_LOGGING = True  # Enable detailed logging
REQUIRE_CONFIRMATION = True  # Require user confirmation for sensitive ops

# ============================================================================
# C2 SERVER CONFIGURATION
# ============================================================================
C2_HOST = "127.0.0.1"
C2_PORT = 8443
C2_PROTOCOL = "http"  # http or https
C2_ENDPOINT = f"{C2_PROTOCOL}://{C2_HOST}:{C2_PORT}"

# C2 Communication intervals (in seconds)
BEACON_INTERVAL = 60
JITTER_PERCENT = 20  # Random jitter percentage

# ============================================================================
# MS GRAPH API CONFIGURATION (SIMULATED)
# ============================================================================
GRAPH_API_ENABLED = False  # Set to False for safety
GRAPH_API_ENDPOINT = "https://graph.microsoft.com/v1.0"
GRAPH_CLIENT_ID = "DEMO-CLIENT-ID"  # Placeholder
GRAPH_TENANT_ID = "DEMO-TENANT-ID"  # Placeholder
GRAPH_SCOPE = ["Mail.ReadWrite", "Mail.Send"]

# ============================================================================
# ENCRYPTION CONFIGURATION
# ============================================================================
ENCRYPTION_ALGORITHM = "AES-256-GCM"
KEY_SIZE = 32  # 256 bits
IV_SIZE = 16   # 128 bits

# Default encryption key (CHANGE IN PRODUCTION)
DEFAULT_ENCRYPTION_KEY = b"DEMO_KEY_32_BYTES_FOR_RESEARCH!!"

# ============================================================================
# NAMED PIPE CONFIGURATION
# ============================================================================
NAMED_PIPE_PREFIX = "finalfinal_"
PIPE_BUFFER_SIZE = 4096
PIPE_TIMEOUT = 5000  # milliseconds

# ============================================================================
# PROCESS INJECTION CONFIGURATION
# ============================================================================
TARGET_PROCESSES = [
    "mspaint.exe",
    "conhost.exe",
    "notepad.exe"
]

INJECTION_METHOD = "SIMULATE"  # SIMULATE, CreateRemoteThread, QueueUserAPC

# ============================================================================
# NETWORK LISTENER CONFIGURATION
# ============================================================================
TCP_LISTENER_PORT = 4444
UDP_LISTENER_PORT = 5555
LISTENER_BIND_ADDRESS = "127.0.0.1"  # Localhost only for safety

# ============================================================================
# PATHLOADER CONFIGURATION
# ============================================================================
PATHLOADER_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
PATHLOADER_DOWNLOAD_TIMEOUT = 30  # seconds
PATHLOADER_MAX_RETRIES = 3

# ============================================================================
# SHELLCODE CONFIGURATION
# ============================================================================
SHELLCODE_ARCHITECTURE = "x64"  # x86 or x64
SHELLCODE_FORMAT = "raw"  # raw, hex, base64
SHELLCODE_MAX_SIZE = 1024 * 1024  # 1MB

# ============================================================================
# LOGGING CONFIGURATION
# ============================================================================
LOG_LEVEL = "DEBUG" if VERBOSE_LOGGING else "INFO"
LOG_FILE = "finalfinal.log"
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_TO_FILE = True
LOG_TO_CONSOLE = True

# ============================================================================
# PATHS
# ============================================================================
BASE_DIR = Path(__file__).parent
MODULES_DIR = BASE_DIR / "modules"
PAYLOADS_DIR = BASE_DIR / "payloads"
LOGS_DIR = BASE_DIR / "logs"

# Create directories if they don't exist
for directory in [MODULES_DIR, PAYLOADS_DIR, LOGS_DIR]:
    directory.mkdir(exist_ok=True)

# ============================================================================
# COMMAND DEFINITIONS
# ============================================================================
COMMANDS = {
    "BEACON": 0x01,
    "EXECUTE": 0x02,
    "DOWNLOAD": 0x03,
    "UPLOAD": 0x04,
    "INJECT": 0x05,
    "SCREENSHOT": 0x06,
    "KEYLOG": 0x07,
    "PERSIST": 0x08,
    "ELEVATE": 0x09,
    "LATERAL": 0x0A,
    "EXFIL": 0x0B,
    "SLEEP": 0x0C,
    "EXIT": 0xFF
}

# ============================================================================
# SAFETY CHECKS
# ============================================================================
def validate_safety_settings():
    """Validate that safety settings are properly configured"""
    if not RESEARCH_MODE:
        raise ValueError("RESEARCH_MODE must be True for safety")
    
    if not LOCALHOST_ONLY:
        raise ValueError("LOCALHOST_ONLY must be True for safety")
    
    if not SIMULATE_INJECTION:
        raise ValueError("SIMULATE_INJECTION must be True for safety")
    
    if C2_HOST not in ["127.0.0.1", "localhost"]:
        raise ValueError("C2_HOST must be localhost for safety")
    
    return True

# Validate on import
validate_safety_settings()
