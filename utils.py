"""
FinalFinal Utility Functions
Common utilities used across the exploit framework
"""

import os
import sys
import time
import random
import logging
import hashlib
import base64
from datetime import datetime
from pathlib import Path
from typing import Optional, Tuple, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from colorama import Fore, Style, init

import config

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# ============================================================================
# LOGGING SETUP
# ============================================================================

def setup_logging(name: str, log_file: Optional[str] = None) -> logging.Logger:
    """Setup logging with file and console handlers"""
    logger = logging.getLogger(name)
    logger.setLevel(getattr(logging, config.LOG_LEVEL))
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    formatter = logging.Formatter(config.LOG_FORMAT)
    
    # Console handler
    if config.LOG_TO_CONSOLE:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
    
    # File handler
    if config.LOG_TO_FILE:
        log_path = config.LOGS_DIR / (log_file or config.LOG_FILE)
        file_handler = logging.FileHandler(log_path)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

# ============================================================================
# ENCRYPTION UTILITIES
# ============================================================================

def generate_key() -> bytes:
    """Generate a random encryption key"""
    return os.urandom(config.KEY_SIZE)

def generate_iv() -> bytes:
    """Generate a random initialization vector"""
    return os.urandom(config.IV_SIZE)

def encrypt_data(data: bytes, key: bytes = None) -> Tuple[bytes, bytes]:
    """
    Encrypt data using AES-256-GCM
    Returns: (encrypted_data, iv)
    """
    if key is None:
        key = config.DEFAULT_ENCRYPTION_KEY
    
    iv = generate_iv()
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Combine tag with ciphertext
    encrypted = ciphertext + encryptor.tag
    
    return encrypted, iv

def decrypt_data(encrypted_data: bytes, iv: bytes, key: bytes = None) -> bytes:
    """
    Decrypt data using AES-256-GCM
    """
    if key is None:
        key = config.DEFAULT_ENCRYPTION_KEY
    
    # Extract tag (last 16 bytes)
    ciphertext = encrypted_data[:-16]
    tag = encrypted_data[-16:]
    
    cipher = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    
    return plaintext

# ============================================================================
# ENCODING UTILITIES
# ============================================================================

def encode_base64(data: bytes) -> str:
    """Encode bytes to base64 string"""
    return base64.b64encode(data).decode('utf-8')

def decode_base64(data: str) -> bytes:
    """Decode base64 string to bytes"""
    return base64.b64decode(data.encode('utf-8'))

def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string"""
    return data.hex()

def hex_to_bytes(hex_string: str) -> bytes:
    """Convert hex string to bytes"""
    return bytes.fromhex(hex_string)

# ============================================================================
# HASHING UTILITIES
# ============================================================================

def calculate_hash(data: bytes, algorithm: str = 'sha256') -> str:
    """Calculate hash of data"""
    h = hashlib.new(algorithm)
    h.update(data)
    return h.hexdigest()

def verify_hash(data: bytes, expected_hash: str, algorithm: str = 'sha256') -> bool:
    """Verify data hash"""
    actual_hash = calculate_hash(data, algorithm)
    return actual_hash == expected_hash

# ============================================================================
# TIMING UTILITIES
# ============================================================================

def calculate_jitter(interval: int, jitter_percent: int = None) -> int:
    """Calculate jittered interval"""
    if jitter_percent is None:
        jitter_percent = config.JITTER_PERCENT
    
    jitter = interval * (jitter_percent / 100.0)
    return interval + random.randint(-int(jitter), int(jitter))

def sleep_with_jitter(interval: int):
    """Sleep with random jitter"""
    jittered_interval = calculate_jitter(interval)
    time.sleep(jittered_interval)

# ============================================================================
# DISPLAY UTILITIES
# ============================================================================

def print_banner():
    """Print exploit banner"""
    banner = f"""
{Fore.RED}╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║  {Fore.YELLOW}███████╗██╗███╗   ██╗ █████╗ ██╗     ███████╗██╗███╗   ██╗ {Fore.RED}║
║  {Fore.YELLOW}██╔════╝██║████╗  ██║██╔══██╗██║     ██╔════╝██║████╗  ██║ {Fore.RED}║
║  {Fore.YELLOW}█████╗  ██║██╔██╗ ██║███████║██║     █████╗  ██║██╔██╗ ██║ {Fore.RED}║
║  {Fore.YELLOW}██╔══╝  ██║██║╚██╗██║██╔══██║██║     ██╔══╝  ██║██║╚██╗██║ {Fore.RED}║
║  {Fore.YELLOW}██║     ██║██║ ╚████║██║  ██║███████╗██║     ██║██║ ╚████║ {Fore.RED}║
║  {Fore.YELLOW}╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝╚═╝  ╚═══╝ {Fore.RED}║
║                                                               ║
║  {Fore.CYAN}FinalDraft Exploit PoC - For Research Purposes Only{Fore.RED}          ║
║  {Fore.GREEN}Based on Elastic Security Labs Research{Fore.RED}                     ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def print_success(message: str):
    """Print success message"""
    print(f"{Fore.GREEN}[+] {message}{Style.RESET_ALL}")

def print_error(message: str):
    """Print error message"""
    print(f"{Fore.RED}[-] {message}{Style.RESET_ALL}")

def print_info(message: str):
    """Print info message"""
    print(f"{Fore.CYAN}[*] {message}{Style.RESET_ALL}")

def print_warning(message: str):
    """Print warning message"""
    print(f"{Fore.YELLOW}[!] {message}{Style.RESET_ALL}")

# ============================================================================
# SAFETY UTILITIES
# ============================================================================

def confirm_action(action: str) -> bool:
    """Request user confirmation for sensitive actions"""
    if not config.REQUIRE_CONFIRMATION:
        return True
    
    print_warning(f"About to perform: {action}")
    response = input(f"{Fore.YELLOW}Continue? (yes/no): {Style.RESET_ALL}").strip().lower()
    return response in ['yes', 'y']

def check_safety_mode():
    """Verify safety mode is enabled"""
    if not config.RESEARCH_MODE:
        print_error("RESEARCH_MODE is disabled! Exiting for safety.")
        sys.exit(1)
    
    if not config.LOCALHOST_ONLY:
        print_error("LOCALHOST_ONLY is disabled! Exiting for safety.")
        sys.exit(1)
    
    print_success("Safety checks passed - Research mode enabled")

# ============================================================================
# SYSTEM UTILITIES
# ============================================================================

def get_timestamp() -> str:
    """Get current timestamp"""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def get_system_info() -> dict:
    """Get basic system information"""
    return {
        'platform': sys.platform,
        'python_version': sys.version,
        'timestamp': get_timestamp()
    }

def generate_implant_id() -> str:
    """Generate unique implant ID"""
    random_bytes = os.urandom(8)
    return hashlib.sha256(random_bytes).hexdigest()[:16]

# ============================================================================
# FILE UTILITIES
# ============================================================================

def read_file_bytes(filepath: Path) -> bytes:
    """Read file as bytes"""
    with open(filepath, 'rb') as f:
        return f.read()

def write_file_bytes(filepath: Path, data: bytes):
    """Write bytes to file"""
    with open(filepath, 'wb') as f:
        f.write(data)

def file_exists(filepath: Path) -> bool:
    """Check if file exists"""
    return filepath.exists() and filepath.is_file()
