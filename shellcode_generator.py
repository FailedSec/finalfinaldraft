"""
FinalFinal Shellcode Generator
Generates and encrypts shellcode payloads for delivery
"""

import sys
import argparse
from pathlib import Path
from typing import Optional

import config
import utils

logger = utils.setup_logging("ShellcodeGenerator")


class ShellcodeGenerator:
    """
    Shellcode Generator
    Creates encrypted shellcode payloads for the PathLoader stage
    """
    
    def __init__(self, output_path: str, architecture: str = "x64"):
        """
        Initialize Shellcode Generator
        
        Args:
            output_path: Path to save generated shellcode
            architecture: Target architecture (x86 or x64)
        """
        self.output_path = Path(output_path)
        self.architecture = architecture
        
        logger.info(f"Shellcode Generator initialized")
        logger.info(f"Output path: {self.output_path}")
        logger.info(f"Architecture: {self.architecture}")
    
    def generate_demo_shellcode(self) -> bytes:
        """
        Generate demonstration shellcode
        This is a safe, non-functional placeholder for research
        
        Returns:
            Demo shellcode bytes
        """
        logger.info("Generating demonstration shellcode...")
        
        # This is a safe demo payload that doesn't execute anything harmful
        # In a real scenario, this would be actual position-independent shellcode
        
        demo_payload = b"""
        DEMO SHELLCODE - FOR RESEARCH ONLY
        ===================================
        
        This is a demonstration payload that simulates the FinalDraft
        second-stage shellcode. In a real attack scenario, this would be
        position-independent shellcode that:
        
        1. Resolves necessary API functions dynamically
        2. Allocates memory for the final payload
        3. Decrypts and loads the FinalDraft implant
        4. Establishes persistence mechanisms
        5. Initiates C2 communication
        6. Transfers execution to the main implant
        
        Architecture: """ + self.architecture.encode() + b"""
        
        SAFETY NOTE: This is a non-functional demonstration payload.
        Real shellcode execution is disabled in this PoC.
        """
        
        # Add some padding to simulate realistic shellcode size
        padding = b'\x90' * 512  # NOP sled simulation
        
        shellcode = demo_payload + padding
        
        logger.info(f"Generated {len(shellcode)} bytes of demo shellcode")
        
        return shellcode
    
    def generate_finaldraft_loader(self) -> bytes:
        """
        Generate FinalDraft loader shellcode
        This would load and execute the main FinalDraft implant
        
        Returns:
            Loader shellcode bytes
        """
        logger.info("Generating FinalDraft loader shellcode...")
        
        # Simulated loader that would:
        # 1. Resolve kernel32.dll and ntdll.dll functions
        # 2. Allocate RWX memory
        # 3. Download FinalDraft implant from C2
        # 4. Decrypt and load FinalDraft
        # 5. Execute FinalDraft entry point
        
        loader_code = b"""
        [FINALDRAFT LOADER SHELLCODE]
        
        Stage 2 Loader - Responsibilities:
        - API Resolution (GetProcAddress, LoadLibrary)
        - Memory Management (VirtualAlloc, VirtualProtect)
        - Network Communication (WinHTTP/WinINet)
        - Decryption (AES-256-GCM)
        - Execution Transfer
        
        Target Process: mspaint.exe or conhost.exe
        Communication: Named Pipes + MS Graph API
        
        [SIMULATED - NOT ACTUAL SHELLCODE]
        """
        
        return loader_code
    
    def encrypt_shellcode(self, shellcode: bytes) -> tuple:
        """
        Encrypt shellcode for delivery
        
        Args:
            shellcode: Raw shellcode bytes
            
        Returns:
            Tuple of (encrypted_data, iv, key)
        """
        logger.info("Encrypting shellcode...")
        
        # Generate encryption key (in real scenario, this would be shared with C2)
        key = config.DEFAULT_ENCRYPTION_KEY
        
        # Encrypt the shellcode
        encrypted_data, iv = utils.encrypt_data(shellcode, key)
        
        logger.info(f"Encrypted {len(shellcode)} bytes to {len(encrypted_data)} bytes")
        logger.debug(f"IV: {utils.bytes_to_hex(iv)}")
        
        # Calculate hash for integrity verification
        shellcode_hash = utils.calculate_hash(shellcode)
        encrypted_hash = utils.calculate_hash(encrypted_data)
        
        logger.info(f"Original SHA256: {shellcode_hash}")
        logger.info(f"Encrypted SHA256: {encrypted_hash}")
        
        return encrypted_data, iv, key
    
    def save_payload(self, encrypted_data: bytes, iv: bytes) -> bool:
        """
        Save encrypted payload to file
        
        Args:
            encrypted_data: Encrypted shellcode
            iv: Initialization vector
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Saving payload to: {self.output_path}")
        
        try:
            # Create output directory if needed
            self.output_path.parent.mkdir(parents=True, exist_ok=True)
            
            # Combine IV and encrypted data
            payload = iv + encrypted_data
            
            # Write to file
            utils.write_file_bytes(self.output_path, payload)
            
            logger.info(f"Saved {len(payload)} bytes to {self.output_path}")
            
            # Also save metadata
            metadata_path = self.output_path.with_suffix('.meta')
            metadata = f"""Payload Metadata
================
Architecture: {self.architecture}
Payload Size: {len(payload)} bytes
IV Size: {len(iv)} bytes
Encrypted Data Size: {len(encrypted_data)} bytes
Encryption: {config.ENCRYPTION_ALGORITHM}
Generated: {utils.get_timestamp()}
SHA256: {utils.calculate_hash(payload)}
"""
            
            with open(metadata_path, 'w') as f:
                f.write(metadata)
            
            logger.info(f"Saved metadata to {metadata_path}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to save payload: {e}")
            return False
    
    def generate(self, payload_type: str = "demo") -> bool:
        """
        Generate complete encrypted payload
        
        Args:
            payload_type: Type of payload to generate (demo, loader)
            
        Returns:
            True if successful, False otherwise
        """
        utils.print_banner()
        utils.print_info("Starting Shellcode Generator...")
        
        # Safety check
        utils.check_safety_mode()
        
        # Generate shellcode
        if payload_type == "demo":
            utils.print_info("Generating demonstration shellcode...")
            shellcode = self.generate_demo_shellcode()
        elif payload_type == "loader":
            utils.print_info("Generating FinalDraft loader shellcode...")
            shellcode = self.generate_finaldraft_loader()
        else:
            utils.print_error(f"Unknown payload type: {payload_type}")
            return False
        
        utils.print_success(f"Generated {len(shellcode)} bytes of shellcode")
        
        # Encrypt shellcode
        utils.print_info("Encrypting shellcode...")
        encrypted_data, iv, key = self.encrypt_shellcode(shellcode)
        utils.print_success(f"Encrypted to {len(encrypted_data)} bytes")
        
        # Save payload
        utils.print_info(f"Saving payload to {self.output_path}...")
        if self.save_payload(encrypted_data, iv):
            utils.print_success("Payload saved successfully")
            utils.print_info(f"Use with: python pathloader.py --payload {self.output_path}")
            return True
        else:
            utils.print_error("Failed to save payload")
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="FinalFinal Shellcode Generator"
    )
    parser.add_argument(
        '--output',
        '-o',
        default='payloads/payload.bin',
        help="Output file path (default: payloads/payload.bin)"
    )
    parser.add_argument(
        '--type',
        '-t',
        choices=['demo', 'loader'],
        default='demo',
        help="Payload type (default: demo)"
    )
    parser.add_argument(
        '--arch',
        '-a',
        choices=['x86', 'x64'],
        default='x64',
        help="Target architecture (default: x64)"
    )
    parser.add_argument(
        '--verbose',
        '-v',
        action='store_true',
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel("DEBUG")
    
    # Create and run generator
    generator = ShellcodeGenerator(args.output, args.arch)
    success = generator.generate(args.type)
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
