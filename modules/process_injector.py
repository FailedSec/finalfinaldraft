"""
FinalFinal Process Injector Module
Simulates process injection techniques used by FinalDraft
"""

import sys
from typing import Optional, List
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import config
import utils

logger = utils.setup_logging("ProcessInjector")


class ProcessInjector:
    """
    Process Injection Module
    Simulates various process injection techniques
    """
    
    INJECTION_TECHNIQUES = [
        'CreateRemoteThread',
        'QueueUserAPC',
        'ProcessHollowing',
        'AtomBombing',
        'ThreadHijacking',
        'ReflectiveDLLInjection'
    ]
    
    def __init__(self):
        """Initialize Process Injector"""
        self.target_processes = config.TARGET_PROCESSES
        logger.info("Process Injector initialized")
    
    def find_target_process(self, process_name: str) -> Optional[int]:
        """
        Find target process by name
        
        Args:
            process_name: Name of the process to find
            
        Returns:
            Process ID or None if not found
        """
        logger.info(f"Searching for process: {process_name}")
        
        if config.SIMULATE_INJECTION:
            logger.info(f"SIMULATION: Found process {process_name} with PID 1234")
            return 1234
        
        # In real scenario, would enumerate processes using:
        # - Windows: CreateToolhelp32Snapshot, Process32First/Next
        # - Or: psutil library
        
        return None
    
    def inject_shellcode(self, pid: int, shellcode: bytes, technique: str = 'CreateRemoteThread') -> bool:
        """
        Inject shellcode into target process
        
        Args:
            pid: Target process ID
            shellcode: Shellcode to inject
            technique: Injection technique to use
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Injecting {len(shellcode)} bytes into PID {pid} using {technique}")
        
        if technique not in self.INJECTION_TECHNIQUES:
            logger.error(f"Unknown injection technique: {technique}")
            return False
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: Process injection simulated")
            
            # Simulate the injection steps
            logger.debug(f"Step 1: Opening process handle for PID {pid}")
            logger.debug(f"Step 2: Allocating {len(shellcode)} bytes in target process")
            logger.debug(f"Step 3: Writing shellcode to allocated memory")
            logger.debug(f"Step 4: Changing memory protection to RX")
            logger.debug(f"Step 5: Creating remote thread at shellcode address")
            logger.debug(f"Step 6: Waiting for thread execution")
            
            utils.print_success(f"Simulated injection into PID {pid}")
            return True
        
        logger.error("Real process injection is disabled for safety")
        return False
    
    def inject_into_target(self, target_name: str, shellcode: bytes) -> bool:
        """
        Find and inject into target process
        
        Args:
            target_name: Target process name
            shellcode: Shellcode to inject
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Attempting injection into {target_name}")
        
        # Find target process
        pid = self.find_target_process(target_name)
        
        if not pid:
            logger.error(f"Target process not found: {target_name}")
            return False
        
        # Inject shellcode
        return self.inject_shellcode(pid, shellcode)
    
    def create_remote_thread_injection(self, pid: int, shellcode: bytes) -> bool:
        """
        CreateRemoteThread injection technique
        
        Args:
            pid: Target process ID
            shellcode: Shellcode to inject
            
        Returns:
            True if successful, False otherwise
        """
        logger.info("Using CreateRemoteThread injection technique")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: CreateRemoteThread injection")
            logger.debug("1. OpenProcess(PROCESS_ALL_ACCESS)")
            logger.debug("2. VirtualAllocEx(MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)")
            logger.debug("3. WriteProcessMemory(shellcode)")
            logger.debug("4. VirtualProtectEx(PAGE_EXECUTE_READ)")
            logger.debug("5. CreateRemoteThread(shellcode_address)")
            return True
        
        return False
    
    def queue_user_apc_injection(self, pid: int, shellcode: bytes) -> bool:
        """
        QueueUserAPC injection technique
        
        Args:
            pid: Target process ID
            shellcode: Shellcode to inject
            
        Returns:
            True if successful, False otherwise
        """
        logger.info("Using QueueUserAPC injection technique")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: QueueUserAPC injection")
            logger.debug("1. OpenProcess(PROCESS_ALL_ACCESS)")
            logger.debug("2. VirtualAllocEx(MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)")
            logger.debug("3. WriteProcessMemory(shellcode)")
            logger.debug("4. VirtualProtectEx(PAGE_EXECUTE_READ)")
            logger.debug("5. Enumerate threads in target process")
            logger.debug("6. OpenThread(THREAD_SET_CONTEXT)")
            logger.debug("7. QueueUserAPC(shellcode_address, thread_handle)")
            return True
        
        return False
    
    def process_hollowing(self, target_path: str, shellcode: bytes) -> bool:
        """
        Process Hollowing injection technique
        
        Args:
            target_path: Path to legitimate executable
            shellcode: Shellcode to inject
            
        Returns:
            True if successful, False otherwise
        """
        logger.info("Using Process Hollowing injection technique")
        
        if config.SIMULATE_INJECTION:
            logger.info(f"SIMULATION: Process Hollowing with {target_path}")
            logger.debug("1. CreateProcess(CREATE_SUSPENDED)")
            logger.debug("2. NtUnmapViewOfSection(unmap original image)")
            logger.debug("3. VirtualAllocEx(allocate memory for shellcode)")
            logger.debug("4. WriteProcessMemory(write shellcode)")
            logger.debug("5. SetThreadContext(set EIP/RIP to shellcode)")
            logger.debug("6. ResumeThread(start execution)")
            return True
        
        return False
    
    def reflective_dll_injection(self, pid: int, dll_path: str) -> bool:
        """
        Reflective DLL Injection technique
        
        Args:
            pid: Target process ID
            dll_path: Path to DLL to inject
            
        Returns:
            True if successful, False otherwise
        """
        logger.info("Using Reflective DLL Injection technique")
        
        if config.SIMULATE_INJECTION:
            logger.info(f"SIMULATION: Reflective DLL Injection of {dll_path}")
            logger.debug("1. Read DLL into memory")
            logger.debug("2. OpenProcess(PROCESS_ALL_ACCESS)")
            logger.debug("3. VirtualAllocEx(allocate memory for DLL)")
            logger.debug("4. WriteProcessMemory(write DLL)")
            logger.debug("5. CreateRemoteThread(ReflectiveLoader)")
            return True
        
        return False


def demo():
    """Demonstration of process injection module"""
    utils.print_banner()
    utils.print_info("Process Injector Module Demo")
    
    # Safety check
    utils.check_safety_mode()
    
    injector = ProcessInjector()
    
    # Demo shellcode
    demo_shellcode = b"DEMO_SHELLCODE_" + b"\x90" * 100
    
    # Test different injection techniques
    utils.print_info("\nTesting injection techniques:")
    
    for technique in ProcessInjector.INJECTION_TECHNIQUES:
        utils.print_info(f"\n{technique}:")
        
        if technique == 'CreateRemoteThread':
            injector.create_remote_thread_injection(1234, demo_shellcode)
        elif technique == 'QueueUserAPC':
            injector.queue_user_apc_injection(1234, demo_shellcode)
        elif technique == 'ProcessHollowing':
            injector.process_hollowing("C:\\Windows\\System32\\notepad.exe", demo_shellcode)
        elif technique == 'ReflectiveDLLInjection':
            injector.reflective_dll_injection(1234, "payload.dll")
        else:
            injector.inject_shellcode(1234, demo_shellcode, technique)


if __name__ == "__main__":
    demo()
