"""
FinalFinal Lateral Movement Module
Simulates lateral movement techniques across the network
"""

import sys
from typing import Optional, Dict, List
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

import config
import utils

logger = utils.setup_logging("LateralMovement")


class LateralMovementModule:
    """
    Lateral Movement Module
    Simulates various lateral movement techniques
    """
    
    TECHNIQUES = [
        'PSExec',
        'WMI',
        'WinRM',
        'DCOM',
        'RDP',
        'SMB',
        'ScheduledTask',
        'ServiceCreation'
    ]
    
    def __init__(self):
        """Initialize Lateral Movement module"""
        self.compromised_hosts = []
        logger.info("Lateral Movement module initialized")
    
    def psexec_lateral_movement(self, target: str, username: str, password: str = None, ntlm_hash: str = None) -> bool:
        """
        Lateral movement using PSExec technique
        
        Args:
            target: Target system IP or hostname
            username: Username for authentication
            password: Password (optional)
            ntlm_hash: NTLM hash for pass-the-hash (optional)
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Attempting PSExec lateral movement to {target}")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: PSExec lateral movement")
            
            logger.debug(f"Target: {target}")
            logger.debug(f"Username: {username}")
            
            logger.debug("Step 1: Connecting to ADMIN$ share on target")
            logger.debug("Step 2: Uploading service executable")
            logger.debug("Step 3: Creating and starting service")
            logger.debug("Step 4: Executing payload")
            logger.debug("Step 5: Cleaning up service and files")
            
            self.compromised_hosts.append({
                'target': target,
                'technique': 'PSExec',
                'timestamp': utils.get_timestamp()
            })
            
            utils.print_success(f"Simulated PSExec to {target}")
            return True
        
        logger.error("Real PSExec is disabled for safety")
        return False
    
    def wmi_lateral_movement(self, target: str, username: str, password: str = None, ntlm_hash: str = None) -> bool:
        """
        Lateral movement using WMI
        
        Args:
            target: Target system IP or hostname
            username: Username for authentication
            password: Password (optional)
            ntlm_hash: NTLM hash for pass-the-hash (optional)
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Attempting WMI lateral movement to {target}")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: WMI lateral movement")
            
            logger.debug(f"Target: {target}")
            logger.debug(f"Username: {username}")
            
            logger.debug("Step 1: Connecting to WMI namespace")
            logger.debug("Step 2: Creating Win32_Process instance")
            logger.debug("Step 3: Executing command via WMI")
            logger.debug("Step 4: Monitoring execution")
            
            self.compromised_hosts.append({
                'target': target,
                'technique': 'WMI',
                'timestamp': utils.get_timestamp()
            })
            
            utils.print_success(f"Simulated WMI execution on {target}")
            return True
        
        logger.error("Real WMI execution is disabled for safety")
        return False
    
    def winrm_lateral_movement(self, target: str, username: str, password: str = None) -> bool:
        """
        Lateral movement using WinRM (PowerShell Remoting)
        
        Args:
            target: Target system IP or hostname
            username: Username for authentication
            password: Password
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Attempting WinRM lateral movement to {target}")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: WinRM lateral movement")
            
            logger.debug(f"Target: {target}")
            logger.debug(f"Username: {username}")
            
            logger.debug("Step 1: Establishing WinRM session")
            logger.debug("Step 2: Authenticating with credentials")
            logger.debug("Step 3: Executing PowerShell commands")
            logger.debug("Step 4: Deploying payload")
            
            self.compromised_hosts.append({
                'target': target,
                'technique': 'WinRM',
                'timestamp': utils.get_timestamp()
            })
            
            utils.print_success(f"Simulated WinRM session to {target}")
            return True
        
        logger.error("Real WinRM is disabled for safety")
        return False
    
    def dcom_lateral_movement(self, target: str, username: str, password: str = None) -> bool:
        """
        Lateral movement using DCOM
        
        Args:
            target: Target system IP or hostname
            username: Username for authentication
            password: Password
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Attempting DCOM lateral movement to {target}")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: DCOM lateral movement")
            
            logger.debug(f"Target: {target}")
            logger.debug(f"Username: {username}")
            
            logger.debug("Step 1: Connecting to DCOM object (MMC20.Application)")
            logger.debug("Step 2: Invoking ExecuteShellCommand method")
            logger.debug("Step 3: Executing payload")
            
            self.compromised_hosts.append({
                'target': target,
                'technique': 'DCOM',
                'timestamp': utils.get_timestamp()
            })
            
            utils.print_success(f"Simulated DCOM execution on {target}")
            return True
        
        logger.error("Real DCOM execution is disabled for safety")
        return False
    
    def rdp_lateral_movement(self, target: str, username: str, password: str = None) -> bool:
        """
        Lateral movement using RDP
        
        Args:
            target: Target system IP or hostname
            username: Username for authentication
            password: Password
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Attempting RDP lateral movement to {target}")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: RDP lateral movement")
            
            logger.debug(f"Target: {target}")
            logger.debug(f"Username: {username}")
            
            logger.debug("Step 1: Establishing RDP connection")
            logger.debug("Step 2: Authenticating with credentials")
            logger.debug("Step 3: Executing commands in RDP session")
            logger.debug("Step 4: Deploying payload")
            
            self.compromised_hosts.append({
                'target': target,
                'technique': 'RDP',
                'timestamp': utils.get_timestamp()
            })
            
            utils.print_success(f"Simulated RDP connection to {target}")
            return True
        
        logger.error("Real RDP is disabled for safety")
        return False
    
    def scheduled_task_lateral_movement(self, target: str, username: str, password: str = None) -> bool:
        """
        Lateral movement using Scheduled Tasks
        
        Args:
            target: Target system IP or hostname
            username: Username for authentication
            password: Password
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Attempting Scheduled Task lateral movement to {target}")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: Scheduled Task lateral movement")
            
            logger.debug(f"Target: {target}")
            logger.debug(f"Username: {username}")
            
            logger.debug("Step 1: Connecting to Task Scheduler service")
            logger.debug("Step 2: Creating new scheduled task")
            logger.debug("Step 3: Setting task to run immediately")
            logger.debug("Step 4: Executing payload via task")
            logger.debug("Step 5: Deleting scheduled task")
            
            self.compromised_hosts.append({
                'target': target,
                'technique': 'ScheduledTask',
                'timestamp': utils.get_timestamp()
            })
            
            utils.print_success(f"Simulated Scheduled Task on {target}")
            return True
        
        logger.error("Real Scheduled Task creation is disabled for safety")
        return False
    
    def service_creation_lateral_movement(self, target: str, username: str, password: str = None) -> bool:
        """
        Lateral movement using Service Creation
        
        Args:
            target: Target system IP or hostname
            username: Username for authentication
            password: Password
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Attempting Service Creation lateral movement to {target}")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: Service Creation lateral movement")
            
            logger.debug(f"Target: {target}")
            logger.debug(f"Username: {username}")
            
            logger.debug("Step 1: Connecting to Service Control Manager")
            logger.debug("Step 2: Creating new service")
            logger.debug("Step 3: Starting service")
            logger.debug("Step 4: Executing payload")
            logger.debug("Step 5: Stopping and deleting service")
            
            self.compromised_hosts.append({
                'target': target,
                'technique': 'ServiceCreation',
                'timestamp': utils.get_timestamp()
            })
            
            utils.print_success(f"Simulated Service Creation on {target}")
            return True
        
        logger.error("Real Service Creation is disabled for safety")
        return False
    
    def smb_relay_attack(self, target: str, relay_target: str) -> bool:
        """
        Perform SMB relay attack
        
        Args:
            target: Target to capture authentication from
            relay_target: Target to relay authentication to
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Attempting SMB relay from {target} to {relay_target}")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: SMB relay attack")
            
            logger.debug(f"Capture target: {target}")
            logger.debug(f"Relay target: {relay_target}")
            
            logger.debug("Step 1: Setting up SMB relay listener")
            logger.debug("Step 2: Capturing NTLM authentication")
            logger.debug("Step 3: Relaying authentication to target")
            logger.debug("Step 4: Executing commands on relay target")
            
            utils.print_success(f"Simulated SMB relay to {relay_target}")
            return True
        
        logger.error("Real SMB relay is disabled for safety")
        return False
    
    def pivot_through_host(self, pivot_host: str, target: str) -> bool:
        """
        Use compromised host as pivot point
        
        Args:
            pivot_host: Compromised host to pivot through
            target: Final target system
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Pivoting through {pivot_host} to reach {target}")
        
        if config.SIMULATE_INJECTION:
            logger.info("SIMULATION: Network pivoting")
            
            logger.debug(f"Pivot host: {pivot_host}")
            logger.debug(f"Target: {target}")
            
            logger.debug("Step 1: Establishing connection to pivot host")
            logger.debug("Step 2: Setting up port forwarding/tunneling")
            logger.debug("Step 3: Routing traffic through pivot")
            logger.debug("Step 4: Accessing target through pivot")
            
            utils.print_success(f"Simulated pivot through {pivot_host}")
            return True
        
        logger.error("Real pivoting is disabled for safety")
        return False
    
    def list_compromised_hosts(self) -> List[Dict]:
        """
        List all compromised hosts
        
        Returns:
            List of compromised hosts
        """
        return self.compromised_hosts
    
    def generate_attack_graph(self, output_path: str) -> bool:
        """
        Generate attack graph showing lateral movement
        
        Args:
            output_path: Path to save graph
            
        Returns:
            True if successful, False otherwise
        """
        logger.info(f"Generating attack graph: {output_path}")
        
        try:
            import json
            
            graph = {
                'timestamp': utils.get_timestamp(),
                'compromised_hosts': self.compromised_hosts,
                'techniques_used': list(set([h['technique'] for h in self.compromised_hosts]))
            }
            
            output_file = Path(output_path)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_file, 'w') as f:
                json.dump(graph, f, indent=2)
            
            utils.print_success(f"Attack graph saved to {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to generate attack graph: {e}")
            return False


def demo():
    """Demonstration of lateral movement module"""
    utils.print_banner()
    utils.print_info("Lateral Movement Module Demo")
    
    # Safety check
    utils.check_safety_mode()
    
    lm = LateralMovementModule()
    
    # Test different techniques
    utils.print_info("\n[*] Testing lateral movement techniques:")
    
    # PSExec
    utils.print_info("\n[*] PSExec...")
    lm.psexec_lateral_movement("192.168.1.100", "Administrator", ntlm_hash="aad3b435b51404ee...")
    
    # WMI
    utils.print_info("\n[*] WMI...")
    lm.wmi_lateral_movement("192.168.1.101", "Administrator", password="P@ssw0rd")
    
    # WinRM
    utils.print_info("\n[*] WinRM...")
    lm.winrm_lateral_movement("192.168.1.102", "Administrator", password="P@ssw0rd")
    
    # DCOM
    utils.print_info("\n[*] DCOM...")
    lm.dcom_lateral_movement("192.168.1.103", "Administrator", password="P@ssw0rd")
    
    # Scheduled Task
    utils.print_info("\n[*] Scheduled Task...")
    lm.scheduled_task_lateral_movement("192.168.1.104", "Administrator", password="P@ssw0rd")
    
    # List compromised hosts
    utils.print_info("\n[*] Compromised hosts:")
    for host in lm.list_compromised_hosts():
        print(f"  {host['target']} via {host['technique']} at {host['timestamp']}")


if __name__ == "__main__":
    demo()
