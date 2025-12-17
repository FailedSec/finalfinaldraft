"""
FinalFinal Modules Package
Additional capabilities for the FinalDraft implant
"""

from pathlib import Path

__version__ = "1.0.0"
__author__ = "Security Research Team"

# Module directory
MODULE_DIR = Path(__file__).parent

# Available modules
AVAILABLE_MODULES = [
    'process_injector',
    'pass_the_hash',
    'network_scanner',
    'credential_dumper',
    'lateral_movement'
]
