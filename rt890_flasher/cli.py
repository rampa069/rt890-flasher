#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Command-line interface for RT-890 Flasher.
"""

import os
import sys
import time
import argparse
import serial.tools.list_ports
from .flasher import RT890Flasher

def list_serial_ports():
    """List available serial ports."""
    ports = list(serial.tools.list_ports.comports())
    
    if not ports:
        print("No serial ports found.")
        return
    
    print("Available serial ports:")
    print("Port\t\tHardware ID\t\tDescription")
    print("-" * 80)
    for port in ports:
        # Format the output more clearly
        device = port.device
        # Pad device name for nicer formatting
        if len(device) < 8:
            device = f"{device}\t"
            
        print(f"{device}\t{port.hwid}\t{port.description}")

def print_banner():
    """Print the application banner."""
    print("RT-890 Firmware Flasher CLI")
    print("===========================")
    print("Python version with improved flash method")
    print(f"Current time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("")

def print_debug_info():
    """Print debug information."""
    print(f"Python version: {sys.version}")
    print(f"Serial version: {serial.__version__}")
    print(f"Operating system: {os.name} - {sys.platform}")
    print("")

def flash_command():
    """Command-line interface for flashing firmware."""
    parser = argparse.ArgumentParser(
        description="Flash firmware to the RT-890 radio.",
        epilog="First, put your radio in flashing mode by turning it on while pressing both Side-Keys."
    )
    
    parser.add_argument('port', nargs='?', help='Serial port where the radio is connected')
    parser.add_argument('firmware', nargs='?', help='File containing the firmware')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output with protocol debugging')
    parser.add_argument('-s', '--slow', action='store_true', help='Use slow baud rate (19200)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable extra debugging information')
    parser.add_argument('-l', '--list', action='store_true', help='List available serial ports')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # If debug mode enabled, print additional info
    if args.debug:
        print_debug_info()
    
    # List ports if requested
    if args.list:
        list_serial_ports()
        return
    
    # Check required arguments
    if not args.port or not args.firmware:
        parser.print_help()
        return
    
    # Execute flash command
    try:
        with RT890Flasher(args.port, args.verbose, args.slow) as flasher:
            flasher.flash_firmware(args.firmware)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Print footer when done
    print("")
    print("Operation complete.")

def backup_command():
    """Command-line interface for backing up firmware."""
    parser = argparse.ArgumentParser(
        description="Backup the RT-890 radio firmware.",
        epilog="Make sure the radio is powered on normally (NOT in flash mode)."
    )
    
    parser.add_argument('port', nargs='?', help='Serial port where the radio is connected')
    parser.add_argument('output', nargs='?', help='Output file for the backup')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output with protocol debugging')
    parser.add_argument('-s', '--slow', action='store_true', help='Use slow baud rate (19200)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable extra debugging information')
    parser.add_argument('-l', '--list', action='store_true', help='List available serial ports')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # If debug mode enabled, print additional info
    if args.debug:
        print_debug_info()
    
    # List ports if requested
    if args.list:
        list_serial_ports()
        return
    
    # Check required arguments
    if not args.port or not args.output:
        parser.print_help()
        return
    
    # Execute backup command
    try:
        with RT890Flasher(args.port, args.verbose, args.slow) as flasher:
            flasher.backup_spi(args.output)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Print footer when done
    print("")
    print("Operation complete.")

def restore_command():
    """Command-line interface for restoring firmware from backup."""
    parser = argparse.ArgumentParser(
        description="Restore the RT-890 radio firmware from a backup file.",
        epilog="Make sure the radio is powered on normally (NOT in flash mode)."
    )
    
    parser.add_argument('port', nargs='?', help='Serial port where the radio is connected')
    parser.add_argument('backup', nargs='?', help='Backup file to restore from')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output with protocol debugging')
    parser.add_argument('-s', '--slow', action='store_true', help='Use slow baud rate (19200)')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable extra debugging information')
    parser.add_argument('-l', '--list', action='store_true', help='List available serial ports')
    
    args = parser.parse_args()
    
    # Print banner
    print_banner()
    
    # If debug mode enabled, print additional info
    if args.debug:
        print_debug_info()
    
    # List ports if requested
    if args.list:
        list_serial_ports()
        return
    
    # Check required arguments
    if not args.port or not args.backup:
        parser.print_help()
        return
    
    # Execute restore command
    try:
        with RT890Flasher(args.port, args.verbose, args.slow) as flasher:
            flasher.restore_spi(args.backup)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)
    
    # Print footer when done
    print("")
    print("Operation complete.") 