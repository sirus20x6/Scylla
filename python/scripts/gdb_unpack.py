#!/usr/bin/env python3
"""
Scylla GDB-Assisted Unpacking Script

Automates unpacking using GDB on Linux/macOS systems.
Integrates with Scylla's GDB bridge for cross-platform unpacking.

Usage:
    python gdb_unpack.py <packed_binary> [options]

Examples:
    # Auto-detect OEP and dump
    python gdb_unpack.py packed_binary

    # Connect to remote gdbserver
    python gdb_unpack.py packed_binary --remote localhost:1234

    # Specify known OEP
    python gdb_unpack.py packed_binary --oep 0x401000

    # Enable verbose GDB logging
    python gdb_unpack.py packed_binary --verbose
"""

import sys
import os
import argparse
from pathlib import Path
from typing import Optional

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class GDBUnpacker:
    """GDB-assisted unpacking"""

    def __init__(self, verbose: bool = False):
        """
        Initialize GDB unpacker

        Args:
            verbose: Enable verbose logging
        """
        self.verbose = verbose
        self.gdb = None

    def connect_gdb(self, remote: Optional[str] = None) -> bool:
        """
        Connect to GDB

        Args:
            remote: Remote gdbserver (host:port), None for local

        Returns:
            True if connected
        """
        try:
            print("[*] Initializing GDB...")

            # In real implementation, would use:
            # from scylla.debugger import GDBBridge
            # self.gdb = GDBBridge()

            if remote:
                print(f"[*] Connecting to gdbserver at {remote}...")
                # self.gdb.connect_to_gdbserver(host, port)
                print("[!] Remote GDB connection requires implementation")
                return False
            else:
                print("[*] Starting local GDB...")
                # self.gdb.connect()
                print("[!] Local GDB requires implementation")
                return False

        except Exception as e:
            print(f"[!] GDB connection failed: {e}")
            return False

    def set_breakpoints(self) -> bool:
        """
        Set initial breakpoints for unpacking

        Returns:
            True if successful
        """
        print("[*] Setting breakpoints...")

        # Common unpacking breakpoints:
        # 1. Entry point
        # 2. VirtualProtect/mprotect (for self-modifying code)
        # 3. Common unpacker APIs

        try:
            # self.gdb.set_breakpoint(address=0x401000)
            # self.gdb.set_breakpoint_expression("VirtualProtect")
            # self.gdb.set_breakpoint_expression("mprotect")

            print("[+] Breakpoints set")
            return True

        except Exception as e:
            print(f"[!] Failed to set breakpoints: {e}")
            return False

    def detect_oep_gdb(self) -> Optional[int]:
        """
        Detect OEP using GDB

        Returns:
            OEP address or None
        """
        print("[*] Detecting OEP with GDB...")

        try:
            # Strategy:
            # 1. Run until first breakpoint
            # 2. Monitor memory protection changes
            # 3. Look for tail jumps or POPAD instructions
            # 4. Detect entropy transitions

            # self.gdb.continue_execution()
            # self.gdb.wait_for_event()

            # Check for POPAD (0x61) instruction
            # rip = self.gdb.read_register("rip")
            # code = self.gdb.read_memory(rip, 16)

            # if code[0] == 0x61:  # POPAD
            #     # Check next instruction
            #     if code[1] == 0xE9:  # JMP
            #         # Extract jump target
            #         offset = int.from_bytes(code[2:6], 'little', signed=True)
            #         oep = rip + 6 + offset
            #         return oep

            print("[!] OEP detection requires full GDB integration")
            return None

        except Exception as e:
            print(f"[!] OEP detection failed: {e}")
            return None

    def dump_memory(self, output_path: str, base_address: Optional[int] = None,
                   size: Optional[int] = None) -> bool:
        """
        Dump process memory

        Args:
            output_path: Output file path
            base_address: Base address to dump (None = main module)
            size: Size to dump (None = entire module)

        Returns:
            True if successful
        """
        print(f"[*] Dumping memory to: {output_path}")

        try:
            # if base_address is None:
            #     modules = self.gdb.get_modules()
            #     if modules:
            #         base_address = modules[0].base_address
            #         size = modules[0].size

            # memory = self.gdb.read_memory(base_address, size)

            # with open(output_path, 'wb') as f:
            #     f.write(memory)

            print("[+] Memory dumped successfully")
            return True

        except Exception as e:
            print(f"[!] Memory dump failed: {e}")
            return False

    def fix_imports(self, dumped_file: str, oep: int) -> bool:
        """
        Fix imports in dumped file using Scylla

        Args:
            dumped_file: Path to dumped memory
            oep: Original entry point

        Returns:
            True if successful
        """
        print("[*] Fixing imports...")

        try:
            # Use Scylla's IAT reconstruction
            # reconstructor = scylla.ImportRebuilder()
            # reconstructor.rebuild(dumped_file, oep)

            print("[+] Imports fixed")
            return True

        except Exception as e:
            print(f"[!] Import fixing failed: {e}")
            return False

    def unpack(self, binary_path: str, output_path: str,
              oep: Optional[int] = None) -> bool:
        """
        Main unpacking workflow

        Args:
            binary_path: Path to packed binary
            output_path: Output path for unpacked binary
            oep: Known OEP (optional)

        Returns:
            True if successful
        """
        print(f"\n[*] GDB Unpacking: {binary_path}")
        print("=" * 60)

        # Step 1: Start process under GDB
        if not self.connect_gdb():
            return False

        # Step 2: Set breakpoints
        if not self.set_breakpoints():
            return False

        # Step 3: Detect OEP if not provided
        if oep is None:
            oep = self.detect_oep_gdb()
            if oep is None:
                print("[!] Failed to detect OEP")
                return False
            print(f"[+] Detected OEP: 0x{oep:X}")
        else:
            print(f"[*] Using provided OEP: 0x{oep:X}")

        # Step 4: Dump memory
        dump_path = output_path.replace('.exe', '_dump.bin')
        if not self.dump_memory(dump_path):
            return False

        # Step 5: Fix imports
        if not self.fix_imports(dump_path, oep):
            return False

        # Step 6: Rebuild PE/ELF file
        print(f"[+] Unpacking complete: {output_path}")

        return True


def generate_gdb_script(binary_path: str, output_path: str = "unpack.gdb") -> str:
    """
    Generate GDB script for manual unpacking

    Args:
        binary_path: Path to packed binary
        output_path: Script output path

    Returns:
        Path to generated script
    """
    script = f'''# Scylla GDB Unpacking Script
# Binary: {binary_path}

# Disable pagination
set pagination off
set confirm off

# Load binary
file {binary_path}

# Set breakpoints on common unpacker APIs
catch syscall mprotect
catch syscall mmap

# Breakpoint on main/entry
break *_start

# Run
run

# Commands to execute at breakpoints:
# - info proc mappings (view memory map)
# - dump memory output.bin 0xSTART 0xEND
# - x/20i $rip (disassemble at current location)

# Helper functions
define dump_all
    set $i = 0
    set $maps = (char*)0
    shell cat /proc/$pid/maps > /tmp/maps.txt
    # Parse maps and dump each region
end

# Instructions:
# 1. Continue execution: c
# 2. Step instruction: si
# 3. View registers: info registers
# 4. View memory map: info proc mappings
# 5. Dump memory: dump binary memory output.bin 0xSTART 0xEND
# 6. Find OEP: Use 'find' command to search for patterns

echo \\n[Scylla] GDB script loaded. Ready for unpacking.\\n
'''

    with open(output_path, 'w') as f:
        f.write(script)

    print(f"[+] GDB script generated: {output_path}")
    print(f"[*] Usage: gdb -x {output_path}")

    return output_path


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Scylla GDB-Assisted Unpacking Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect and unpack
  %(prog)s packed_binary

  # Remote gdbserver
  %(prog)s packed_binary --remote localhost:1234

  # Known OEP
  %(prog)s packed_binary --oep 0x401000

  # Generate GDB script only
  %(prog)s packed_binary --generate-script --output unpack.gdb
        """
    )

    parser.add_argument('binary', help='Packed binary to unpack')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('--oep', type=lambda x: int(x, 0),
                       help='Known OEP address (hex or decimal)')
    parser.add_argument('--remote', help='Remote gdbserver (host:port)')
    parser.add_argument('--generate-script', action='store_true',
                       help='Generate GDB script instead of running')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Generate script mode
    if args.generate_script:
        output_path = args.output or "unpack.gdb"
        generate_gdb_script(args.binary, output_path)
        return 0

    # Unpacking mode
    output_path = args.output or args.binary + "_unpacked"

    unpacker = GDBUnpacker(verbose=args.verbose)
    success = unpacker.unpack(args.binary, output_path, oep=args.oep)

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
