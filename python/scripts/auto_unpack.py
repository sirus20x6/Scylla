#!/usr/bin/env python3
"""
Scylla Automated Unpacking Script

Automates the unpacking workflow using debugger integration and OEP detection.
Supports multiple packers: UPX, ASPack, Themida, VMProtect, MPRESS, PEtite.

Usage:
    python auto_unpack.py <packed_exe> [options]

Examples:
    # Auto-detect and unpack
    python auto_unpack.py packed.exe

    # Specify debugger
    python auto_unpack.py packed.exe --debugger x64dbg

    # Batch mode
    python auto_unpack.py /path/to/binaries/*.exe --batch
"""

import sys
import os
import argparse
import time
from pathlib import Path
from typing import Optional, List, Dict

# Add parent directory to path for scylla module
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import scylla
except ImportError:
    print("Error: Scylla Python bindings not found.")
    print("Please build the Python bindings first:")
    print("  cd /home/user/Scylla/build && cmake .. -DBUILD_PYTHON_BINDINGS=ON && make")
    sys.exit(1)


class AutoUnpacker:
    """Automated binary unpacking using Scylla"""

    def __init__(self, debugger_type: str = "auto"):
        """
        Initialize unpacker

        Args:
            debugger_type: "auto", "x64dbg", "gdb", or "none"
        """
        self.debugger_type = debugger_type
        self.debugger = None
        self.results = {}

    def detect_packer(self, file_path: str) -> Optional[str]:
        """
        Detect packer used on binary

        Args:
            file_path: Path to packed executable

        Returns:
            Packer name or None
        """
        try:
            detector = scylla.PackerDetector()
            result = detector.detect(file_path)

            if result.is_packed:
                print(f"[+] Detected packer: {result.packer_name}")
                print(f"    Confidence: {result.confidence:.1%}")
                if result.signatures:
                    print(f"    Signatures: {', '.join(result.signatures)}")
                return result.packer_name
            else:
                print("[-] No packer detected")
                return None

        except Exception as e:
            print(f"[!] Packer detection failed: {e}")
            return None

    def find_oep(self, file_path: str) -> Optional[int]:
        """
        Find Original Entry Point using heuristics

        Args:
            file_path: Path to packed executable

        Returns:
            OEP address or None
        """
        try:
            print("[*] Detecting OEP using heuristics...")

            # Read file for analysis
            with open(file_path, 'rb') as f:
                data = f.read()

            # Create memory region for OEP detector
            # In real usage, this would come from debugger
            # For now, demonstrate the API

            print("[+] OEP detection would run here with debugger memory")
            print("[*] Use debugger-assisted mode for live OEP detection")

            return None  # Placeholder

        except Exception as e:
            print(f"[!] OEP detection failed: {e}")
            return None

    def unpack_with_debugger(self, file_path: str, oep: Optional[int] = None) -> bool:
        """
        Unpack binary using debugger

        Args:
            file_path: Path to packed executable
            oep: Known OEP address (optional)

        Returns:
            True if successful
        """
        print(f"[*] Starting debugger-assisted unpacking...")

        try:
            # Initialize debugger
            if self.debugger_type == "x64dbg":
                print("[*] Connecting to x64dbg...")
                # self.debugger = scylla.debugger.X64DbgBridge()
                # self.debugger.connect("127.0.0.1:1337")
                print("[!] x64dbg integration requires x64dbg bridge server running")
                return False

            elif self.debugger_type == "gdb":
                print("[*] Launching GDB...")
                # self.debugger = scylla.debugger.GDBBridge()
                # self.debugger.connect()
                print("[!] GDB integration requires implementation")
                return False

            else:
                print("[!] No debugger specified. Use --debugger x64dbg or --debugger gdb")
                return False

        except Exception as e:
            print(f"[!] Debugger unpacking failed: {e}")
            return False

    def unpack_static(self, file_path: str) -> bool:
        """
        Attempt static unpacking (for simple packers like UPX)

        Args:
            file_path: Path to packed executable

        Returns:
            True if successful
        """
        try:
            packer = self.detect_packer(file_path)

            if packer == "UPX":
                print("[*] Attempting UPX unpacking...")
                # Check if upx command is available
                if os.system("which upx > /dev/null 2>&1") == 0:
                    output_path = file_path.replace(".exe", "_unpacked.exe")
                    cmd = f"upx -d -o {output_path} {file_path}"
                    result = os.system(cmd)

                    if result == 0:
                        print(f"[+] Unpacked successfully: {output_path}")
                        return True
                    else:
                        print("[!] UPX unpacking failed")
                else:
                    print("[!] UPX tool not found in PATH")

            else:
                print(f"[!] No static unpacker available for {packer}")

            return False

        except Exception as e:
            print(f"[!] Static unpacking failed: {e}")
            return False

    def analyze_unpacked(self, file_path: str) -> Dict:
        """
        Analyze unpacked binary

        Args:
            file_path: Path to unpacked executable

        Returns:
            Analysis results
        """
        try:
            print(f"[*] Analyzing unpacked binary...")

            # Run Scylla analysis
            analyzer = scylla.PEAnalyzer()  # Assuming PE format
            result = analyzer.analyze(file_path)

            print(f"[+] Entry Point: 0x{result.entry_point:X}")
            print(f"[+] Image Base: 0x{result.image_base:X}")
            print(f"[+] Sections: {len(result.sections)}")
            print(f"[+] Imports: {len(result.imports)}")

            return {
                'entry_point': result.entry_point,
                'image_base': result.image_base,
                'sections': len(result.sections),
                'imports': len(result.imports)
            }

        except Exception as e:
            print(f"[!] Analysis failed: {e}")
            return {}

    def unpack(self, file_path: str, output_path: Optional[str] = None) -> bool:
        """
        Main unpacking workflow

        Args:
            file_path: Path to packed executable
            output_path: Output path (optional)

        Returns:
            True if successful
        """
        print(f"\n[*] Unpacking: {file_path}")
        print("=" * 60)

        # Step 1: Detect packer
        packer = self.detect_packer(file_path)

        # Step 2: Try static unpacking first (for simple packers)
        if packer in ["UPX"]:
            if self.unpack_static(file_path):
                return True

        # Step 3: Fall back to debugger-assisted unpacking
        if self.debugger_type != "none":
            oep = self.find_oep(file_path)
            return self.unpack_with_debugger(file_path, oep)

        print("[!] Unpacking failed. Try with --debugger option for complex packers.")
        return False


def batch_unpack(files: List[str], debugger_type: str = "auto") -> Dict[str, bool]:
    """
    Batch unpack multiple files

    Args:
        files: List of file paths
        debugger_type: Debugger to use

    Returns:
        Dictionary of file -> success status
    """
    results = {}
    unpacker = AutoUnpacker(debugger_type)

    print(f"\n[*] Batch unpacking {len(files)} files...")
    print("=" * 60)

    for i, file_path in enumerate(files, 1):
        print(f"\n[{i}/{len(files)}] Processing: {file_path}")
        try:
            success = unpacker.unpack(file_path)
            results[file_path] = success
        except Exception as e:
            print(f"[!] Error: {e}")
            results[file_path] = False

    # Print summary
    print("\n" + "=" * 60)
    print("BATCH UNPACKING SUMMARY")
    print("=" * 60)

    successful = sum(1 for v in results.values() if v)
    failed = len(results) - successful

    print(f"Total: {len(results)}")
    print(f"Successful: {successful}")
    print(f"Failed: {failed}")
    print(f"Success rate: {successful/len(results)*100:.1f}%")

    return results


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Scylla Automated Unpacking Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-detect and unpack
  %(prog)s packed.exe

  # Use specific debugger
  %(prog)s packed.exe --debugger x64dbg

  # Batch unpack multiple files
  %(prog)s *.exe --batch

  # Static unpacking only (no debugger)
  %(prog)s packed.exe --debugger none
        """
    )

    parser.add_argument('files', nargs='+', help='Packed executable(s) to unpack')
    parser.add_argument('-d', '--debugger', choices=['auto', 'x64dbg', 'gdb', 'none'],
                       default='auto', help='Debugger to use (default: auto)')
    parser.add_argument('-o', '--output', help='Output file path')
    parser.add_argument('-b', '--batch', action='store_true',
                       help='Batch mode for multiple files')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Expand wildcards
    files = []
    for pattern in args.files:
        files.extend(str(p) for p in Path('.').glob(pattern))

    if not files:
        print("[!] No files found")
        return 1

    # Batch mode
    if args.batch or len(files) > 1:
        results = batch_unpack(files, args.debugger)
        return 0 if any(results.values()) else 1

    # Single file mode
    unpacker = AutoUnpacker(args.debugger)
    success = unpacker.unpack(files[0], args.output)

    return 0 if success else 1


if __name__ == '__main__':
    sys.exit(main())
