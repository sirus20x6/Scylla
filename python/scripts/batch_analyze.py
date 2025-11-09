#!/usr/bin/env python3
"""
Scylla Batch Analysis Script

Analyzes multiple binaries and generates comprehensive reports.

Usage:
    python batch_analyze.py <directory> [options]

Examples:
    # Analyze all executables in directory
    python batch_analyze.py /path/to/binaries

    # Recursive search with JSON report
    python batch_analyze.py /path --recursive --format json --output report.json

    # Filter by packer
    python batch_analyze.py /path --filter-packer UPX
"""

import sys
import os
import json
import argparse
from pathlib import Path
from typing import List, Dict, Optional
from collections import defaultdict
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class BatchAnalyzer:
    """Batch binary analysis"""

    def __init__(self):
        self.results = []
        self.stats = defaultdict(int)

    def find_binaries(self, directory: str, recursive: bool = False,
                     patterns: List[str] = None) -> List[Path]:
        """
        Find binary files in directory

        Args:
            directory: Directory to search
            recursive: Search recursively
            patterns: File patterns to match

        Returns:
            List of binary file paths
        """
        if patterns is None:
            patterns = ['*.exe', '*.dll', '*.sys', '*.so', '*.dylib']

        files = []
        path = Path(directory)

        if recursive:
            for pattern in patterns:
                files.extend(path.rglob(pattern))
        else:
            for pattern in patterns:
                files.extend(path.glob(pattern))

        return sorted(files)

    def analyze_file(self, file_path: Path) -> Dict:
        """
        Analyze a single binary file

        Args:
            file_path: Path to binary

        Returns:
            Analysis results dictionary
        """
        result = {
            'file': str(file_path),
            'name': file_path.name,
            'size': file_path.stat().st_size,
            'timestamp': datetime.fromtimestamp(file_path.stat().st_mtime).isoformat(),
            'success': False,
            'error': None
        }

        try:
            # Detect packer
            print(f"[*] Analyzing: {file_path.name}")

            # In a real implementation, this would call Scylla's analysis
            # For now, provide structure for integration

            # Placeholder for demonstration
            result.update({
                'format': 'PE',  # or ELF, Mach-O
                'architecture': 'x64',
                'is_packed': False,
                'packer': None,
                'entropy': 6.5,
                'sections': 5,
                'imports': 120,
                'exports': 0,
                'security': {
                    'dep': True,
                    'aslr': True,
                    'cfg': False,
                    'signed': False
                },
                'success': True
            })

            # Update statistics
            self.stats['total'] += 1
            self.stats['success'] += 1
            self.stats[result['architecture']] += 1

            if result['is_packed']:
                self.stats['packed'] += 1
                self.stats[f"packer_{result['packer']}"] += 1

        except Exception as e:
            result['error'] = str(e)
            self.stats['failed'] += 1
            print(f"[!] Error analyzing {file_path.name}: {e}")

        return result

    def analyze_batch(self, files: List[Path],
                     filter_packer: Optional[str] = None) -> List[Dict]:
        """
        Analyze multiple files

        Args:
            files: List of file paths
            filter_packer: Only include files with this packer

        Returns:
            List of analysis results
        """
        print(f"\n[*] Batch analyzing {len(files)} files...")
        print("=" * 60)

        for i, file_path in enumerate(files, 1):
            print(f"[{i}/{len(files)}] {file_path.name}")

            result = self.analyze_file(file_path)

            # Apply filter
            if filter_packer:
                if result.get('packer') == filter_packer:
                    self.results.append(result)
            else:
                self.results.append(result)

        return self.results

    def generate_report(self, format: str = 'text') -> str:
        """
        Generate analysis report

        Args:
            format: Report format ('text', 'json', 'csv')

        Returns:
            Report string
        """
        if format == 'json':
            return self.generate_json_report()
        elif format == 'csv':
            return self.generate_csv_report()
        else:
            return self.generate_text_report()

    def generate_text_report(self) -> str:
        """Generate text report"""
        lines = []
        lines.append("\n" + "=" * 60)
        lines.append("SCYLLA BATCH ANALYSIS REPORT")
        lines.append("=" * 60)
        lines.append(f"Generated: {datetime.now().isoformat()}")
        lines.append(f"Total files: {self.stats['total']}")
        lines.append(f"Successful: {self.stats['success']}")
        lines.append(f"Failed: {self.stats['failed']}")

        lines.append("\n--- ARCHITECTURE DISTRIBUTION ---")
        for key, value in self.stats.items():
            if key in ['x86', 'x64', 'arm', 'arm64']:
                lines.append(f"  {key}: {value}")

        lines.append("\n--- PACKER DETECTION ---")
        lines.append(f"  Packed: {self.stats.get('packed', 0)}")
        lines.append(f"  Unpacked: {self.stats['total'] - self.stats.get('packed', 0)}")

        packer_counts = {}
        for key, value in self.stats.items():
            if key.startswith('packer_'):
                packer_name = key.replace('packer_', '')
                packer_counts[packer_name] = value

        if packer_counts:
            lines.append("\n  Packer distribution:")
            for packer, count in sorted(packer_counts.items(), key=lambda x: -x[1]):
                percentage = (count / self.stats['total']) * 100
                lines.append(f"    {packer}: {count} ({percentage:.1f}%)")

        lines.append("\n--- DETAILED RESULTS ---")
        for result in self.results[:10]:  # Show first 10
            lines.append(f"\nFile: {result['name']}")
            lines.append(f"  Size: {result['size']:,} bytes")
            lines.append(f"  Architecture: {result.get('architecture', 'Unknown')}")
            if result.get('is_packed'):
                lines.append(f"  Packer: {result.get('packer', 'Unknown')}")
            if result.get('entropy'):
                lines.append(f"  Entropy: {result['entropy']:.2f}")

        if len(self.results) > 10:
            lines.append(f"\n... and {len(self.results) - 10} more files")

        lines.append("\n" + "=" * 60)

        return '\n'.join(lines)

    def generate_json_report(self) -> str:
        """Generate JSON report"""
        report = {
            'generated': datetime.now().isoformat(),
            'statistics': dict(self.stats),
            'results': self.results
        }
        return json.dumps(report, indent=2)

    def generate_csv_report(self) -> str:
        """Generate CSV report"""
        lines = []
        lines.append("File,Size,Architecture,Format,Packed,Packer,Entropy,Sections,Imports,DEP,ASLR,Success")

        for result in self.results:
            fields = [
                result['name'],
                str(result['size']),
                result.get('architecture', ''),
                result.get('format', ''),
                str(result.get('is_packed', False)),
                result.get('packer', ''),
                str(result.get('entropy', '')),
                str(result.get('sections', '')),
                str(result.get('imports', '')),
                str(result.get('security', {}).get('dep', '')),
                str(result.get('security', {}).get('aslr', '')),
                str(result['success'])
            ]
            lines.append(','.join(fields))

        return '\n'.join(lines)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description="Scylla Batch Analysis Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze directory
  %(prog)s /path/to/binaries

  # Recursive with JSON report
  %(prog)s /path --recursive --format json -o report.json

  # Filter by packer
  %(prog)s /path --filter-packer UPX

  # Custom file patterns
  %(prog)s /path --pattern "*.exe" --pattern "*.dll"
        """
    )

    parser.add_argument('directory', help='Directory to analyze')
    parser.add_argument('-r', '--recursive', action='store_true',
                       help='Search recursively')
    parser.add_argument('-f', '--format', choices=['text', 'json', 'csv'],
                       default='text', help='Report format (default: text)')
    parser.add_argument('-o', '--output', help='Output file (default: stdout)')
    parser.add_argument('--filter-packer', help='Filter by packer name')
    parser.add_argument('--pattern', action='append',
                       help='File pattern to match (can specify multiple)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Verbose output')

    args = parser.parse_args()

    # Initialize analyzer
    analyzer = BatchAnalyzer()

    # Find binaries
    files = analyzer.find_binaries(
        args.directory,
        recursive=args.recursive,
        patterns=args.pattern
    )

    if not files:
        print("[!] No binary files found")
        return 1

    print(f"[*] Found {len(files)} binary files")

    # Analyze
    analyzer.analyze_batch(files, filter_packer=args.filter_packer)

    # Generate report
    report = analyzer.generate_report(args.format)

    # Output
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\n[+] Report saved to: {args.output}")
    else:
        print(report)

    return 0


if __name__ == '__main__':
    sys.exit(main())
