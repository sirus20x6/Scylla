#!/usr/bin/env python3
"""
Automation Workflow Examples

Demonstrates how to use pyscylla for automated malware analysis workflows.
"""

import pyscylla
from pyscylla import security, packer, config
import os
import json
from pathlib import Path
from datetime import datetime


class MalwareAnalysisPipeline:
    """Automated malware analysis pipeline"""

    def __init__(self, output_dir="analysis_results"):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)

        # Load malware analysis profile
        config_mgr = config.ConfigurationManager.instance()
        config_mgr.load_profile("malware-analysis")

        self.security_analyzer = security.SecurityAnalyzer()
        self.packer_detector = packer.PackerDetector()

    def analyze_sample(self, file_path):
        """
        Complete analysis of a malware sample

        Returns:
            dict: Analysis results
        """
        results = {
            'file': str(file_path),
            'timestamp': datetime.now().isoformat(),
            'security': None,
            'packer': None,
            'verdict': None
        }

        try:
            # Security analysis
            sec_result = self.security_analyzer.analyze(str(file_path))
            results['security'] = {
                'score': sec_result.security_score,
                'risk_level': str(sec_result.risk_level),
                'dep': sec_result.mitigations.dep_enabled,
                'aslr': sec_result.mitigations.aslr_enabled,
                'cfg': sec_result.mitigations.cfg_enabled,
                'signed': sec_result.mitigations.authenticode_present,
                'valid_signature': sec_result.mitigations.signature_valid,
                'weaknesses': sec_result.weaknesses,
                'recommendations': sec_result.recommendations
            }

            # Packer detection
            pack_result = self.packer_detector.detect_from_file(str(file_path))
            results['packer'] = {
                'is_packed': pack_result.is_packed,
                'name': pack_result.packer_name,
                'confidence': pack_result.confidence,
                'method': pack_result.detection_method,
                'indicators': pack_result.indicators
            }

            # Generate verdict
            results['verdict'] = self._generate_verdict(results)

        except Exception as e:
            results['error'] = str(e)

        return results

    def _generate_verdict(self, results):
        """Generate automated verdict based on analysis"""
        suspicion_score = 0
        reasons = []

        # Check security score
        if results['security']['score'] < 30:
            suspicion_score += 40
            reasons.append("Very low security score (< 30)")

        # Check code signing
        if not results['security']['signed']:
            suspicion_score += 30
            reasons.append("Not code signed")
        elif not results['security']['valid_signature']:
            suspicion_score += 50
            reasons.append("Invalid code signature")

        # Check packer
        if results['packer']['is_packed']:
            suspicion_score += 20
            reasons.append(f"Packed with {results['packer']['name']}")

        # Determine verdict
        if suspicion_score >= 70:
            verdict = "MALICIOUS"
        elif suspicion_score >= 40:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            'verdict': verdict,
            'suspicion_score': suspicion_score,
            'reasons': reasons
        }

    def process_directory(self, directory, recursive=True):
        """
        Process all PE files in a directory

        Args:
            directory: Path to directory
            recursive: Scan recursively

        Returns:
            list: Analysis results for all files
        """
        results = []
        pattern = "**/*.exe" if recursive else "*.exe"

        for file_path in Path(directory).glob(pattern):
            print(f"Analyzing: {file_path.name}")
            result = self.analyze_sample(file_path)
            results.append(result)

        return results

    def generate_report(self, results, format='json'):
        """
        Generate analysis report

        Args:
            results: Analysis results
            format: Report format (json, html, markdown)

        Returns:
            Path to report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if format == 'json':
            report_path = self.output_dir / f"report_{timestamp}.json"
            with open(report_path, 'w') as f:
                json.dump(results, f, indent=2)

        elif format == 'html':
            report_path = self.output_dir / f"report_{timestamp}.html"
            html = self._generate_html_report(results)
            with open(report_path, 'w') as f:
                f.write(html)

        elif format == 'markdown':
            report_path = self.output_dir / f"report_{timestamp}.md"
            md = self._generate_markdown_report(results)
            with open(report_path, 'w') as f:
                f.write(md)

        return report_path

    def _generate_markdown_report(self, results):
        """Generate Markdown report"""
        md = ["# Malware Analysis Report\n"]
        md.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        md.append(f"Total Samples: {len(results)}\n")

        # Statistics
        verdicts = {}
        for r in results:
            if 'verdict' in r:
                v = r['verdict']['verdict']
                verdicts[v] = verdicts.get(v, 0) + 1

        md.append("\n## Summary\n")
        for verdict, count in verdicts.items():
            md.append(f"- {verdict}: {count}\n")

        # Detailed results
        md.append("\n## Detailed Results\n")
        for i, r in enumerate(results, 1):
            md.append(f"\n### {i}. {Path(r['file']).name}\n")

            if 'verdict' in r:
                md.append(f"**Verdict:** {r['verdict']['verdict']} "
                         f"(Suspicion: {r['verdict']['suspicion_score']})\n")

            if 'security' in r and r['security']:
                s = r['security']
                md.append(f"\n**Security Score:** {s['score']}/100\n")
                md.append(f"- DEP: {'✓' if s['dep'] else '✗'}\n")
                md.append(f"- ASLR: {'✓' if s['aslr'] else '✗'}\n")
                md.append(f"- CFG: {'✓' if s['cfg'] else '✗'}\n")

            if 'packer' in r and r['packer']['is_packed']:
                p = r['packer']
                md.append(f"\n**Packer:** {p['name']} ({p['confidence']}% confidence)\n")

        return ''.join(md)

    def _generate_html_report(self, results):
        """Generate HTML report"""
        html = ["<!DOCTYPE html><html><head>"]
        html.append("<title>Malware Analysis Report</title>")
        html.append("<style>")
        html.append("body { font-family: Arial, sans-serif; margin: 20px; }")
        html.append("table { border-collapse: collapse; width: 100%; }")
        html.append("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }")
        html.append("th { background-color: #4CAF50; color: white; }")
        html.append(".malicious { background-color: #ffcccc; }")
        html.append(".suspicious { background-color: #ffffcc; }")
        html.append(".clean { background-color: #ccffcc; }")
        html.append("</style></head><body>")

        html.append(f"<h1>Malware Analysis Report</h1>")
        html.append(f"<p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")

        html.append("<table>")
        html.append("<tr><th>File</th><th>Verdict</th><th>Score</th><th>Packer</th></tr>")

        for r in results:
            verdict = r.get('verdict', {}).get('verdict', 'Unknown')
            css_class = verdict.lower()
            score = r.get('security', {}).get('score', 0) if r.get('security') else 0
            packer = r.get('packer', {}).get('name', 'None') if r.get('packer', {}).get('is_packed') else 'None'

            html.append(f"<tr class='{css_class}'>")
            html.append(f"<td>{Path(r['file']).name}</td>")
            html.append(f"<td>{verdict}</td>")
            html.append(f"<td>{score}/100</td>")
            html.append(f"<td>{packer}</td>")
            html.append("</tr>")

        html.append("</table></body></html>")

        return ''.join(html)


def example_single_file_workflow():
    """Example: Analyze single malware sample"""
    print("=== Single File Analysis Workflow ===\n")

    pipeline = MalwareAnalysisPipeline()

    # Analyze sample
    result = pipeline.analyze_sample("suspected_malware.exe")

    # Print verdict
    if 'verdict' in result:
        verdict = result['verdict']
        print(f"Verdict: {verdict['verdict']}")
        print(f"Suspicion Score: {verdict['suspicion_score']}/100")

        if verdict['reasons']:
            print("\nReasons:")
            for reason in verdict['reasons']:
                print(f"  • {reason}")

    # Save result
    report = pipeline.generate_report([result], format='json')
    print(f"\nReport saved to: {report}")


def example_batch_workflow():
    """Example: Batch analyze malware dataset"""
    print("=== Batch Analysis Workflow ===\n")

    pipeline = MalwareAnalysisPipeline()

    # Process directory
    print("Processing malware samples...")
    results = pipeline.process_directory("malware_samples", recursive=True)

    # Generate statistics
    total = len(results)
    malicious = sum(1 for r in results if r.get('verdict', {}).get('verdict') == 'MALICIOUS')
    suspicious = sum(1 for r in results if r.get('verdict', {}).get('verdict') == 'SUSPICIOUS')
    clean = sum(1 for r in results if r.get('verdict', {}).get('verdict') == 'CLEAN')

    print(f"\nResults:")
    print(f"  Total: {total}")
    print(f"  Malicious: {malicious}")
    print(f"  Suspicious: {suspicious}")
    print(f"  Clean: {clean}")

    # Generate reports in multiple formats
    print("\nGenerating reports...")
    json_report = pipeline.generate_report(results, format='json')
    html_report = pipeline.generate_report(results, format='html')
    md_report = pipeline.generate_report(results, format='markdown')

    print(f"  JSON: {json_report}")
    print(f"  HTML: {html_report}")
    print(f"  Markdown: {md_report}")


def example_continuous_monitoring():
    """Example: Continuous monitoring of samples directory"""
    print("=== Continuous Monitoring ===\n")

    import time

    pipeline = MalwareAnalysisPipeline()
    watch_dir = Path("incoming_samples")
    processed_dir = Path("processed_samples")

    watch_dir.mkdir(exist_ok=True)
    processed_dir.mkdir(exist_ok=True)

    print(f"Monitoring: {watch_dir}")
    print("Press Ctrl+C to stop\n")

    try:
        while True:
            # Check for new files
            for file_path in watch_dir.glob("*.exe"):
                print(f"New sample detected: {file_path.name}")

                # Analyze
                result = pipeline.analyze_sample(file_path)

                # Generate report
                report = pipeline.generate_report([result], format='json')

                # Move to processed
                dest = processed_dir / file_path.name
                file_path.rename(dest)

                print(f"  Verdict: {result.get('verdict', {}).get('verdict', 'Unknown')}")
                print(f"  Moved to: {dest}")
                print(f"  Report: {report}\n")

            time.sleep(5)  # Check every 5 seconds

    except KeyboardInterrupt:
        print("\nMonitoring stopped")


def main():
    """Run workflow examples"""
    print("Scylla Python Automation Workflows")
    print("=" * 60 + "\n")

    # Example 1: Single file
    example_single_file_workflow()
    print("\n" + "=" * 60 + "\n")

    # Example 2: Batch processing
    example_batch_workflow()
    print("\n" + "=" * 60 + "\n")

    # Example 3: Continuous monitoring (commented out for safety)
    # example_continuous_monitoring()


if __name__ == '__main__':
    main()
