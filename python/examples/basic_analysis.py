#!/usr/bin/env python3
"""
Basic Scylla Analysis Examples

Demonstrates how to use pyscylla for basic PE analysis tasks.
"""

import pyscylla
from pyscylla import security, packer, config


def analyze_single_file(file_path):
    """Analyze a single PE file for security and packer"""
    print(f"=== Analyzing: {file_path} ===\n")

    # Security analysis
    print("Security Analysis:")
    print("-" * 40)
    sec_result = pyscylla.analyze_security(file_path)

    print(f"Security Score: {sec_result.security_score}/100")
    print(f"Risk Level: {sec_result.risk_level}")

    print("\nMitigations:")
    mitigations = sec_result.mitigations
    print(f"  DEP/NX:     {'✓' if mitigations.dep_enabled else '✗'}")
    print(f"  ASLR:       {'✓' if mitigations.aslr_enabled else '✗'}")
    print(f"  CFG:        {'✓' if mitigations.cfg_enabled else '✗'}")
    print(f"  /GS:        {'✓' if mitigations.gs_enabled else '✗'}")
    print(f"  SafeSEH:    {'✓' if mitigations.safe_seh else '✗'}")
    print(f"  Signed:     {'✓' if mitigations.authenticode_present else '✗'}")

    if sec_result.weaknesses:
        print("\nWeaknesses:")
        for weakness in sec_result.weaknesses:
            print(f"  ⚠ {weakness}")

    if sec_result.recommendations:
        print("\nRecommendations:")
        for i, rec in enumerate(sec_result.recommendations, 1):
            print(f"  {i}. {rec}")

    # Packer detection
    print("\n\nPacker Detection:")
    print("-" * 40)
    pack_result = pyscylla.detect_packer(file_path)

    if pack_result.is_packed:
        print(f"Packer: {pack_result.packer_name}")
        print(f"Confidence: {pack_result.confidence}%")
        print(f"Method: {pack_result.detection_method}")

        if pack_result.indicators:
            print("\nIndicators:")
            for indicator in pack_result.indicators:
                print(f"  • {indicator}")
    else:
        print("No packer detected")

    print("\n" + "=" * 60 + "\n")


def batch_analysis(file_list):
    """Analyze multiple files and generate report"""
    print("=== Batch Security Analysis ===\n")

    results = []
    for file_path in file_list:
        try:
            result = pyscylla.analyze_security(file_path)
            results.append((file_path, result))
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}")

    # Print summary table
    print(f"{'File':<30} {'Score':<8} {'DEP':<6} {'ASLR':<6} {'CFG':<6} {'Signed':<8}")
    print("-" * 80)

    for file_path, result in results:
        m = result.mitigations
        print(f"{file_path:<30} "
              f"{result.security_score:<8} "
              f"{'✓' if m.dep_enabled else '✗':<6} "
              f"{'✓' if m.aslr_enabled else '✗':<6} "
              f"{'✓' if m.cfg_enabled else '✗':<6} "
              f"{'✓' if m.authenticode_present else '✗':<8}")

    # Statistics
    avg_score = sum(r[1].security_score for r in results) / len(results) if results else 0
    print(f"\nAverage Security Score: {avg_score:.1f}/100")

    # Identify weakest file
    if results:
        weakest = min(results, key=lambda x: x[1].security_score)
        print(f"Weakest File: {weakest[0]} (score: {weakest[1].security_score})")


def configuration_example():
    """Demonstrate configuration management"""
    print("=== Configuration Management ===\n")

    # Get configuration manager
    config_mgr = config.ConfigurationManager.instance()

    # List available profiles
    profiles = config_mgr.list_profiles()
    print(f"Available Profiles: {', '.join(profiles)}")

    # Load a profile
    if config_mgr.load_profile("malware-analysis"):
        print("\n✓ Loaded 'malware-analysis' profile")

        # Get current configuration
        current = config_mgr.get_current_profile()
        print(f"  Name: {current.name}")
        print(f"  Description: {current.description}")

        print("\n  Analysis Settings:")
        print(f"    Deep IAT Scan: {current.analysis.deep_iat_scan}")
        print(f"    Detect Anomalies: {current.analysis.detect_anomalies}")

        print("\n  Packer Detection:")
        print(f"    Entropy Threshold: {current.packer_detection.entropy_threshold}")
        print(f"    Min Confidence: {current.packer_detection.min_confidence}")

        print("\n  Performance:")
        print(f"    Worker Threads: {current.performance.worker_threads}")
        print(f"    Caching: {current.performance.enable_caching}")

        print("\n  Output:")
        print(f"    Format: {current.output.default_format}")
        print(f"    Verbosity: {current.output.verbosity}")


def custom_packer_detection():
    """Advanced packer detection with custom signatures"""
    print("=== Custom Packer Detection ===\n")

    detector = packer.PackerDetector()

    # Create custom signature
    custom_sig = packer.PackerSignature()
    custom_sig.name = "CustomPacker"
    custom_sig.version = "1.0"
    custom_sig.section_names = [".custom", ".packed"]
    custom_sig.string_signatures = ["CUSTOMPACKER"]
    custom_sig.min_entropy = 7.0

    detector.add_signature(custom_sig)
    print("✓ Added custom packer signature")

    # Load additional signatures from JSON
    try:
        detector.load_signatures("custom_signatures.json")
        print("✓ Loaded signatures from JSON")
    except:
        print("⚠ No custom signatures file found")

    # Detect with custom signatures
    file_path = "sample.exe"
    result = detector.detect_from_file(file_path)

    print(f"\nDetection Result:")
    print(f"  File: {file_path}")
    print(f"  Packed: {result.is_packed}")
    print(f"  Packer: {result.packer_name}")
    print(f"  Confidence: {result.confidence}%")


def security_comparison():
    """Compare security postures of multiple versions"""
    print("=== Security Version Comparison ===\n")

    versions = ["app_v1.0.exe", "app_v1.1.exe", "app_v2.0.exe"]
    analyzer = security.SecurityAnalyzer()

    print(f"{'Version':<15} {'Score':<8} {'DEP':<6} {'ASLR':<6} {'CFG':<6} {'Risk':<10}")
    print("-" * 65)

    for version in versions:
        try:
            result = analyzer.analyze(version)
            m = result.mitigations

            risk_map = {
                security.RiskLevel.MINIMAL: "Minimal",
                security.RiskLevel.LOW: "Low",
                security.RiskLevel.MEDIUM: "Medium",
                security.RiskLevel.HIGH: "High",
                security.RiskLevel.CRITICAL: "Critical"
            }

            print(f"{version:<15} "
                  f"{result.security_score:<8} "
                  f"{'✓' if m.dep_enabled else '✗':<6} "
                  f"{'✓' if m.aslr_enabled else '✗':<6} "
                  f"{'✓' if m.cfg_enabled else '✗':<6} "
                  f"{risk_map.get(result.risk_level, 'Unknown'):<10}")

        except Exception as e:
            print(f"{version:<15} Error: {e}")


def main():
    """Run all examples"""
    print("Scylla Python Bindings - Examples")
    print("=" * 60)
    print(f"Version: {pyscylla.version()}")
    print("=" * 60 + "\n")

    # Example 1: Single file analysis
    analyze_single_file("C:\\Windows\\System32\\notepad.exe")

    # Example 2: Batch analysis
    files = [
        "C:\\Windows\\System32\\cmd.exe",
        "C:\\Windows\\System32\\calc.exe",
        "C:\\Windows\\System32\\notepad.exe"
    ]
    batch_analysis(files)

    # Example 3: Configuration
    print()
    configuration_example()

    # Example 4: Custom packer detection
    print()
    custom_packer_detection()

    # Example 5: Security comparison
    print()
    security_comparison()


if __name__ == '__main__':
    main()
