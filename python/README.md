# PyScylla - Python Bindings for Scylla

Python bindings for the Scylla PE analysis and reverse engineering toolkit.

## Features

- **Security Analysis**: Detect DEP, ASLR, CFG, SafeSEH, and code signing
- **Packer Detection**: Identify 15+ common packers with signature and heuristic analysis
- **Configuration Management**: Use built-in profiles or create custom configurations
- **Automation**: Build automated malware analysis workflows
- **Cross-Platform**: Works on Windows, Linux, and macOS

## Installation

### From Source

```bash
git clone https://github.com/NtQuery/Scylla.git
cd Scylla/python
python setup.py install
```

### Requirements

- Python 3.7+
- CMake 3.15+
- C++17 compiler
- pybind11

## Quick Start

```python
import pyscylla

# Quick security analysis
result = pyscylla.analyze_security("malware.exe")
print(f"Security Score: {result.security_score}/100")
print(f"DEP Enabled: {result.mitigations.dep_enabled}")
print(f"ASLR Enabled: {result.mitigations.aslr_enabled}")

# Quick packer detection
pack_result = pyscylla.detect_packer("packed.exe")
if pack_result.is_packed:
    print(f"Packer: {pack_result.packer_name}")
    print(f"Confidence: {pack_result.confidence}%")
```

## Usage Examples

### Security Analysis

```python
from pyscylla import security

analyzer = security.SecurityAnalyzer()
result = analyzer.analyze("sample.exe")

print(f"Security Score: {result.security_score}/100")
print(f"Risk Level: {result.risk_level}")

# Check specific mitigations
if not result.mitigations.dep_enabled:
    print("⚠ DEP is disabled!")

# Get recommendations
for rec in result.recommendations:
    print(f"  • {rec}")
```

### Packer Detection

```python
from pyscylla import packer

detector = packer.PackerDetector()

# Detect packer
result = detector.detect_from_file("packed.exe")

if result.is_packed:
    print(f"Packer: {result.packer_name}")
    print(f"Method: {result.detection_method}")

    # Show indicators
    for indicator in result.indicators:
        print(f"  - {indicator}")
```

### Configuration Profiles

```python
from pyscylla import config

# Get configuration manager
mgr = config.ConfigurationManager.instance()

# List available profiles
profiles = mgr.list_profiles()
print(f"Available: {', '.join(profiles)}")

# Load a profile
mgr.load_profile("malware-analysis")

# Get current configuration
current = mgr.get_current_profile()
print(f"Profile: {current.name}")
print(f"Deep Scan: {current.analysis.deep_iat_scan}")
```

### Batch Analysis

```python
import pyscylla
from pathlib import Path

results = []

for exe_file in Path("malware_samples").glob("*.exe"):
    result = pyscylla.analyze_security(str(exe_file))
    results.append((exe_file.name, result.security_score))

# Show weakest files
results.sort(key=lambda x: x[1])
print("Weakest files:")
for name, score in results[:5]:
    print(f"  {name}: {score}/100")
```

### Automated Malware Analysis

```python
from pyscylla import security, packer
import json

def analyze_sample(file_path):
    """Complete malware analysis"""

    # Security analysis
    sec = security.SecurityAnalyzer().analyze(file_path)

    # Packer detection
    pack = packer.PackerDetector().detect_from_file(file_path)

    # Generate verdict
    suspicion = 0
    if sec.security_score < 30:
        suspicion += 40
    if not sec.mitigations.authenticode_present:
        suspicion += 30
    if pack.is_packed:
        suspicion += 20

    verdict = "MALICIOUS" if suspicion >= 70 else \
              "SUSPICIOUS" if suspicion >= 40 else "CLEAN"

    return {
        'file': file_path,
        'security_score': sec.security_score,
        'is_packed': pack.is_packed,
        'packer': pack.packer_name if pack.is_packed else None,
        'verdict': verdict,
        'suspicion': suspicion
    }

# Analyze sample
result = analyze_sample("suspected_malware.exe")
print(json.dumps(result, indent=2))
```

## API Reference

### Security Module

#### `SecurityAnalyzer`

- `analyze(file_path)` - Analyze security mitigations
- `check_dep(file_path)` - Check DEP/NX
- `check_aslr(file_path)` - Check ASLR
- `check_cfg(file_path)` - Check Control Flow Guard
- `verify_signature(file_path)` - Verify Authenticode signature

#### `SecurityAssessment`

- `security_score` - Overall score (0-100)
- `risk_level` - Risk level enum (MINIMAL, LOW, MEDIUM, HIGH, CRITICAL)
- `mitigations` - SecurityMitigations object
- `strengths` - List of security strengths
- `weaknesses` - List of security weaknesses
- `recommendations` - List of recommendations

#### `SecurityMitigations`

- `dep_enabled` - DEP/NX enabled
- `aslr_enabled` - ASLR enabled
- `high_entropy_va` - High-entropy ASLR (64-bit)
- `cfg_enabled` - Control Flow Guard enabled
- `safe_seh` - SafeSEH enabled
- `gs_enabled` - Stack protection (/GS) enabled
- `authenticode_present` - Code signing present
- `signature_valid` - Signature is valid

### Packer Module

#### `PackerDetector`

- `detect_from_file(file_path)` - Detect packer
- `add_signature(signature)` - Add custom signature
- `load_signatures(json_path)` - Load signatures from JSON

#### `PackerDetectionResult`

- `is_packed` - Whether file is packed
- `packer_name` - Name of detected packer
- `confidence` - Detection confidence (0-100)
- `detection_method` - Method used (signature/heuristic)
- `indicators` - List of detection indicators

#### `PackerSignature`

- `name` - Packer name
- `version` - Version
- `section_names` - Section name patterns
- `string_signatures` - String patterns
- `min_entropy` - Minimum entropy threshold

### Config Module

#### `ConfigurationManager`

- `instance()` - Get singleton instance
- `load_profile(name)` - Load configuration profile
- `save_profile(name)` - Save current profile
- `list_profiles()` - List available profiles
- `create_profile(name, description)` - Create new profile
- `get_current_profile()` - Get current configuration

#### Built-in Profiles

- `default` - Balanced configuration
- `quick-scan` - Fast scanning (5x faster)
- `deep-analysis` - Comprehensive analysis
- `malware-analysis` - Optimized for malware
- `performance` - Maximum speed

## Advanced Usage

### Custom Packer Signatures

```python
from pyscylla import packer

# Create custom signature
sig = packer.PackerSignature()
sig.name = "CustomPacker"
sig.version = "1.0"
sig.section_names = [".custom"]
sig.string_signatures = ["CUSTOMPACKER"]
sig.min_entropy = 7.0

# Add to detector
detector = packer.PackerDetector()
detector.add_signature(sig)
```

### Security Comparison

```python
from pyscylla import security

analyzer = security.SecurityAnalyzer()

versions = ["app_v1.exe", "app_v2.exe", "app_v3.exe"]

for version in versions:
    result = analyzer.analyze(version)
    print(f"{version}: {result.security_score}/100")
```

### Integration with Analysis Tools

```python
import pyscylla
import pefile
import ssdeep

def full_analysis(file_path):
    """Combine PyScylla with other tools"""

    # PyScylla analysis
    sec = pyscylla.analyze_security(file_path)
    pack = pyscylla.detect_packer(file_path)

    # pefile analysis
    pe = pefile.PE(file_path)

    # Fuzzy hash
    fuzz = ssdeep.hash_from_file(file_path)

    return {
        'security': sec,
        'packer': pack,
        'imphash': pe.get_imphash(),
        'ssdeep': fuzz
    }
```

## License

See the main Scylla repository for license information.

## Contributing

Contributions are welcome! Please submit pull requests to the main Scylla repository.

## Support

- GitHub Issues: https://github.com/NtQuery/Scylla/issues
- Documentation: https://github.com/NtQuery/Scylla/wiki
