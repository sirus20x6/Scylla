# Scylla Configuration System

## Overview

Scylla's configuration system provides flexible, reusable profiles for customizing analysis behavior. You can save and load configurations, use built-in profiles optimized for different scenarios, or create custom profiles tailored to your specific needs.

## Features

- **Built-in Profiles**: Pre-configured profiles for common use cases
- **Custom Profiles**: Create and save your own configurations
- **JSON Storage**: Human-readable configuration files
- **Dynamic Adjustment**: Modify settings at runtime
- **Profile Management**: Import, export, duplicate, and rename profiles
- **Validation**: Automatic validation of configuration values

## Configuration Categories

Each profile contains four main configuration sections:

### 1. Analysis Configuration

Controls how PE files are analyzed:

```cpp
AnalysisConfig {
    bool enableIATScanning;        // Enable IAT scanning
    bool deepIATScan;              // Deep scan (slower, more thorough)
    size_t iatScanThreads;         // Number of threads (0 = auto)
    size_t maxIATEntries;          // Safety limit
    bool resolveImportNames;       // Resolve import function names
    bool validateImportAddresses;  // Validate import addresses
    bool rebuildForwarders;        // Rebuild forwarded imports
    bool analyzeSections;          // Analyze PE sections
    bool calculateSectionHashes;   // Calculate section hashes
    bool detectAnomalies;          // Detect anomalies
    bool scanFullMemory;           // Scan all memory regions
    size_t memoryChunkSize;        // Memory chunk size for scanning
    std::chrono::seconds scanTimeout;        // Maximum scan time
    std::chrono::seconds apiResolveTimeout;  // API resolution timeout
}
```

### 2. Packer Detection Configuration

Controls packer detection behavior:

```cpp
PackerDetectionConfig {
    bool enableSignatureDetection;  // Signature-based detection
    bool enableHeuristicDetection;  // Heuristic analysis
    bool enableEntropyAnalysis;     // Entropy calculation
    double entropyThreshold;        // Shannon entropy threshold (0-8)
    int minConfidence;              // Minimum confidence to report (0-100)
    int suspicionThreshold;         // Heuristic suspicion threshold
    std::string signatureDatabasePath;  // Custom signature DB path
    bool autoUpdateSignatures;      // Auto-update signatures
    bool analyzeOverlay;            // Analyze PE overlay
    bool analyzeResources;          // Analyze resources section
    bool detectCustomPackers;       // Detect custom/unknown packers
    size_t maxSignaturesToTest;     // Signature limit
    bool stopOnFirstMatch;          // Stop at first match (faster)
}
```

### 3. Performance Configuration

Controls performance and resource usage:

```cpp
PerformanceConfig {
    size_t workerThreads;           // Worker threads (0 = auto)
    bool enableParallelProcessing;  // Enable multi-threading
    bool enableCaching;             // Enable caching system
    size_t apiCacheSize;            // API cache size
    size_t peCacheSize;             // PE analysis cache size
    std::chrono::minutes cacheTTL;  // Cache time-to-live
    size_t maxCacheMemoryMB;        // Maximum cache memory
    bool useMemoryMapping;          // Use memory-mapped I/O
    size_t ioBufferSize;            // I/O buffer size
    bool asyncIO;                   // Asynchronous I/O
}
```

### 4. Output Configuration

Controls output format and verbosity:

```cpp
OutputConfig {
    Format defaultFormat;           // Text, JSON, XML, CSV
    Verbosity verbosity;            // Minimal, Normal, Detailed, Debug
    bool showSections;              // Show section info
    bool showImports;               // Show imports
    bool showExports;               // Show exports
    bool showResources;             // Show resources
    bool showSecurity;              // Show security features
    bool showPacker;                // Show packer detection results
    bool showHashes;                // Show file/section hashes
    bool colorOutput;               // ANSI color output
    bool prettyPrint;               // Pretty-print JSON/XML
    int indentSize;                 // Indentation size
    std::string outputDirectory;    // Output directory
    bool timestampFiles;            // Add timestamps to filenames
    bool overwriteExisting;         // Overwrite existing files
}
```

## Built-in Profiles

### Default Profile

Balanced configuration suitable for general use:

```bash
scylla analyze --profile default sample.exe
```

- Moderate IAT scanning
- Standard packer detection
- Caching enabled
- Normal verbosity

### Quick Scan Profile

Fast scanning with minimal details:

```bash
scylla analyze --profile quick-scan sample.exe
```

**Optimizations:**
- ✓ Signature detection only (no heuristics)
- ✓ Skip section analysis
- ✓ Stop on first packer match
- ✓ Minimal output

**Use Cases:**
- Rapid triage of multiple files
- Quick packer identification
- Batch processing

**Performance:** ~5x faster than default

### Deep Analysis Profile

Comprehensive analysis with all features:

```bash
scylla analyze --profile deep-analysis sample.exe
```

**Features:**
- ✓ Deep IAT scanning
- ✓ All packer detection methods
- ✓ Section hash calculation
- ✓ Full memory scanning
- ✓ Resource analysis
- ✓ Detailed JSON output

**Use Cases:**
- Detailed malware analysis
- Forensic investigation
- Complete documentation

**Performance:** 2-3x slower than default

### Malware Analysis Profile

Optimized for analyzing packed malware:

```bash
scylla analyze --profile malware-analysis sample.exe
```

**Features:**
- ✓ Aggressive packer detection (lower thresholds)
- ✓ Deep scanning enabled
- ✓ Entropy analysis
- ✓ Custom packer detection
- ✓ Section hashing
- ✓ Timestamped output files

**Use Cases:**
- Malware reverse engineering
- Packed sample analysis
- Security research

### Performance Profile

Maximum performance for batch processing:

```bash
scylla batch --profile performance *.exe
```

**Optimizations:**
- ✓ All CPU cores utilized
- ✓ Large cache sizes (1 GB)
- ✓ Memory-mapped I/O
- ✓ Signature detection only
- ✓ Compact output

**Use Cases:**
- Processing hundreds of files
- Automated scanning
- High-throughput analysis

**Performance:** Up to 100x faster for cached files

## Usage Examples

### Command-Line Interface

```bash
# Use built-in profile
scylla analyze --profile malware-analysis packed.exe

# Create custom profile
scylla config create my-profile --based-on deep-analysis

# Modify profile settings
scylla config set my-profile analysis.deepIATScan true
scylla config set my-profile packerDetection.entropyThreshold 6.5

# List all profiles
scylla config list

# Show profile details
scylla config show my-profile

# Export profile
scylla config export my-profile -o my-profile.json

# Import profile
scylla config import shared-profile.json
```

### Programmatic Usage

```cpp
#include "Configuration.h"

using namespace Scylla;

// Load a profile
auto& configMgr = ConfigurationManager::Instance();
configMgr.LoadProfile("malware-analysis");

// Get current configuration
const auto& profile = configMgr.GetCurrentProfile();

// Use configuration settings
if (profile.analysis.deepIATScan) {
    // Perform deep IAT scan
}

// Dynamically adjust settings
auto& currentProfile = configMgr.GetCurrentProfile();
currentProfile.packerDetection.entropyThreshold = 6.0;

// Create custom profile
configMgr.CreateProfile("my-config", "Custom configuration");
auto* myProfile = configMgr.GetProfile("my-config");
myProfile->analysis.deepIATScan = true;
myProfile->performance.workerThreads = 8;

// Save to disk
configMgr.SaveProfile("my-config");
```

### Dynamic Configuration

Adjust settings based on file characteristics:

```cpp
auto& configMgr = ConfigurationManager::Instance();
configMgr.LoadProfile("quick-scan");

auto& profile = configMgr.GetCurrentProfile();

// Adjust based on file size
if (fileSize > 10 * 1024 * 1024) {  // > 10 MB
    profile.performance.apiCacheSize = 2000;
    profile.analysis.memoryChunkSize = 2 * 1024 * 1024;
}

// Adjust based on entropy
double entropy = CalculateEntropy(fileData);
if (entropy > 7.5) {  // Likely packed
    profile.packerDetection.enableHeuristicDetection = true;
    profile.analysis.deepIATScan = true;
}
```

## Configuration Files

### Location

Configuration files are stored in:

- **Windows**: `%APPDATA%\Scylla\config\`
- **Linux**: `~/.config/scylla/`
- **macOS**: `~/Library/Application Support/Scylla/config/`

### Format

Configurations are stored as JSON files:

```json
{
  "name": "malware-analysis",
  "description": "Optimized for analyzing packed malware samples",
  "version": "1.0",
  "analysis": {
    "enableIATScanning": true,
    "deepIATScan": true,
    "iatScanThreads": 0,
    "entropyThreshold": 6.5
  },
  "packerDetection": {
    "enableSignatureDetection": true,
    "enableHeuristicDetection": true,
    "minConfidence": 40
  },
  "performance": {
    "enableCaching": true,
    "apiCacheSize": 1500,
    "maxCacheMemoryMB": 300
  },
  "output": {
    "defaultFormat": "json",
    "verbosity": "detailed",
    "prettyPrint": true
  }
}
```

## Profile Management

### Creating Profiles

```cpp
// From scratch
configMgr.CreateProfile("my-profile", "My custom configuration");

// Duplicate existing
configMgr.DuplicateProfile("malware-analysis", "my-malware-config");

// Based on default with modifications
auto profile = configMgr.CreateDefaultProfile();
profile.name = "custom";
profile.analysis.deepIATScan = true;
configMgr.SetCurrentProfile(profile);
configMgr.SaveProfile("custom");
```

### Importing/Exporting

```cpp
// Export to share with team
configMgr.ExportProfile("my-profile", "/path/to/my-profile.json");

// Import from colleague
std::string profileName;
configMgr.ImportProfile("/path/to/shared-profile.json", profileName);
```

### Validation

```cpp
ConfigurationProfile profile = /* ... */;
std::vector<std::string> errors;

if (!configMgr.ValidateProfile(profile, errors)) {
    std::cout << "Validation failed:\n";
    for (const auto& error : errors) {
        std::cout << "  • " << error << "\n";
    }
}
```

## Best Practices

### 1. Start with Built-in Profiles

Begin with a built-in profile that matches your use case:

- **General use**: `default`
- **Quick checks**: `quick-scan`
- **Detailed analysis**: `deep-analysis`
- **Malware analysis**: `malware-analysis`
- **Batch processing**: `performance`

### 2. Create Custom Profiles for Specific Tasks

Duplicate and customize profiles for repeated tasks:

```bash
# Create CTF analysis profile
scylla config duplicate deep-analysis ctf-analysis
scylla config set ctf-analysis output.showHashes true
scylla config set ctf-analysis analysis.calculateSectionHashes true
```

### 3. Adjust Dynamically for Special Cases

Modify settings at runtime for one-off adjustments:

```cpp
configMgr.LoadProfile("default");
auto& profile = configMgr.GetCurrentProfile();

// One-time adjustment
profile.analysis.scanTimeout = std::chrono::seconds(300);
```

### 4. Version Control Your Profiles

Store custom profiles in version control:

```bash
# Export profiles
scylla config export team-malware -o profiles/team-malware.json
scylla config export team-performance -o profiles/team-performance.json

# Add to git
git add profiles/*.json
```

### 5. Validate Before Sharing

Always validate profiles before sharing:

```cpp
std::vector<std::string> errors;
if (configMgr.ValidateProfile(profile, errors)) {
    configMgr.ExportProfile(profile.name, sharePath);
} else {
    // Fix errors first
}
```

## Performance Tuning

### Caching Settings

```cpp
// High-throughput analysis
profile.performance.enableCaching = true;
profile.performance.apiCacheSize = 5000;
profile.performance.peCacheSize = 200;
profile.performance.maxCacheMemoryMB = 1000;
```

### Threading Configuration

```cpp
// Maximize CPU usage
profile.performance.workerThreads = std::thread::hardware_concurrency();
profile.performance.enableParallelProcessing = true;

// Or limit resources
profile.performance.workerThreads = 2;
```

### Memory Optimization

```cpp
// Large file handling
profile.performance.useMemoryMapping = true;
profile.analysis.memoryChunkSize = 4 * 1024 * 1024;  // 4 MB chunks
```

## Troubleshooting

### Profile Not Found

```
Error: Profile 'my-profile' not found
```

**Solution:** Check available profiles with `scylla config list`

### Validation Errors

```
Error: Entropy threshold must be between 0.0 and 8.0
```

**Solution:** Fix configuration values to be within valid ranges

### Performance Issues

If analysis is slow:
1. Try `quick-scan` or `performance` profile
2. Disable deep scanning: `deepIATScan = false`
3. Disable heuristics: `enableHeuristicDetection = false`
4. Increase cache sizes

### High Memory Usage

If memory consumption is too high:
1. Reduce cache sizes: `apiCacheSize`, `peCacheSize`
2. Lower `maxCacheMemoryMB`
3. Disable full memory scanning: `scanFullMemory = false`

## See Also

- [Enhancement Roadmap](../ROADMAP.md) - Future configuration features
- [Build Instructions](../BUILD.md) - Building with configuration support
- [Packer Detection](PACKER_DETECTION.md) - Packer detection settings
- [Caching System](CACHING.md) - Cache configuration details
