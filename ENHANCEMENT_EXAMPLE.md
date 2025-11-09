# Enhancement Example: Enhanced CLI with Full Functionality

This document shows a practical implementation of enhanced CLI functionality - one of the high-priority quick wins.

## Current State vs Enhanced State

### Current CLI (Basic)
```bash
scylla-cli info  # Just shows platform info
```

### Enhanced CLI (Proposed)
```bash
# Full PE analysis
scylla-cli analyze suspicious.exe

# Process dumping
scylla-cli dump --pid 1234 --output dump.exe --fix-iat

# IAT reconstruction
scylla-cli rebuild --file packed.exe --iat 0x401000 --output fixed.exe

# Batch processing
scylla-cli batch --input samples/ --output results/ --format json

# Plugin support
scylla-cli plugin list
scylla-cli plugin run imprec_compat sample.exe
```

## Implementation Plan

### 1. Command Structure

```cpp
// ScyllaCLI/Commands.h
namespace ScyllaCLI {

enum class CommandType {
    Info,
    Analyze,
    Dump,
    Rebuild,
    Batch,
    Plugin
};

struct CommandOptions {
    std::string inputFile;
    std::string outputFile;
    uint64_t iatAddress = 0;
    uint32_t iatSize = 0;
    uint32_t pid = 0;
    bool autoDetectIAT = true;
    bool fixOEP = false;
    std::string format = "text";  // text, json, xml
    bool verbose = false;
};

class CommandHandler {
public:
    virtual ~CommandHandler() = default;
    virtual int Execute(const CommandOptions& opts) = 0;
    virtual std::string GetHelp() const = 0;
};

// Specific command handlers
class AnalyzeCommand : public CommandHandler {
public:
    int Execute(const CommandOptions& opts) override;
    std::string GetHelp() const override;
};

class DumpCommand : public CommandHandler {
public:
    int Execute(const CommandOptions& opts) override;
    std::string GetHelp() const override;
};

class RebuildCommand : public CommandHandler {
public:
    int Execute(const CommandOptions& opts) override;
    std::string GetHelp() const override;
};

class BatchCommand : public CommandHandler {
public:
    int Execute(const CommandOptions& opts) override;
    std::string GetHelp() const override;
};

} // namespace ScyllaCLI
```

### 2. Analyze Command Implementation

```cpp
// ScyllaCLI/AnalyzeCommand.cpp
#include "Commands.h"
#include "../libScylla/PeParser.h"
#include "../libScylla/IATSearch.h"
#include "../libScylla/ApiReader.h"
#include <nlohmann/json.hpp>  // For JSON output

using json = nlohmann::json;

int AnalyzeCommand::Execute(const CommandOptions& opts) {
    if (opts.inputFile.empty()) {
        std::cerr << "Error: Input file required\n";
        return 1;
    }

    try {
        // Load PE file
        PeParser pe;
        if (!pe.LoadFile(opts.inputFile)) {
            std::cerr << "Error: Failed to load PE file\n";
            return 1;
        }

        // Perform analysis
        AnalysisResults results;
        results.fileName = opts.inputFile;
        results.architecture = pe.Is64Bit() ? "x64" : "x86";
        results.imageBase = pe.GetImageBase();
        results.entryPoint = pe.GetEntryPoint();

        // Analyze sections
        for (const auto& section : pe.GetSections()) {
            SectionInfo info;
            info.name = section.name;
            info.virtualAddress = section.virtualAddress;
            info.virtualSize = section.virtualSize;
            info.rawSize = section.rawSize;
            info.characteristics = section.characteristics;
            results.sections.push_back(info);
        }

        // Search for IAT
        if (opts.autoDetectIAT) {
            IATSearch iatSearch;
            iatSearch.ScanForIAT(&pe);

            if (iatSearch.IsIATFound()) {
                results.iatAddress = iatSearch.GetIATAddress();
                results.iatSize = iatSearch.GetIATSize();
                results.iatFound = true;
            }
        }

        // Reconstruct imports
        if (results.iatFound) {
            ApiReader apiReader;
            apiReader.ReadImports(&pe, results.iatAddress, results.iatSize);

            for (const auto& module : apiReader.GetModules()) {
                ModuleImports modImports;
                modImports.moduleName = module.name;

                for (const auto& import : module.imports) {
                    ImportInfo impInfo;
                    impInfo.name = import.name;
                    impInfo.ordinal = import.ordinal;
                    impInfo.address = import.address;
                    impInfo.valid = import.valid;
                    modImports.imports.push_back(impInfo);
                }

                results.modules.push_back(modImports);
            }
        }

        // Output results
        if (opts.format == "json") {
            OutputJSON(results, opts.outputFile);
        } else if (opts.format == "xml") {
            OutputXML(results, opts.outputFile);
        } else {
            OutputText(results, opts.verbose);
        }

        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}

void AnalyzeCommand::OutputJSON(const AnalysisResults& results,
                                const std::string& outputFile) {
    json j;

    j["file"] = results.fileName;
    j["architecture"] = results.architecture;
    j["image_base"] = FormatHex(results.imageBase);
    j["entry_point"] = FormatHex(results.entryPoint);

    // Sections
    j["sections"] = json::array();
    for (const auto& section : results.sections) {
        json sec;
        sec["name"] = section.name;
        sec["virtual_address"] = FormatHex(section.virtualAddress);
        sec["virtual_size"] = section.virtualSize;
        sec["raw_size"] = section.rawSize;
        sec["characteristics"] = FormatHex(section.characteristics);
        j["sections"].push_back(sec);
    }

    // IAT
    if (results.iatFound) {
        j["iat"]["address"] = FormatHex(results.iatAddress);
        j["iat"]["size"] = results.iatSize;

        // Imports
        j["imports"] = json::array();
        for (const auto& module : results.modules) {
            json mod;
            mod["name"] = module.moduleName;
            mod["imports"] = json::array();

            for (const auto& imp : module.imports) {
                json import;
                import["name"] = imp.name;
                import["ordinal"] = imp.ordinal;
                import["address"] = FormatHex(imp.address);
                import["valid"] = imp.valid;
                mod["imports"].push_back(import);
            }

            j["imports"].push_back(mod);
        }
    }

    // Output to file or stdout
    std::string jsonStr = j.dump(2);  // Pretty print with 2-space indent

    if (!outputFile.empty()) {
        std::ofstream out(outputFile);
        out << jsonStr;
    } else {
        std::cout << jsonStr << std::endl;
    }
}

void AnalyzeCommand::OutputText(const AnalysisResults& results, bool verbose) {
    std::cout << "═══════════════════════════════════════════════════════════\n";
    std::cout << "Scylla Analysis Results\n";
    std::cout << "═══════════════════════════════════════════════════════════\n\n";

    std::cout << "File: " << results.fileName << "\n";
    std::cout << "Architecture: " << results.architecture << "\n";
    std::cout << "Image Base: " << FormatHex(results.imageBase) << "\n";
    std::cout << "Entry Point: " << FormatHex(results.entryPoint) << "\n\n";

    // Sections
    std::cout << "Sections (" << results.sections.size() << "):\n";
    std::cout << "───────────────────────────────────────────────────────────\n";
    std::cout << std::setw(10) << std::left << "Name"
              << std::setw(12) << "VirtAddr"
              << std::setw(12) << "VirtSize"
              << std::setw(12) << "RawSize"
              << std::setw(12) << "Flags\n";
    std::cout << "───────────────────────────────────────────────────────────\n";

    for (const auto& section : results.sections) {
        std::cout << std::setw(10) << std::left << section.name
                  << std::setw(12) << FormatHex(section.virtualAddress)
                  << std::setw(12) << FormatSize(section.virtualSize)
                  << std::setw(12) << FormatSize(section.rawSize)
                  << std::setw(12) << FormatFlags(section.characteristics) << "\n";
    }

    std::cout << "\n";

    // IAT
    if (results.iatFound) {
        std::cout << "Import Address Table:\n";
        std::cout << "───────────────────────────────────────────────────────────\n";
        std::cout << "Address: " << FormatHex(results.iatAddress) << "\n";
        std::cout << "Size: " << FormatSize(results.iatSize) << "\n\n";

        // Imports
        std::cout << "Imports (" << results.modules.size() << " modules):\n";
        std::cout << "───────────────────────────────────────────────────────────\n";

        for (const auto& module : results.modules) {
            std::cout << "\n[" << module.moduleName << "] - "
                      << module.imports.size() << " imports\n";

            if (verbose) {
                for (const auto& imp : module.imports) {
                    std::cout << "  " << FormatHex(imp.address) << " ";

                    if (imp.valid) {
                        std::cout << "✓ ";
                    } else {
                        std::cout << "✗ ";
                    }

                    if (!imp.name.empty()) {
                        std::cout << imp.name;
                    } else {
                        std::cout << "Ordinal " << imp.ordinal;
                    }
                    std::cout << "\n";
                }
            }
        }
    } else {
        std::cout << "IAT: Not found (use --iat-address to specify manually)\n";
    }

    std::cout << "\n═══════════════════════════════════════════════════════════\n";
}
```

### 3. Dump Command Implementation

```cpp
// ScyllaCLI/DumpCommand.cpp
int DumpCommand::Execute(const CommandOptions& opts) {
    if (opts.pid == 0) {
        std::cerr << "Error: Process ID required (--pid)\n";
        return 1;
    }

    if (opts.outputFile.empty()) {
        std::cerr << "Error: Output file required (--output)\n";
        return 1;
    }

    try {
        // Create platform abstraction
        auto platform = Platform::CreatePlatform();

        // Open process
        if (!platform->OpenProcess(opts.pid)) {
            std::cerr << "Error: Failed to open process " << opts.pid << "\n";
            std::cerr << "Hint: Try running with elevated privileges\n";
            return 1;
        }

        std::cout << "Attached to process " << opts.pid << "\n";

        // Get process path
        auto processPath = platform->GetProcessPath();
        std::cout << "Process: " << WStringToString(processPath) << "\n";

        // Enumerate modules
        std::vector<Platform::ModuleInfo> modules;
        if (!platform->EnumerateModules(modules)) {
            std::cerr << "Error: Failed to enumerate modules\n";
            return 1;
        }

        if (modules.empty()) {
            std::cerr << "Error: No modules found\n";
            return 1;
        }

        // Get main module
        auto& mainModule = modules[0];
        std::cout << "Main module: " << WStringToString(mainModule.name) << "\n";
        std::cout << "Base address: " << FormatHex(mainModule.baseAddress) << "\n";
        std::cout << "Size: " << FormatSize(mainModule.size) << "\n";

        // Dump memory
        std::vector<uint8_t> dumpedData(mainModule.size);
        if (!platform->ReadMemory(mainModule.baseAddress,
                                  dumpedData.data(),
                                  dumpedData.size())) {
            std::cerr << "Error: Failed to read process memory\n";
            return 1;
        }

        std::cout << "Dumped " << FormatSize(dumpedData.size()) << " bytes\n";

        // Fix PE header if needed
        PeParser pe;
        pe.LoadFromMemory(dumpedData.data(), dumpedData.size(), mainModule.baseAddress);

        // Fix IAT if requested
        if (opts.autoDetectIAT || opts.iatAddress != 0) {
            std::cout << "Fixing import table...\n";

            IATSearch iatSearch;
            uint64_t iatAddr = opts.iatAddress;
            uint32_t iatSize = opts.iatSize;

            if (opts.autoDetectIAT) {
                iatSearch.ScanForIAT(&pe);
                if (iatSearch.IsIATFound()) {
                    iatAddr = iatSearch.GetIATAddress();
                    iatSize = iatSearch.GetIATSize();
                    std::cout << "IAT found at: " << FormatHex(iatAddr) << "\n";
                }
            }

            if (iatAddr != 0) {
                ImportRebuilder rebuilder;
                rebuilder.RebuildImports(&pe, iatAddr, iatSize);
                std::cout << "Import table fixed\n";
            }
        }

        // Fix OEP if requested
        if (opts.fixOEP) {
            // Implementation would go here
            std::cout << "OEP fix not yet implemented\n";
        }

        // Save to file
        if (!pe.SaveToFile(opts.outputFile)) {
            std::cerr << "Error: Failed to save dump\n";
            return 1;
        }

        std::cout << "Dump saved to: " << opts.outputFile << "\n";

        platform->CloseProcess();
        return 0;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
```

### 4. Batch Processing Command

```cpp
// ScyllaCLI/BatchCommand.cpp
int BatchCommand::Execute(const CommandOptions& opts) {
    if (opts.inputFile.empty()) {
        std::cerr << "Error: Input directory required\n";
        return 1;
    }

    try {
        // Find all PE files in directory
        auto files = FindPEFiles(opts.inputFile);

        if (files.empty()) {
            std::cout << "No PE files found in " << opts.inputFile << "\n";
            return 0;
        }

        std::cout << "Found " << files.size() << " PE files\n";
        std::cout << "Starting batch analysis...\n\n";

        // Results collection
        std::vector<AnalysisResults> allResults;
        size_t successCount = 0;
        size_t failCount = 0;

        // Process each file
        for (size_t i = 0; i < files.size(); i++) {
            const auto& file = files[i];

            std::cout << "[" << (i + 1) << "/" << files.size() << "] "
                      << file << "... ";

            try {
                CommandOptions fileOpts = opts;
                fileOpts.inputFile = file;

                AnalyzeCommand analyzer;
                if (analyzer.Execute(fileOpts) == 0) {
                    std::cout << "✓ OK\n";
                    successCount++;
                } else {
                    std::cout << "✗ FAILED\n";
                    failCount++;
                }

            } catch (const std::exception& e) {
                std::cout << "✗ ERROR: " << e.what() << "\n";
                failCount++;
            }
        }

        // Summary
        std::cout << "\n═══════════════════════════════════════════════════════════\n";
        std::cout << "Batch Analysis Complete\n";
        std::cout << "═══════════════════════════════════════════════════════════\n";
        std::cout << "Total files: " << files.size() << "\n";
        std::cout << "Successful: " << successCount << "\n";
        std::cout << "Failed: " << failCount << "\n";

        return (failCount == 0) ? 0 : 1;

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
```

### 5. Main CLI Entry Point

```cpp
// ScyllaCLI/cli_main.cpp (enhanced)
#include "Commands.h"
#include <map>

using namespace ScyllaCLI;

void printUsage(const char* progName) {
    std::cout << "Scylla CLI v0.9.9 - PE Import Table Reconstruction Tool\n\n";
    std::cout << "Usage: " << progName << " <command> [options]\n\n";
    std::cout << "Commands:\n";
    std::cout << "  info                          Show platform information\n";
    std::cout << "  analyze <file>                Analyze PE file\n";
    std::cout << "  dump                          Dump process memory\n";
    std::cout << "  rebuild <file>                Rebuild import table\n";
    std::cout << "  batch <directory>             Batch process files\n";
    std::cout << "  plugin <action>               Manage plugins\n\n";
    std::cout << "Options:\n";
    std::cout << "  -h, --help                    Show this help\n";
    std::cout << "  -v, --verbose                 Verbose output\n";
    std::cout << "  -o, --output <file>           Output file\n";
    std::cout << "  --format <fmt>                Output format (text|json|xml)\n";
    std::cout << "  --pid <pid>                   Process ID (for dump)\n";
    std::cout << "  --iat <address>               IAT address (hex)\n";
    std::cout << "  --iat-size <size>             IAT size (hex)\n";
    std::cout << "  --auto-iat                    Auto-detect IAT (default)\n";
    std::cout << "  --fix-oep                     Fix original entry point\n\n";
    std::cout << "Examples:\n";
    std::cout << "  " << progName << " analyze packed.exe\n";
    std::cout << "  " << progName << " analyze packed.exe --format json -o result.json\n";
    std::cout << "  " << progName << " dump --pid 1234 --output dump.exe\n";
    std::cout << "  " << progName << " rebuild packed.exe --iat 0x401000\n";
    std::cout << "  " << progName << " batch ./samples --format json\n\n";
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printUsage(argv[0]);
        return 1;
    }

    // Parse command
    std::string command = argv[1];

    // Parse options
    CommandOptions opts;

    for (int i = 2; i < argc; i++) {
        std::string arg = argv[i];

        if (arg == "-h" || arg == "--help") {
            printUsage(argv[0]);
            return 0;
        }
        else if (arg == "-v" || arg == "--verbose") {
            opts.verbose = true;
        }
        else if (arg == "-o" || arg == "--output") {
            if (i + 1 < argc) opts.outputFile = argv[++i];
        }
        else if (arg == "--format") {
            if (i + 1 < argc) opts.format = argv[++i];
        }
        else if (arg == "--pid") {
            if (i + 1 < argc) opts.pid = std::stoul(argv[++i]);
        }
        else if (arg == "--iat") {
            if (i + 1 < argc) opts.iatAddress = std::stoull(argv[++i], nullptr, 16);
        }
        else if (arg == "--iat-size") {
            if (i + 1 < argc) opts.iatSize = std::stoul(argv[++i], nullptr, 16);
        }
        else if (arg == "--auto-iat") {
            opts.autoDetectIAT = true;
        }
        else if (arg == "--fix-oep") {
            opts.fixOEP = true;
        }
        else if (arg[0] != '-') {
            // Positional argument (input file)
            if (opts.inputFile.empty()) {
                opts.inputFile = arg;
            }
        }
    }

    // Execute command
    try {
        std::unique_ptr<CommandHandler> handler;

        if (command == "info") {
            printPlatformInfo();
            return 0;
        }
        else if (command == "analyze") {
            handler = std::make_unique<AnalyzeCommand>();
        }
        else if (command == "dump") {
            handler = std::make_unique<DumpCommand>();
        }
        else if (command == "rebuild") {
            handler = std::make_unique<RebuildCommand>();
        }
        else if (command == "batch") {
            handler = std::make_unique<BatchCommand>();
        }
        else {
            std::cerr << "Unknown command: " << command << "\n";
            printUsage(argv[0]);
            return 1;
        }

        return handler->Execute(opts);

    } catch (const std::exception& e) {
        std::cerr << "Fatal error: " << e.what() << "\n";
        return 1;
    }
}
```

## Usage Examples

### Example 1: Analyze a packed executable
```bash
$ scylla-cli analyze packed.exe --verbose

═══════════════════════════════════════════════════════════
Scylla Analysis Results
═══════════════════════════════════════════════════════════

File: packed.exe
Architecture: x86
Image Base: 0x00400000
Entry Point: 0x00401000

Sections (3):
───────────────────────────────────────────────────────────
Name       VirtAddr     VirtSize     RawSize      Flags
───────────────────────────────────────────────────────────
.text      0x00001000   32.0 KB      32.0 KB      RWX
.data      0x00009000   8.0 KB       4.0 KB       RW
.rsrc      0x0000B000   4.0 KB       4.0 KB       R

Import Address Table:
───────────────────────────────────────────────────────────
Address: 0x00405000
Size: 2048 bytes

Imports (2 modules):
───────────────────────────────────────────────────────────

[kernel32.dll] - 15 imports
  0x00405000 ✓ GetProcAddress
  0x00405004 ✓ LoadLibraryA
  0x00405008 ✓ VirtualProtect
  ...

[user32.dll] - 5 imports
  0x00405040 ✓ MessageBoxA
  0x00405044 ✓ GetActiveWindow
  ...

═══════════════════════════════════════════════════════════
```

### Example 2: Export to JSON
```bash
$ scylla-cli analyze packed.exe --format json -o analysis.json
$ cat analysis.json
{
  "file": "packed.exe",
  "architecture": "x86",
  "image_base": "0x00400000",
  "entry_point": "0x00401000",
  "sections": [
    {
      "name": ".text",
      "virtual_address": "0x00001000",
      "virtual_size": 32768,
      "raw_size": 32768,
      "characteristics": "0x60000020"
    }
  ],
  "iat": {
    "address": "0x00405000",
    "size": 2048
  },
  "imports": [
    {
      "name": "kernel32.dll",
      "imports": [
        {
          "name": "GetProcAddress",
          "ordinal": 0,
          "address": "0x00405000",
          "valid": true
        }
      ]
    }
  ]
}
```

### Example 3: Dump and fix a running process
```bash
$ scylla-cli dump --pid 1234 --output dump.exe --auto-iat

Attached to process 1234
Process: C:\Program Files\App\app.exe
Main module: app.exe
Base address: 0x00400000
Size: 1.2 MB
Dumped 1.2 MB bytes
Fixing import table...
IAT found at: 0x00405000
Import table fixed
Dump saved to: dump.exe
```

### Example 4: Batch processing
```bash
$ scylla-cli batch ./malware_samples --format json --output results/

Found 150 PE files
Starting batch analysis...

[1/150] sample1.exe... ✓ OK
[2/150] sample2.exe... ✓ OK
[3/150] sample3.exe... ✗ FAILED
...

═══════════════════════════════════════════════════════════
Batch Analysis Complete
═══════════════════════════════════════════════════════════
Total files: 150
Successful: 147
Failed: 3
```

## Integration with Scripts

### Python Example
```python
#!/usr/bin/env python3
import subprocess
import json

# Analyze file
result = subprocess.run([
    'scylla-cli', 'analyze', 'sample.exe',
    '--format', 'json'
], capture_output=True, text=True)

# Parse JSON
data = json.loads(result.stdout)

# Check for suspicious imports
suspicious_apis = ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread']

for module in data.get('imports', []):
    for imp in module.get('imports', []):
        if imp['name'] in suspicious_apis:
            print(f"⚠️  Suspicious API: {imp['name']}")
```

### Bash Example
```bash
#!/bin/bash
# Process all samples and generate report

mkdir -p results

for file in samples/*.exe; do
    echo "Processing $file..."
    scylla-cli analyze "$file" \
        --format json \
        --output "results/$(basename $file).json"
done

# Generate summary
echo "Analysis complete:"
echo "Total files: $(ls samples/*.exe | wc -l)"
echo "Results saved to results/"
```

## Benefits of Enhanced CLI

1. **Automation** - Easy to script and integrate
2. **CI/CD** - Can be used in build pipelines
3. **Remote Analysis** - SSH-friendly, no GUI needed
4. **Batch Processing** - Analyze thousands of samples
5. **Tool Integration** - Works with other analysis tools
6. **Structured Output** - JSON/XML for parsing

## Next Steps

1. Implement command handlers
2. Add JSON/XML output support
3. Integrate with existing Scylla core
4. Add progress indicators
5. Implement plugin system
6. Add more output formats (CSV, HTML reports)
7. Create comprehensive test suite

