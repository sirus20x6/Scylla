# Scylla Dump Command

## Overview

The Dump Command enables dumping process memory from running processes, essential for unpacking malware that unpacks itself in memory. It provides fine-grained control over what memory regions to dump and supports automatic PE reconstruction.

## Key Features

- **Process Memory Dumping**: Extract memory regions from running processes
- **PE Reconstruction**: Automatically rebuild PE headers and structure
- **IAT Fixing**: Reconstruct Import Address Table
- **Selective Dumping**: Filter regions by permissions, type, size, or address range
- **Batch Operations**: Dump multiple processes simultaneously
- **Metadata Export**: Save dump information as JSON
- **Cross-Platform**: Works on Windows and Linux (via ptrace)

## Command-Line Usage

### Basic Dump

```bash
# Dump by process ID
scylla dump --pid 1234 -o unpacked.exe

# Dump by process name
scylla dump --process notepad.exe -o notepad_dump.exe

# Quick dump (executable regions + PE rebuild)
scylla dump --pid 1234 --quick -o output.exe
```

### Advanced Options

```bash
# Dump only executable regions
scylla dump --pid 1234 --executable-only -o code.bin

# Dump with PE reconstruction
scylla dump --pid 1234 --rebuild-pe --fix-imports -o rebuilt.exe

# Dump specific address range
scylla dump --pid 1234 --start 0x400000 --end 0x500000 -o region.bin

# Dump full process (all regions)
scylla dump --pid 1234 --full --output-dir full_dump/

# Include metadata
scylla dump --pid 1234 --metadata -o dump.exe
```

### Filtering Options

```bash
# Filter by region size
scylla dump --pid 1234 --min-size 4096 --max-size 10485760 -o filtered.bin

# Dump only modified regions
scylla dump --pid 1234 --modified-only -o unpacked_code.bin

# Exclude private regions
scylla dump --pid 1234 --exclude-private -o dump.exe
```

### Batch Dumping

```bash
# Dump all Chrome processes
scylla dump --name chrome --batch --output-dir chrome_dumps/

# Dump multiple PIDs
scylla dump --pids 1234,5678,9012 --output-dir dumps/
```

## Programmatic API

### Quick Dump Example

```cpp
#include "DumpCommand.h"

using namespace Scylla::CLI;

// Simple dump
DumpCommand dumper;
uint32_t pid = 1234;
auto result = dumper.QuickDump(pid, "unpacked.exe");

if (result.success) {
    std::cout << "Dumped: " << result.outputFile << "\n";
    std::cout << "Size: " << result.bytesRead << " bytes\n";
}
```

### Custom Configuration

```cpp
// Configure dump parameters
DumpConfig config = {};
config.processId = 1234;
config.outputPath = "unpacked.exe";

// Dump options
config.dumpExecutableOnly = true;  // Only RX/RWX regions
config.rebuildPE = true;           // Rebuild PE structure
config.fixImports = true;          // Fix Import Address Table
config.includeMetadata = true;     // Save JSON metadata

// Region filters
config.minRegionSize = 4096;       // Minimum 4 KB
config.startAddress = 0x400000;    // Start from image base
config.endAddress = 0x500000;      // Up to this address

// Execute dump
DumpCommand dumper;
auto result = dumper.Execute(config);

if (result.success) {
    std::cout << "Success!\n";
    std::cout << "  File: " << result.outputFile << "\n";
    std::cout << "  Bytes: " << result.bytesRead << "\n";
    std::cout << "  Regions: " << result.regionsRead << "\n";

    if (result.peRebuilt) {
        std::cout << "  Sections: " << result.sectionsRecovered << "\n";
        std::cout << "  Imports: " << result.importsFixed << "\n";
    }
}
```

### Process Enumeration

```cpp
// List all processes
auto allPids = DumpCommand::ListProcesses();
std::cout << "Total processes: " << allPids.size() << "\n";

// Find by name
auto pids = DumpCommand::FindProcessByName("malware.exe");
if (!pids.empty()) {
    std::cout << "Found PID: " << pids[0] << "\n";
}

// Enumerate memory regions
auto regions = DumpCommand::EnumerateRegions(pids[0]);
for (const auto& region : regions) {
    std::cout << "0x" << std::hex << region.baseAddress
              << " - " << (region.size / 1024) << " KB - "
              << region.protectionStr << "\n";
}

// List loaded modules
auto modules = DumpCommand::EnumerateModules(pids[0]);
for (const auto& module : modules) {
    std::cout << "Module: " << module << "\n";
}
```

### Batch Dumping

```cpp
BatchDumper batchDumper;

// Dump multiple processes
std::vector<uint32_t> pids = {1234, 5678, 9012};

DumpConfig baseConfig = {};
baseConfig.outputPath = "dumps/process.exe";
baseConfig.dumpExecutableOnly = true;
baseConfig.rebuildPE = true;

auto results = batchDumper.DumpAllProcesses(pids, baseConfig);

// Get statistics
auto stats = batchDumper.GetStatistics();
std::cout << "Successful: " << stats.successfulDumps << "/"
          << stats.totalProcesses << "\n";
std::cout << "Total size: " << (stats.totalBytesWritten / 1024 / 1024)
          << " MB\n";
```

## Use Cases

### 1. Unpacking Malware

**Scenario**: Malware unpacks itself in memory after execution

```bash
# Step 1: Run malware in sandbox
start malware.exe

# Step 2: Wait for unpacking (monitor VirtualAlloc/VirtualProtect)
# Use process monitor or debugger to detect unpacking

# Step 3: Dump unpacked code
scylla dump --name malware.exe --executable-only --rebuild-pe -o unpacked.exe

# Step 4: Analyze dump
scylla analyze --profile malware-analysis unpacked.exe
```

**Programmatic**:
```cpp
// Find malware process
auto pids = DumpCommand::FindProcessByName("malware.exe");

// Wait for unpacking indicator (high entropy in new regions)
std::this_thread::sleep_for(std::chrono::seconds(5));

// Dump unpacked code
DumpConfig config = {};
config.processId = pids[0];
config.outputPath = "unpacked.exe";
config.dumpExecutableOnly = true;
config.rebuildPE = true;
config.fixImports = true;

DumpCommand dumper;
auto result = dumper.Execute(config);
```

### 2. Code Extraction from Running Process

**Scenario**: Extract specific code sections for analysis

```bash
# Dump main executable module only
scylla dump --pid 1234 --module main.exe -o main_dump.exe

# Dump specific DLL from process
scylla dump --pid 1234 --module user32.dll -o user32_dump.dll

# Dump code cave (specific address range)
scylla dump --pid 1234 --start 0x10000000 --end 0x10010000 -o codecave.bin
```

### 3. Dynamic Analysis Support

**Scenario**: Dump process at different execution stages

```bash
# Initial dump (before unpacking)
scylla dump --pid 1234 -o dump_initial.exe

# ... wait for unpacking ...

# After unpacking
scylla dump --pid 1234 --modified-only -o dump_unpacked.exe

# Compare dumps to identify unpacked regions
```

### 4. Forensic Analysis

**Scenario**: Full memory dump for forensics

```bash
# Complete memory dump
scylla dump --pid 1234 --full --output-dir forensic_dump/

# Dump includes:
# - All executable regions
# - All writable regions (heap, stack)
# - Memory-mapped files
# - Metadata JSON
```

### 5. Batch Malware Analysis

**Scenario**: Analyze multiple malware samples running simultaneously

```bash
# Dump all running malware samples
scylla dump --name malware_sample --batch --output-dir batch_dumps/

# Each process gets separate file:
# - batch_dumps/malware_sample_1234.exe
# - batch_dumps/malware_sample_5678.exe
# - etc.
```

## Memory Region Types

### Executable Regions (IMAGE)

- Contains loaded PE files (EXE, DLL)
- Typically has RX or RWX permissions
- **Use for**: Dumping main executable or DLLs

### Private Regions (PRIVATE)

- Process heap, stack, allocated memory
- Often RW permissions (changes to RWX if unpacked)
- **Use for**: Finding unpacked code

### Mapped Regions (MAPPED)

- Memory-mapped files
- Shared memory
- **Use for**: Extracting injected code

## Protection Flags

| Flag | Meaning | Typical Use |
|------|---------|-------------|
| R-- | Read-only | Data sections, resources |
| RW- | Read-Write | Heap, stack, data |
| R-X | Read-Execute | Code sections |
| RWX | Read-Write-Execute | ⚠ **Unpacked code**, shellcode |

**Note**: RWX regions are highly suspicious and often indicate unpacked malware.

## Output Formats

### Raw Binary Dump

```bash
scylla dump --pid 1234 --raw -o raw_dump.bin
```

- Pure memory content
- No PE headers
- Useful for shellcode analysis

### Rebuilt PE

```bash
scylla dump --pid 1234 --rebuild-pe -o rebuilt.exe
```

- Valid PE file
- Reconstructed headers and sections
- Fixed Import Address Table
- Can be analyzed with standard tools

### Split Regions

```bash
scylla dump --pid 1234 --split-regions --output-dir regions/
```

Output structure:
```
regions/
  ├── region_0000000000400000_65536.bin
  ├── region_0000000010000000_4096.bin
  ├── region_0000000020000000_8192.bin
  └── metadata.json
```

### Metadata JSON

```json
{
  "success": true,
  "processId": 1234,
  "outputFile": "dump.exe",
  "bytesRead": 524288,
  "regionsRead": 12,
  "imageBase": "0x400000",
  "entryPoint": "0x401000",
  "peRebuilt": true,
  "sectionsRecovered": 5,
  "importsFixed": 127,
  "warnings": [],
  "errors": []
}
```

## Error Handling

### Common Errors

**Access Denied**
```
Error: Failed to open process 1234
```
**Solution**: Run as Administrator (Windows) or with sudo (Linux)

**Process Not Found**
```
Error: Process 'malware.exe' not found
```
**Solution**: Verify process is running with `scylla ps` or Task Manager

**Read Failed**
```
Warning: Failed to read region at 0x400000
```
**Solution**: Process may have terminated or region was freed

### Retry Mechanism

```cpp
// Configure retry on read failures
config.retryCount = 3;  // Retry up to 3 times

// Execute with retries
auto result = dumper.Execute(config);
```

## Best Practices

### 1. Suspend Process Before Dumping

Prevents memory from changing during dump:

```cpp
config.suspendProcess = true;
```

### 2. Validate Dumps

Always check dump success:

```cpp
if (result.success && result.bytesRead > 0) {
    // Verify with PE parser
    if (IsPEValid(result.outputFile)) {
        // Proceed with analysis
    }
}
```

### 3. Filter Small Regions

Skip noise from tiny allocations:

```cpp
config.minRegionSize = 4096;  // 4 KB minimum
```

### 4. Check for RWX Regions

Indicator of unpacked code:

```cpp
auto regions = DumpCommand::EnumerateRegions(pid);
for (const auto& region : regions) {
    if (region.isReadable && region.isWritable && region.isExecutable) {
        std::cout << "Suspicious RWX region at 0x" << std::hex
                  << region.baseAddress << "\n";
    }
}
```

### 5. Save Metadata

Always save metadata for reproducibility:

```cpp
config.includeMetadata = true;
```

## Platform Differences

### Windows

- Uses `ReadProcessMemory` API
- Requires `PROCESS_VM_READ` permission
- Can enumerate with `CreateToolhelp32Snapshot`
- Memory regions from `VirtualQueryEx`

### Linux

- Uses `ptrace(PTRACE_ATTACH)` or `/proc/[pid]/mem`
- Requires `CAP_SYS_PTRACE` capability
- Process list from `/proc` filesystem
- Memory regions from `/proc/[pid]/maps`

## Security Considerations

### Permissions

**Windows**: Requires Administrator for most processes

**Linux**: Requires root or `CAP_SYS_PTRACE` capability

### Anti-Dump Techniques

Malware may detect and prevent dumping:

1. **Anti-Debugger Checks**: Detect ptrace on Linux
2. **Memory Encryption**: Encrypt code in memory
3. **Guard Pages**: Use PAGE_GUARD to detect reads
4. **Self-Modifying Code**: Change code during execution

**Mitigation**:
- Use stealth debugging techniques
- Dump at strategic execution points
- Consider using hardware-assisted debugging

## See Also

- [Analyze Command](ANALYZE_COMMAND.md) - Analyzing dumped files
- [Rebuild Command](REBUILD_COMMAND.md) - Fixing IAT in dumps
- [Configuration Profiles](CONFIGURATION.md) - Dump configuration profiles
- [Malware Analysis Guide](MALWARE_ANALYSIS.md) - Complete unpacking workflow
