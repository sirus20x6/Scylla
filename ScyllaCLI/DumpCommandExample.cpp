/*
 * Dump Command Usage Examples
 *
 * Demonstrates how to use Scylla's process dumping capabilities
 */

#include "DumpCommand.h"
#include <iostream>
#include <iomanip>

using namespace Scylla::CLI;

/*
 * Example 1: Quick Dump
 *
 * Simplest way to dump a process
 */
void QuickDumpExample() {
    std::cout << "=== Quick Dump Example ===\n\n";

    DumpCommand dumper;

    // Find process by name
    std::string processName = "notepad.exe";
    auto pids = DumpCommand::FindProcessByName(processName);

    if (pids.empty()) {
        std::cout << "Process '" << processName << "' not found\n";
        std::cout << "Please run notepad.exe first\n\n";
        return;
    }

    uint32_t pid = pids[0];
    std::cout << "Found " << processName << " (PID: " << pid << ")\n";

    // Quick dump - dumps main executable with PE reconstruction
    std::filesystem::path outputPath = "notepad_dumped.exe";
    auto result = dumper.QuickDump(pid, outputPath);

    if (result.success) {
        std::cout << "✓ Dump successful!\n";
        std::cout << "  Output: " << result.outputFile << "\n";
        std::cout << "  Size: " << (result.bytesRead / 1024) << " KB\n";
        std::cout << "  Regions: " << result.regionsRead << "\n";
    } else {
        std::cout << "✗ Dump failed\n";
        for (const auto& error : result.errors) {
            std::cout << "  Error: " << error << "\n";
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 2: Custom Dump Configuration
 *
 * Full control over dumping process
 */
void CustomDumpExample() {
    std::cout << "=== Custom Dump Example ===\n\n";

    DumpCommand dumper;

    // Find target process
    auto pids = DumpCommand::FindProcessByName("calc");
    if (pids.empty()) {
        std::cout << "Calculator not found (try 'calc' or 'Calculator')\n\n";
        return;
    }

    // Configure dump
    DumpConfig config = {};
    config.processId = pids[0];
    config.outputPath = "calculator_dump.bin";

    // Dump options
    config.dumpExecutableOnly = true;      // Only executable regions
    config.rebuildPE = true;               // Rebuild PE structure
    config.fixImports = true;              // Fix IAT
    config.includeMetadata = true;         // Save JSON metadata
    config.createDirectory = false;        // Single file output

    // Region filters
    config.minRegionSize = 4096;           // Skip regions < 4 KB
    config.maxRegionSize = 100 * 1024 * 1024;  // Skip regions > 100 MB

    std::cout << "Dumping calculator (PID " << config.processId << ")...\n";
    std::cout << "Configuration:\n";
    std::cout << "  Executable only: YES\n";
    std::cout << "  Rebuild PE: YES\n";
    std::cout << "  Fix imports: YES\n";
    std::cout << "  Min region: 4 KB\n\n";

    auto result = dumper.Execute(config);

    if (result.success) {
        std::cout << "✓ Dump completed\n";
        std::cout << "  File: " << result.outputFile << "\n";
        std::cout << "  Size: " << (result.bytesRead / 1024.0) << " KB\n";
        std::cout << "  Regions: " << result.regionsRead << "\n";

        if (!result.warnings.empty()) {
            std::cout << "\nWarnings:\n";
            for (const auto& warning : result.warnings) {
                std::cout << "  ⚠ " << warning << "\n";
            }
        }
    } else {
        std::cout << "✗ Dump failed\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 3: Dump All Memory Regions
 *
 * Comprehensive memory dump with separate files
 */
void FullMemoryDumpExample() {
    std::cout << "=== Full Memory Dump Example ===\n\n";

    DumpCommand dumper;

    auto pids = DumpCommand::FindProcessByName("sample.exe");
    if (pids.empty()) {
        std::cout << "Target process not found\n\n";
        return;
    }

    // Configure for full dump
    DumpConfig config = {};
    config.processId = pids[0];
    config.outputPath = "full_dump";  // Directory path
    config.dumpFullProcess = true;    // All regions
    config.createDirectory = true;    // Separate files for each region
    config.includeMetadata = true;    // Save metadata

    std::cout << "Performing full memory dump...\n";
    std::cout << "This will create multiple files in: " << config.outputPath << "\n\n";

    auto result = dumper.Execute(config);

    if (result.success) {
        std::cout << "✓ Full dump completed\n";
        std::cout << "  Output directory: " << result.outputFile << "\n";
        std::cout << "  Total size: " << (result.bytesRead / 1024 / 1024.0) << " MB\n";
        std::cout << "  Regions dumped: " << result.regionsRead << "\n";
        std::cout << "\nCheck the output directory for individual region files\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 4: Process Enumeration
 *
 * List and analyze running processes
 */
void ProcessEnumerationExample() {
    std::cout << "=== Process Enumeration Example ===\n\n";

    // List all processes
    auto allPids = DumpCommand::ListProcesses();
    std::cout << "Total processes: " << allPids.size() << "\n\n";

    // Find specific processes
    std::vector<std::string> targets = {"notepad", "calc", "chrome", "explorer"};

    std::cout << std::left << std::setw(20) << "Process Name"
              << std::setw(10) << "Count"
              << "PIDs\n";
    std::cout << std::string(60, '-') << "\n";

    for (const auto& name : targets) {
        auto pids = DumpCommand::FindProcessByName(name);
        std::cout << std::setw(20) << name
                  << std::setw(10) << pids.size();

        if (!pids.empty()) {
            for (size_t i = 0; i < std::min(pids.size(), size_t(3)); i++) {
                std::cout << pids[i];
                if (i < std::min(pids.size(), size_t(3)) - 1) std::cout << ", ";
            }
            if (pids.size() > 3) std::cout << "...";
        } else {
            std::cout << "-";
        }
        std::cout << "\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 5: Memory Region Analysis
 *
 * Enumerate and analyze memory regions
 */
void MemoryRegionAnalysisExample() {
    std::cout << "=== Memory Region Analysis ===\n\n";

    auto pids = DumpCommand::FindProcessByName("notepad");
    if (pids.empty()) {
        std::cout << "Notepad not running\n\n";
        return;
    }

    uint32_t pid = pids[0];
    std::cout << "Analyzing notepad.exe (PID " << pid << ")\n\n";

    // Enumerate memory regions
    auto regions = DumpCommand::EnumerateRegions(pid);

    std::cout << "Total regions: " << regions.size() << "\n\n";

    // Categorize regions
    size_t executableRegions = 0;
    size_t writableRegions = 0;
    size_t imageRegions = 0;
    size_t privateRegions = 0;
    uint64_t totalSize = 0;

    for (const auto& region : regions) {
        if (region.isExecutable) executableRegions++;
        if (region.isWritable) writableRegions++;
        if (region.typeStr == "Image") imageRegions++;
        if (region.typeStr == "Private") privateRegions++;
        totalSize += region.size;
    }

    std::cout << "Region Statistics:\n";
    std::cout << "─────────────────────────────────────\n";
    std::cout << "  Executable regions:  " << executableRegions << "\n";
    std::cout << "  Writable regions:    " << writableRegions << "\n";
    std::cout << "  Image regions:       " << imageRegions << "\n";
    std::cout << "  Private regions:     " << privateRegions << "\n";
    std::cout << "  Total memory:        " << (totalSize / 1024 / 1024) << " MB\n\n";

    // Show first few executable regions
    std::cout << "Sample Executable Regions:\n";
    std::cout << std::left
              << std::setw(18) << "Address"
              << std::setw(12) << "Size"
              << std::setw(8) << "Perms"
              << "Type\n";
    std::cout << std::string(60, '-') << "\n";

    int count = 0;
    for (const auto& region : regions) {
        if (region.isExecutable && count < 10) {
            std::cout << std::hex << std::setfill('0')
                      << "0x" << std::setw(16) << region.baseAddress << "  "
                      << std::dec << std::setw(8) << (region.size / 1024) << " KB  "
                      << std::setw(8) << region.protectionStr
                      << region.typeStr << "\n";
            count++;
        }
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 6: Batch Dumping
 *
 * Dump multiple processes at once
 */
void BatchDumpExample() {
    std::cout << "=== Batch Dump Example ===\n\n";

    BatchDumper batchDumper;

    // Find all chrome processes
    auto pids = DumpCommand::FindProcessByName("chrome");

    if (pids.empty()) {
        std::cout << "No Chrome processes found\n\n";
        return;
    }

    std::cout << "Found " << pids.size() << " Chrome processes\n";
    std::cout << "Dumping all processes...\n\n";

    // Configure base dump settings
    DumpConfig baseConfig = {};
    baseConfig.outputPath = "chrome_dumps/chrome.exe";
    baseConfig.dumpExecutableOnly = true;
    baseConfig.includeMetadata = true;
    baseConfig.createDirectory = false;

    // Batch dump
    auto results = batchDumper.DumpAllProcesses(pids, baseConfig);

    // Show statistics
    auto stats = batchDumper.GetStatistics();

    std::cout << "\nBatch Dump Results:\n";
    std::cout << "─────────────────────────────────────\n";
    std::cout << "  Total processes:     " << stats.totalProcesses << "\n";
    std::cout << "  Successful dumps:    " << stats.successfulDumps << "\n";
    std::cout << "  Failed dumps:        " << stats.failedDumps << "\n";
    std::cout << "  Total bytes written: " << (stats.totalBytesWritten / 1024 / 1024) << " MB\n";
    std::cout << "  Average dump size:   " << (stats.averageDumpSize / 1024) << " KB\n";

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

/*
 * Example 7: Unpacking Workflow
 *
 * Typical malware unpacking scenario
 */
void UnpackingWorkflowExample() {
    std::cout << "=== Unpacking Workflow Example ===\n\n";

    std::cout << "Typical workflow for unpacking malware:\n\n";

    std::cout << "1. Run packed malware in sandbox\n";
    std::cout << "   > start packed_malware.exe\n\n";

    std::cout << "2. Wait for unpacking (monitor with process monitor)\n";
    std::cout << "   - Look for VirtualAlloc/VirtualProtect calls\n";
    std::cout << "   - Watch for memory region changes (RW -> RX)\n\n";

    std::cout << "3. Dump unpacked code from memory\n";
    std::cout << "   > scylla dump --pid 1234 --executable-only --rebuild-pe unpacked.exe\n\n";

    std::cout << "4. Analyze dump with packer detector\n";
    std::cout << "   > scylla analyze --profile malware-analysis unpacked.exe\n\n";

    std::cout << "5. Fix imports if needed\n";
    std::cout << "   > scylla rebuild --iat-auto unpacked.exe\n\n";

    std::cout << "Example with Scylla API:\n\n";

    DumpCommand dumper;

    // Simulate finding unpacker process
    std::cout << "// Find process\n";
    std::cout << "auto pids = DumpCommand::FindProcessByName(\"malware.exe\");\n";
    std::cout << "uint32_t pid = pids[0];\n\n";

    std::cout << "// Configure dump for unpacked code\n";
    std::cout << "DumpConfig config = {};\n";
    std::cout << "config.processId = pid;\n";
    std::cout << "config.outputPath = \"unpacked.exe\";\n";
    std::cout << "config.dumpExecutableOnly = true;  // Only RX/RWX regions\n";
    std::cout << "config.rebuildPE = true;           // Rebuild PE headers\n";
    std::cout << "config.fixImports = true;          // Reconstruct IAT\n\n";

    std::cout << "// Execute dump\n";
    std::cout << "auto result = dumper.Execute(config);\n\n";

    std::cout << "// Verify\n";
    std::cout << "if (result.success) {\n";
    std::cout << "    std::cout << \"Unpacked: \" << result.outputFile << \"\\n\";\n";
    std::cout << "    // Proceed with analysis\n";
    std::cout << "}\n";

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}

int main() {
    std::cout << "Scylla Dump Command Examples\n";
    std::cout << std::string(60, '=') << "\n\n";

    try {
        QuickDumpExample();
        ProcessEnumerationExample();
        MemoryRegionAnalysisExample();
        CustomDumpExample();
        // Uncomment if you want full dumps:
        // FullMemoryDumpExample();
        // BatchDumpExample();
        UnpackingWorkflowExample();

        std::cout << "All examples completed!\n";

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }

    return 0;
}
