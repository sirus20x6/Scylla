/*
 * Scylla Dump Command
 *
 * Dumps process memory for unpacking and analysis
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>

namespace Scylla {
namespace CLI {

/*
 * Memory region information
 */
struct MemoryRegionInfo {
    uint64_t baseAddress;
    uint64_t size;
    uint32_t protection;
    uint32_t type;
    std::string protectionStr;  // "RWX", "R--", etc.
    std::string typeStr;        // "Image", "Private", "Mapped"
    bool isExecutable;
    bool isWritable;
    bool isReadable;
};

/*
 * Process dump configuration
 */
struct DumpConfig {
    // Target selection
    uint32_t processId;
    std::string processName;
    uint64_t moduleBase;        // 0 = dump main module
    std::string moduleName;

    // Dump options
    bool dumpFullProcess;       // Dump all regions
    bool dumpExecutableOnly;    // Only executable regions
    bool dumpModifiedOnly;      // Only modified (unpacked) regions
    bool rebuildPE;             // Rebuild PE headers
    bool fixImports;            // Fix IAT

    // Region filters
    uint64_t startAddress;      // 0 = from beginning
    uint64_t endAddress;        // 0 = to end
    size_t minRegionSize;       // Skip small regions
    size_t maxRegionSize;       // Skip huge regions

    // Output options
    std::filesystem::path outputPath;
    bool createDirectory;       // Create dir for multiple dumps
    bool includeMetadata;       // Save dump metadata (JSON)
    bool compressDump;          // Compress output

    // Advanced
    bool suspendProcess;        // Suspend before dumping
    bool useRawDump;            // Raw memory dump vs PE rebuild
    int retryCount;             // Retry failed reads
};

/*
 * Dump result information
 */
struct DumpResult {
    bool success;
    std::string outputFile;
    size_t bytesRead;
    size_t regionsRead;
    uint64_t imageBase;
    uint64_t entryPoint;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;

    // PE information (if rebuildPE = true)
    bool peRebuilt;
    size_t sectionsRecovered;
    size_t importsFixed;
};

/*
 * Dump Command
 *
 * Handles process memory dumping operations
 */
class DumpCommand {
public:
    DumpCommand();
    ~DumpCommand();

    // Execute dump operation
    DumpResult Execute(const DumpConfig& config);

    // Helper methods
    static std::vector<uint32_t> ListProcesses();
    static std::vector<uint32_t> FindProcessByName(const std::string& name);
    static std::vector<MemoryRegionInfo> EnumerateRegions(uint32_t processId);
    static std::vector<std::string> EnumerateModules(uint32_t processId);

    // Dump specific regions
    DumpResult DumpRegion(uint32_t processId, uint64_t address, size_t size,
                          const std::filesystem::path& outputPath);

    // Dump with PE reconstruction
    DumpResult DumpAndRebuild(uint32_t processId, uint64_t moduleBase,
                              const std::filesystem::path& outputPath);

    // Quick dump (main executable)
    DumpResult QuickDump(uint32_t processId, const std::filesystem::path& outputPath);

private:
    // Process access
    void* OpenProcess(uint32_t processId);
    void CloseProcess(void* handle);
    bool ReadProcessMemory(void* handle, uint64_t address, void* buffer, size_t size);

    // PE reconstruction
    bool RebuildPEHeaders(uint8_t* dumpData, size_t dumpSize, uint64_t originalBase);
    bool FixImportTable(uint8_t* dumpData, size_t dumpSize, uint32_t processId, uint64_t moduleBase);
    bool FixRelocations(uint8_t* dumpData, size_t dumpSize, uint64_t originalBase, uint64_t newBase);

    // Region analysis
    std::vector<MemoryRegionInfo> FilterRegions(const std::vector<MemoryRegionInfo>& regions,
                                                 const DumpConfig& config);
    bool IsRegionModified(uint32_t processId, const MemoryRegionInfo& region);

    // Metadata
    void SaveMetadata(const DumpResult& result, const DumpConfig& config,
                     const std::filesystem::path& metadataPath);

    // Utilities
    std::string FormatProtection(uint32_t protection);
    std::string FormatMemoryType(uint32_t type);
    bool IsSuspiciousRegion(const MemoryRegionInfo& region);
};

/*
 * Dump multiple processes in batch
 */
class BatchDumper {
public:
    BatchDumper();

    // Batch operations
    std::vector<DumpResult> DumpAllProcesses(const std::vector<uint32_t>& pids,
                                             const DumpConfig& baseConfig);

    std::vector<DumpResult> DumpByName(const std::string& processName,
                                       const DumpConfig& baseConfig);

    // Statistics
    struct BatchStats {
        size_t totalProcesses;
        size_t successfulDumps;
        size_t failedDumps;
        size_t totalBytesWritten;
        double averageDumpSize;
    };

    BatchStats GetStatistics() const { return m_stats; }

private:
    BatchStats m_stats;
};

} // namespace CLI
} // namespace Scylla
