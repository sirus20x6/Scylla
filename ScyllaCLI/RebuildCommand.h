/*
 * Scylla Rebuild Command
 *
 * Reconstructs Import Address Table (IAT) in dumped executables
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <unordered_map>

namespace Scylla {
namespace CLI {

/*
 * Import information
 */
struct ImportInfo {
    std::string moduleName;
    std::string functionName;
    uint64_t address;
    uint16_t ordinal;
    bool isOrdinal;
    bool resolved;
};

/*
 * IAT entry
 */
struct IATEntry {
    uint64_t rva;              // Relative Virtual Address
    uint64_t address;          // Absolute address
    std::string moduleName;
    std::string functionName;
    uint16_t ordinal;
    bool isOrdinal;
    bool isValid;
};

/*
 * Rebuild configuration
 */
struct RebuildConfig {
    // Input/Output
    std::filesystem::path inputFile;
    std::filesystem::path outputFile;  // Empty = overwrite input

    // IAT Detection
    bool autoDetectIAT;                // Automatically find IAT
    uint64_t iatRVA;                   // Manual IAT RVA (if !autoDetect)
    uint64_t iatSize;                  // Manual IAT size

    // Process Information (for live analysis)
    uint32_t processId;                // 0 = file-only mode
    uint64_t imageBase;                // Original image base
    uint64_t oepRVA;                   // Original Entry Point RVA

    // Rebuild Options
    bool createNewSection;             // Create new .idata section
    bool fixOEP;                       // Fix Original Entry Point
    bool removeOverlay;                // Remove file overlay
    bool rebuildImportDirectory;       // Rebuild import directory
    bool removeRelocations;            // Strip relocation table
    bool stripDebugInfo;               // Remove debug info

    // Import Resolution
    bool resolveForwarders;            // Resolve forwarded imports
    bool scanForUnresolvedAPIs;        // Deep scan for missing APIs
    bool tryOrdinalImports;            // Use ordinals when names unavailable
    bool validateImports;              // Validate all imports exist

    // Advanced
    bool preserveUnusedSections;       // Keep unused sections
    std::vector<std::string> apiDatabasePaths;  // Custom API databases
    int maxScanAttempts;               // Maximum IAT scan attempts
};

/*
 * Rebuild result
 */
struct RebuildResult {
    bool success;
    std::string outputFile;

    // Statistics
    size_t importsFound;
    size_t importsResolved;
    size_t importsUnresolved;
    size_t modulesFound;
    size_t sectionsCreated;
    size_t sectionsModified;

    // IAT Information
    uint64_t iatRVA;
    uint64_t iatSize;
    uint64_t importDirectoryRVA;

    // Issues
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
    std::vector<ImportInfo> unresolvedImports;

    // PE Information
    uint64_t newImageBase;
    uint64_t newOEP;
    bool validPE;
};

/*
 * Rebuild Command
 *
 * Handles IAT reconstruction and PE rebuilding
 */
class RebuildCommand {
public:
    RebuildCommand();
    ~RebuildCommand();

    // Execute rebuild operation
    RebuildResult Execute(const RebuildConfig& config);

    // Quick rebuild (auto-detect IAT)
    RebuildResult QuickRebuild(const std::filesystem::path& inputFile,
                               const std::filesystem::path& outputFile);

    // Rebuild from process
    RebuildResult RebuildFromProcess(uint32_t processId,
                                     uint64_t imageBase,
                                     const std::filesystem::path& outputFile);

    // IAT Detection
    struct IATInfo {
        uint64_t rva;
        uint64_t size;
        uint64_t entryCount;
        double confidence;  // 0.0-1.0
    };

    std::vector<IATInfo> DetectIAT(const std::filesystem::path& file,
                                   uint64_t imageBase = 0);

    IATInfo FindBestIAT(const std::vector<IATInfo>& candidates);

    // Import Scanning
    std::vector<IATEntry> ScanIAT(const std::filesystem::path& file,
                                  uint64_t iatRVA,
                                  uint64_t iatSize);

    std::vector<IATEntry> ScanIATFromProcess(uint32_t processId,
                                             uint64_t imageBase,
                                             uint64_t iatRVA,
                                             uint64_t iatSize);

    // Import Resolution
    bool ResolveImport(IATEntry& entry);
    void ResolveAllImports(std::vector<IATEntry>& entries);

    // API Database
    void LoadAPIDatabase(const std::filesystem::path& dbPath);
    std::string LookupAddress(uint64_t address);
    uint64_t LookupFunction(const std::string& module, const std::string& function);

private:
    // PE Parsing
    struct PEHeaders {
        uint32_t signature;
        uint16_t machine;
        uint16_t numberOfSections;
        uint64_t imageBase;
        uint64_t entryPoint;
        uint32_t sizeOfImage;
        uint32_t sizeOfHeaders;
        bool is64Bit;
    };

    PEHeaders ParsePEHeaders(const std::filesystem::path& file);
    std::vector<uint8_t> ReadFile(const std::filesystem::path& file);
    bool WriteFile(const std::filesystem::path& file, const std::vector<uint8_t>& data);

    // IAT Detection Methods
    std::vector<IATInfo> DetectByPointerScan(const std::vector<uint8_t>& fileData,
                                             const PEHeaders& headers);
    std::vector<IATInfo> DetectByImportDirectory(const std::vector<uint8_t>& fileData,
                                                 const PEHeaders& headers);
    std::vector<IATInfo> DetectByHeuristics(const std::vector<uint8_t>& fileData,
                                            const PEHeaders& headers);

    // Import Resolution
    bool ResolveByAPIDatabase(IATEntry& entry);
    bool ResolveByModuleExports(IATEntry& entry);
    bool ResolveBySignature(IATEntry& entry);

    // PE Reconstruction
    bool CreateImportSection(std::vector<uint8_t>& fileData,
                            const std::vector<IATEntry>& entries,
                            uint64_t& newSectionRVA);

    bool RebuildImportDirectory(std::vector<uint8_t>& fileData,
                               const std::vector<IATEntry>& entries,
                               uint64_t importDirRVA);

    bool FixPEHeaders(std::vector<uint8_t>& fileData,
                     const RebuildConfig& config,
                     const RebuildResult& result);

    // Utilities
    uint64_t RVAToFileOffset(uint64_t rva, const std::vector<uint8_t>& fileData);
    uint64_t FileOffsetToRVA(uint64_t offset, const std::vector<uint8_t>& fileData);

    bool IsValidPointer(uint64_t address, const PEHeaders& headers);
    bool IsCodeSection(uint64_t rva, const std::vector<uint8_t>& fileData);

    std::vector<std::string> GetKnownModules();
    bool IsKnownAPI(const std::string& module, const std::string& function);

    // API Database
    std::unordered_map<uint64_t, ImportInfo> m_apiDatabase;
    std::unordered_map<std::string, std::unordered_map<std::string, uint64_t>> m_moduleExports;
};

/*
 * IAT Analyzer
 *
 * Analyzes IAT quality and completeness
 */
class IATAnalyzer {
public:
    struct AnalysisResult {
        double completeness;       // 0.0-1.0
        double confidence;         // 0.0-1.0
        size_t totalEntries;
        size_t resolvedEntries;
        size_t unresolvedEntries;
        size_t invalidEntries;
        std::vector<std::string> issues;
        std::vector<std::string> recommendations;
    };

    AnalysisResult Analyze(const std::vector<IATEntry>& entries);

    // Validation
    bool ValidateIATStructure(const std::vector<IATEntry>& entries);
    bool ValidateImportConsistency(const std::vector<IATEntry>& entries);

    // Quality Metrics
    double CalculateCompleteness(const std::vector<IATEntry>& entries);
    double CalculateConfidence(const std::vector<IATEntry>& entries);

    // Recommendations
    std::vector<std::string> GenerateRecommendations(const AnalysisResult& result);
};

} // namespace CLI
} // namespace Scylla
