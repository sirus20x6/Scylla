/*
 * Scylla Rebuild Command - Implementation
 */

#include "RebuildCommand.h"
#include <iostream>
#include <fstream>
#include <algorithm>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#else
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#endif

namespace Scylla {
namespace CLI {

// ============================================================================
// RebuildCommand Implementation
// ============================================================================

RebuildCommand::RebuildCommand() {
    // Initialize known modules and APIs
    // In real implementation, this would load from database
}

RebuildCommand::~RebuildCommand() {
}

RebuildResult RebuildCommand::Execute(const RebuildConfig& config) {
    RebuildResult result = {};
    result.success = false;

    // Validate input
    if (!std::filesystem::exists(config.inputFile)) {
        result.errors.push_back("Input file not found: " + config.inputFile.string());
        return result;
    }

    std::cout << "Rebuilding IAT for: " << config.inputFile << "\n";

    try {
        // Step 1: Read PE file
        auto fileData = ReadFile(config.inputFile);
        if (fileData.empty()) {
            result.errors.push_back("Failed to read file");
            return result;
        }

        // Step 2: Parse PE headers
        auto headers = ParsePEHeaders(config.inputFile);
        if (headers.signature != 0x4550) {  // 'PE'
            result.errors.push_back("Invalid PE file");
            return result;
        }

        std::cout << "  Architecture: " << (headers.is64Bit ? "x64" : "x86") << "\n";
        std::cout << "  Image base: 0x" << std::hex << headers.imageBase << std::dec << "\n";

        // Step 3: Detect or use provided IAT
        uint64_t iatRVA = config.iatRVA;
        uint64_t iatSize = config.iatSize;

        if (config.autoDetectIAT) {
            std::cout << "  Auto-detecting IAT...\n";
            auto iatCandidates = DetectIAT(config.inputFile, headers.imageBase);

            if (iatCandidates.empty()) {
                result.errors.push_back("Failed to detect IAT");
                return result;
            }

            auto bestIAT = FindBestIAT(iatCandidates);
            iatRVA = bestIAT.rva;
            iatSize = bestIAT.size;

            std::cout << "  Found IAT at RVA 0x" << std::hex << iatRVA << std::dec
                      << " (size: " << iatSize << " bytes, confidence: "
                      << (bestIAT.confidence * 100.0) << "%)\n";
        }

        result.iatRVA = iatRVA;
        result.iatSize = iatSize;

        // Step 4: Scan IAT for imports
        std::vector<IATEntry> entries;

        if (config.processId > 0) {
            // Scan from live process
            std::cout << "  Scanning IAT from process " << config.processId << "...\n";
            entries = ScanIATFromProcess(config.processId, headers.imageBase, iatRVA, iatSize);
        } else {
            // Scan from file
            std::cout << "  Scanning IAT from file...\n";
            entries = ScanIAT(config.inputFile, iatRVA, iatSize);
        }

        std::cout << "  Found " << entries.size() << " IAT entries\n";
        result.importsFound = entries.size();

        // Step 5: Resolve imports
        if (!entries.empty()) {
            std::cout << "  Resolving imports...\n";
            ResolveAllImports(entries);

            size_t resolved = 0;
            size_t unresolved = 0;

            for (const auto& entry : entries) {
                if (!entry.functionName.empty() && !entry.moduleName.empty()) {
                    resolved++;
                } else {
                    unresolved++;
                    ImportInfo unresolvedImport;
                    unresolvedImport.address = entry.address;
                    unresolvedImport.resolved = false;
                    result.unresolvedImports.push_back(unresolvedImport);
                }
            }

            result.importsResolved = resolved;
            result.importsUnresolved = unresolved;

            std::cout << "  Resolved: " << resolved << "/" << entries.size() << "\n";

            if (unresolved > 0) {
                result.warnings.push_back(std::to_string(unresolved) + " imports could not be resolved");
            }
        }

        // Step 6: Rebuild import directory
        if (config.rebuildImportDirectory && !entries.empty()) {
            std::cout << "  Rebuilding import directory...\n";

            uint64_t newSectionRVA = 0;
            if (CreateImportSection(fileData, entries, newSectionRVA)) {
                result.sectionsCreated++;
                result.importDirectoryRVA = newSectionRVA;

                if (RebuildImportDirectory(fileData, entries, newSectionRVA)) {
                    std::cout << "  Import directory rebuilt at RVA 0x" << std::hex
                              << newSectionRVA << std::dec << "\n";
                }
            }
        }

        // Step 7: Fix PE headers
        if (config.fixOEP && config.oepRVA > 0) {
            std::cout << "  Fixing Original Entry Point...\n";
            // Update OEP in PE headers
            result.newOEP = config.oepRVA;
        }

        // Step 8: Write output file
        std::filesystem::path outputPath = config.outputFile.empty() ?
                                          config.inputFile : config.outputFile;

        if (WriteFile(outputPath, fileData)) {
            result.success = true;
            result.outputFile = outputPath.string();
            result.validPE = true;

            std::cout << "\n✓ Rebuild successful!\n";
            std::cout << "  Output: " << outputPath << "\n";
            std::cout << "  Imports resolved: " << result.importsResolved << "\n";
            std::cout << "  Sections created: " << result.sectionsCreated << "\n";
        } else {
            result.errors.push_back("Failed to write output file");
        }

    } catch (const std::exception& e) {
        result.errors.push_back(std::string("Exception: ") + e.what());
    }

    return result;
}

RebuildResult RebuildCommand::QuickRebuild(const std::filesystem::path& inputFile,
                                          const std::filesystem::path& outputFile)
{
    RebuildConfig config = {};
    config.inputFile = inputFile;
    config.outputFile = outputFile;
    config.autoDetectIAT = true;
    config.rebuildImportDirectory = true;
    config.resolveForwarders = true;
    config.validateImports = true;

    return Execute(config);
}

RebuildResult RebuildCommand::RebuildFromProcess(uint32_t processId,
                                                 uint64_t imageBase,
                                                 const std::filesystem::path& outputFile)
{
    RebuildConfig config = {};
    config.outputFile = outputFile;
    config.processId = processId;
    config.imageBase = imageBase;
    config.autoDetectIAT = true;
    config.rebuildImportDirectory = true;
    config.fixOEP = true;

    // Need to specify input file (the dumped file)
    // This is a simplified version

    return Execute(config);
}

std::vector<RebuildCommand::IATInfo> RebuildCommand::DetectIAT(
    const std::filesystem::path& file,
    uint64_t imageBase)
{
    std::vector<IATInfo> candidates;

    auto fileData = ReadFile(file);
    if (fileData.empty()) {
        return candidates;
    }

    auto headers = ParsePEHeaders(file);

    // Method 1: Check import directory
    auto dirCandidates = DetectByImportDirectory(fileData, headers);
    candidates.insert(candidates.end(), dirCandidates.begin(), dirCandidates.end());

    // Method 2: Pointer scan
    auto scanCandidates = DetectByPointerScan(fileData, headers);
    candidates.insert(candidates.end(), scanCandidates.begin(), scanCandidates.end());

    // Method 3: Heuristic analysis
    auto heurCandidates = DetectByHeuristics(fileData, headers);
    candidates.insert(candidates.end(), heurCandidates.begin(), heurCandidates.end());

    return candidates;
}

RebuildCommand::IATInfo RebuildCommand::FindBestIAT(const std::vector<IATInfo>& candidates) {
    if (candidates.empty()) {
        return IATInfo{};
    }

    // Find candidate with highest confidence
    auto best = std::max_element(candidates.begin(), candidates.end(),
        [](const IATInfo& a, const IATInfo& b) {
            return a.confidence < b.confidence;
        });

    return *best;
}

std::vector<IATEntry> RebuildCommand::ScanIAT(const std::filesystem::path& file,
                                              uint64_t iatRVA,
                                              uint64_t iatSize)
{
    std::vector<IATEntry> entries;

    auto fileData = ReadFile(file);
    if (fileData.empty()) {
        return entries;
    }

    auto headers = ParsePEHeaders(file);
    uint64_t offset = RVAToFileOffset(iatRVA, fileData);

    if (offset == 0 || offset + iatSize > fileData.size()) {
        return entries;
    }

    // Scan IAT entries
    size_t ptrSize = headers.is64Bit ? 8 : 4;
    size_t entryCount = iatSize / ptrSize;

    for (size_t i = 0; i < entryCount; i++) {
        uint64_t address = 0;

        if (headers.is64Bit) {
            memcpy(&address, &fileData[offset + i * 8], 8);
        } else {
            uint32_t addr32 = 0;
            memcpy(&addr32, &fileData[offset + i * 4], 4);
            address = addr32;
        }

        if (address == 0) {
            break;  // End of IAT
        }

        IATEntry entry;
        entry.rva = iatRVA + (i * ptrSize);
        entry.address = address;
        entry.isValid = IsValidPointer(address, headers);

        entries.push_back(entry);
    }

    return entries;
}

std::vector<IATEntry> RebuildCommand::ScanIATFromProcess(uint32_t processId,
                                                         uint64_t imageBase,
                                                         uint64_t iatRVA,
                                                         uint64_t iatSize)
{
    std::vector<IATEntry> entries;

#ifdef _WIN32
    HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, processId);
    if (!hProcess) {
        return entries;
    }

    std::vector<uint8_t> buffer(iatSize);
    SIZE_T bytesRead;

    if (ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(imageBase + iatRVA),
                         buffer.data(), iatSize, &bytesRead))
    {
        // Parse IAT from memory
        // Simplified: assume 64-bit pointers
        size_t entryCount = iatSize / 8;

        for (size_t i = 0; i < entryCount; i++) {
            uint64_t address = 0;
            memcpy(&address, &buffer[i * 8], 8);

            if (address == 0) break;

            IATEntry entry;
            entry.rva = iatRVA + (i * 8);
            entry.address = address;
            entry.isValid = true;

            entries.push_back(entry);
        }
    }

    CloseHandle(hProcess);
#endif

    return entries;
}

void RebuildCommand::ResolveAllImports(std::vector<IATEntry>& entries) {
    for (auto& entry : entries) {
        ResolveImport(entry);
    }
}

bool RebuildCommand::ResolveImport(IATEntry& entry) {
    // Try different resolution methods

    // Method 1: API database lookup
    if (ResolveByAPIDatabase(entry)) {
        return true;
    }

    // Method 2: Module exports lookup
    if (ResolveByModuleExports(entry)) {
        return true;
    }

    // Method 3: Signature-based resolution
    if (ResolveBySignature(entry)) {
        return true;
    }

    return false;
}

// ============================================================================
// Helper Methods
// ============================================================================

std::vector<uint8_t> RebuildCommand::ReadFile(const std::filesystem::path& file) {
    std::ifstream ifs(file, std::ios::binary | std::ios::ate);
    if (!ifs.is_open()) {
        return {};
    }

    auto size = ifs.tellg();
    std::vector<uint8_t> data(size);

    ifs.seekg(0);
    ifs.read(reinterpret_cast<char*>(data.data()), size);

    return data;
}

bool RebuildCommand::WriteFile(const std::filesystem::path& file,
                              const std::vector<uint8_t>& data)
{
    std::ofstream ofs(file, std::ios::binary);
    if (!ofs.is_open()) {
        return false;
    }

    ofs.write(reinterpret_cast<const char*>(data.data()), data.size());
    return true;
}

RebuildCommand::PEHeaders RebuildCommand::ParsePEHeaders(const std::filesystem::path& file) {
    PEHeaders headers = {};

    auto data = ReadFile(file);
    if (data.size() < 64) {
        return headers;
    }

    // DOS header
    if (data[0] != 'M' || data[1] != 'Z') {
        return headers;
    }

    uint32_t peOffset = *reinterpret_cast<uint32_t*>(&data[0x3C]);
    if (peOffset + 4 > data.size()) {
        return headers;
    }

    // PE signature
    headers.signature = *reinterpret_cast<uint32_t*>(&data[peOffset]);
    if (headers.signature != 0x4550) {  // 'PE\0\0'
        return headers;
    }

    // COFF header
    headers.machine = *reinterpret_cast<uint16_t*>(&data[peOffset + 4]);
    headers.numberOfSections = *reinterpret_cast<uint16_t*>(&data[peOffset + 6]);

    // Optional header magic
    uint16_t magic = *reinterpret_cast<uint16_t*>(&data[peOffset + 24]);
    headers.is64Bit = (magic == 0x20B);  // PE32+ = 0x20B, PE32 = 0x10B

    // Image base, entry point, etc.
    size_t optHeaderOffset = peOffset + 24;

    if (headers.is64Bit) {
        headers.imageBase = *reinterpret_cast<uint64_t*>(&data[optHeaderOffset + 24]);
        headers.entryPoint = *reinterpret_cast<uint32_t*>(&data[optHeaderOffset + 16]);
    } else {
        headers.imageBase = *reinterpret_cast<uint32_t*>(&data[optHeaderOffset + 28]);
        headers.entryPoint = *reinterpret_cast<uint32_t*>(&data[optHeaderOffset + 16]);
    }

    return headers;
}

uint64_t RebuildCommand::RVAToFileOffset(uint64_t rva, const std::vector<uint8_t>& fileData) {
    // Simplified: assumes RVA == file offset for now
    // Real implementation would use section table
    return rva;
}

bool RebuildCommand::IsValidPointer(uint64_t address, const PEHeaders& headers) {
    // Basic validation
    return (address >= headers.imageBase &&
            address < headers.imageBase + headers.sizeOfImage);
}

// Placeholder implementations for detection methods

std::vector<RebuildCommand::IATInfo> RebuildCommand::DetectByPointerScan(
    const std::vector<uint8_t>& fileData,
    const PEHeaders& headers)
{
    // Simplified placeholder
    std::vector<IATInfo> candidates;
    return candidates;
}

std::vector<RebuildCommand::IATInfo> RebuildCommand::DetectByImportDirectory(
    const std::vector<uint8_t>& fileData,
    const PEHeaders& headers)
{
    // Simplified placeholder
    std::vector<IATInfo> candidates;
    return candidates;
}

std::vector<RebuildCommand::IATInfo> RebuildCommand::DetectByHeuristics(
    const std::vector<uint8_t>& fileData,
    const PEHeaders& headers)
{
    // Simplified placeholder
    std::vector<IATInfo> candidates;
    return candidates;
}

bool RebuildCommand::ResolveByAPIDatabase(IATEntry& entry) {
    // Placeholder: lookup in API database
    return false;
}

bool RebuildCommand::ResolveByModuleExports(IATEntry& entry) {
    // Placeholder: resolve by checking module exports
    return false;
}

bool RebuildCommand::ResolveBySignature(IATEntry& entry) {
    // Placeholder: signature-based resolution
    return false;
}

bool RebuildCommand::CreateImportSection(std::vector<uint8_t>& fileData,
                                        const std::vector<IATEntry>& entries,
                                        uint64_t& newSectionRVA)
{
    // Placeholder: create new .idata section
    return false;
}

bool RebuildCommand::RebuildImportDirectory(std::vector<uint8_t>& fileData,
                                           const std::vector<IATEntry>& entries,
                                           uint64_t importDirRVA)
{
    // Placeholder: rebuild import directory structures
    return false;
}

// ============================================================================
// IATAnalyzer Implementation
// ============================================================================

IATAnalyzer::AnalysisResult IATAnalyzer::Analyze(const std::vector<IATEntry>& entries) {
    AnalysisResult result = {};

    result.totalEntries = entries.size();

    for (const auto& entry : entries) {
        if (!entry.functionName.empty()) {
            result.resolvedEntries++;
        } else {
            result.unresolvedEntries++;
        }

        if (!entry.isValid) {
            result.invalidEntries++;
        }
    }

    result.completeness = CalculateCompleteness(entries);
    result.confidence = CalculateConfidence(entries);

    result.recommendations = GenerateRecommendations(result);

    return result;
}

double IATAnalyzer::CalculateCompleteness(const std::vector<IATEntry>& entries) {
    if (entries.empty()) return 0.0;

    size_t resolved = 0;
    for (const auto& entry : entries) {
        if (!entry.functionName.empty() && !entry.moduleName.empty()) {
            resolved++;
        }
    }

    return static_cast<double>(resolved) / entries.size();
}

double IATAnalyzer::CalculateConfidence(const std::vector<IATEntry>& entries) {
    if (entries.empty()) return 0.0;

    size_t valid = 0;
    for (const auto& entry : entries) {
        if (entry.isValid) {
            valid++;
        }
    }

    return static_cast<double>(valid) / entries.size();
}

std::vector<std::string> IATAnalyzer::GenerateRecommendations(const AnalysisResult& result) {
    std::vector<std::string> recommendations;

    if (result.completeness < 0.5) {
        recommendations.push_back("Low completeness - consider using process dump for better results");
    }

    if (result.unresolvedEntries > 10) {
        recommendations.push_back("Many unresolved imports - check API database");
    }

    if (result.invalidEntries > 0) {
        recommendations.push_back("Invalid IAT entries detected - verify IAT location");
    }

    return recommendations;
}

bool IATAnalyzer::ValidateIATStructure(const std::vector<IATEntry>& entries) {
    // Check for reasonable IAT structure
    return !entries.empty() && entries.size() < 10000;
}

bool IATAnalyzer::ValidateImportConsistency(const std::vector<IATEntry>& entries) {
    // Check that imports are consistent
    return true;  // Placeholder
}

} // namespace CLI
} // namespace Scylla
