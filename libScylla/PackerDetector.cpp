/*
 * Scylla Packer Detection - Implementation
 */

#include "PackerDetector.h"
#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <sstream>

namespace Scylla {

// ============================================================================
// SignatureDatabase Implementation
// ============================================================================

SignatureDatabase::SignatureDatabase() {
    LoadBuiltinSignatures();
}

SignatureDatabase::~SignatureDatabase() {
}

void SignatureDatabase::LoadBuiltinSignatures() {
    AddUPX();
    AddVMProtect();
    AddThemida();
    AddASPack();
    AddPECompact();
    AddArmadillo();
    AddEnigma();
    AddObsidium();
    AddMPRESS();
    AddPEtite();
}

void SignatureDatabase::AddUPX() {
    PackerSignature sig;
    sig.name = "UPX";
    sig.sectionNames = {"UPX0", "UPX1", "UPX2", "UPX!"};
    sig.stringSignatures = {"UPX!"};

    // UPX entry point pattern (PUSHAD + MOV ESI)
    sig.entryPointPattern = {0x60, 0xBE, 0x00, 0x00, 0x00, 0x00, 0x8D, 0xBE};
    sig.entryPointMask     = {0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF};

    sig.minEntropy = 6.5;
    sig.maxEntropy = 8.0;
    sig.minImportCount = 0;
    sig.maxImportCount = 20;

    sig.versions["3.96"] = "Standard UPX 3.96";
    sig.versions["3.95"] = "Standard UPX 3.95";

    m_signatures.push_back(sig);
}

void SignatureDatabase::AddVMProtect() {
    PackerSignature sig;
    sig.name = "VMProtect";
    sig.sectionNames = {".vmp0", ".vmp1", ".vmp2", "vmp0", "vmp1"};
    sig.stringSignatures = {"VMProtect", "Protected by VMProtect"};

    sig.minEntropy = 7.2;
    sig.maxEntropy = 8.0;
    sig.minImportCount = 1;
    sig.maxImportCount = 50;

    sig.commonImports = {"LoadLibraryA", "GetProcAddress", "VirtualProtect"};

    m_signatures.push_back(sig);
}

void SignatureDatabase::AddThemida() {
    PackerSignature sig;
    sig.name = "Themida";
    sig.sectionNames = {".themida", "themida", ".winlic", "winlicense"};
    sig.stringSignatures = {"Themida", "Oreans", "WinLicense"};

    sig.minEntropy = 7.5;
    sig.maxEntropy = 8.0;
    sig.minImportCount = 1;
    sig.maxImportCount = 30;

    m_signatures.push_back(sig);
}

void SignatureDatabase::AddASPack() {
    PackerSignature sig;
    sig.name = "ASPack";
    sig.sectionNames = {".aspack", ".adata", "ASPack"};
    sig.stringSignatures = {"ASPack"};

    // ASPack entry point pattern
    sig.entryPointPattern = {0x60, 0xE8, 0x03, 0x00, 0x00, 0x00, 0xE9, 0xEB};
    sig.entryPointMask     = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    sig.minEntropy = 6.8;
    sig.maxEntropy = 8.0;

    m_signatures.push_back(sig);
}

void SignatureDatabase::AddPECompact() {
    PackerSignature sig;
    sig.name = "PECompact";
    sig.sectionNames = {".pec1", ".pec2", "PEC2", "PECompact"};
    sig.stringSignatures = {"PECompact", "Bitsum"};

    sig.minEntropy = 6.5;
    sig.maxEntropy = 8.0;
    sig.minImportCount = 5;
    sig.maxImportCount = 40;

    m_signatures.push_back(sig);
}

void SignatureDatabase::AddArmadillo() {
    PackerSignature sig;
    sig.name = "Armadillo";
    sig.sectionNames = {".arma", "armadillo"};
    sig.stringSignatures = {"Armadillo", "Silicon Realms"};

    sig.minEntropy = 6.0;
    sig.maxEntropy = 7.8;

    m_signatures.push_back(sig);
}

void SignatureDatabase::AddEnigma() {
    PackerSignature sig;
    sig.name = "Enigma Protector";
    sig.sectionNames = {".enigma1", ".enigma2", "enigma"};
    sig.stringSignatures = {"Enigma Protector", "The Enigma Protector"};

    sig.minEntropy = 7.0;
    sig.maxEntropy = 8.0;
    sig.minImportCount = 5;
    sig.maxImportCount = 50;

    m_signatures.push_back(sig);
}

void SignatureDatabase::AddObsidium() {
    PackerSignature sig;
    sig.name = "Obsidium";
    sig.sectionNames = {".obsidium", "obsidium"};
    sig.stringSignatures = {"Obsidium"};

    sig.minEntropy = 7.2;
    sig.maxEntropy = 8.0;

    m_signatures.push_back(sig);
}

void SignatureDatabase::AddMPRESS() {
    PackerSignature sig;
    sig.name = "MPRESS";
    sig.sectionNames = {".MPRESS1", ".MPRESS2", "MPRESS"};
    sig.stringSignatures = {"MPRESS"};

    sig.minEntropy = 6.8;
    sig.maxEntropy = 8.0;
    sig.minImportCount = 0;
    sig.maxImportCount = 15;

    m_signatures.push_back(sig);
}

void SignatureDatabase::AddPEtite() {
    PackerSignature sig;
    sig.name = "PEtite";
    sig.sectionNames = {".petite", "petite"};
    sig.stringSignatures = {"PEtite"};

    // PEtite entry point
    sig.entryPointPattern = {0xB8, 0x00, 0x00, 0x00, 0x00, 0x66, 0x9C, 0x60};
    sig.entryPointMask     = {0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF};

    sig.minEntropy = 6.5;
    sig.maxEntropy = 7.8;

    m_signatures.push_back(sig);
}

PackerSignature* SignatureDatabase::FindMatch(
    const std::vector<std::string>& sectionNames,
    const std::vector<uint8_t>& entryPointData,
    const std::vector<std::string>& strings)
{
    int bestMatchScore = 0;
    PackerSignature* bestMatch = nullptr;

    for (auto& sig : m_signatures) {
        int matchScore = 0;

        // Check section names (strong indicator)
        for (const auto& secName : sectionNames) {
            for (const auto& sigSecName : sig.sectionNames) {
                if (secName.find(sigSecName) != std::string::npos ||
                    sigSecName.find(secName) != std::string::npos) {
                    matchScore += 50;  // Section name match is very strong
                    break;
                }
            }
        }

        // Check string signatures (very strong)
        for (const auto& str : strings) {
            for (const auto& sigStr : sig.stringSignatures) {
                if (str.find(sigStr) != std::string::npos) {
                    matchScore += 40;
                    break;
                }
            }
        }

        // Check entry point pattern (strong)
        if (!sig.entryPointPattern.empty() && !entryPointData.empty()) {
            bool patternMatch = true;
            size_t checkSize = std::min(sig.entryPointPattern.size(), entryPointData.size());

            for (size_t i = 0; i < checkSize; i++) {
                uint8_t mask = (i < sig.entryPointMask.size()) ? sig.entryPointMask[i] : 0xFF;
                if ((entryPointData[i] & mask) != (sig.entryPointPattern[i] & mask)) {
                    patternMatch = false;
                    break;
                }
            }

            if (patternMatch) {
                matchScore += 30;
            }
        }

        if (matchScore > bestMatchScore) {
            bestMatchScore = matchScore;
            bestMatch = &sig;
        }
    }

    // Return match if confidence is high enough
    return (bestMatchScore >= 30) ? bestMatch : nullptr;
}

void SignatureDatabase::AddSignature(const PackerSignature& signature) {
    m_signatures.push_back(signature);
}

bool SignatureDatabase::LoadFromFile(const std::string& jsonPath) {
    // TODO: Implement JSON parsing
    // For now, we use built-in signatures
    return true;
}

// ============================================================================
// HeuristicAnalyzer Implementation
// ============================================================================

HeuristicAnalyzer::HeuristicAnalyzer()
    : m_entropyThreshold(7.0)
    , m_importThreshold(10)
{
}

double HeuristicAnalyzer::CalculateEntropy(const uint8_t* data, size_t size) {
    if (!data || size == 0) return 0.0;

    // Count byte frequencies
    size_t freq[256] = {0};
    for (size_t i = 0; i < size; i++) {
        freq[data[i]]++;
    }

    // Calculate Shannon entropy
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / size;
            entropy -= p * std::log2(p);
        }
    }

    return entropy;
}

bool HeuristicAnalyzer::HasSuspiciousImports(const std::vector<std::string>& imports) {
    // Check for typical packer import patterns
    int loaderAPIs = 0;

    for (const auto& imp : imports) {
        if (imp == "LoadLibraryA" || imp == "LoadLibraryW" ||
            imp == "GetProcAddress" || imp == "VirtualAlloc" ||
            imp == "VirtualProtect") {
            loaderAPIs++;
        }
    }

    // If most imports are loader APIs, suspicious
    return (imports.size() > 0 && loaderAPIs >= static_cast<int>(imports.size()) * 0.6);
}

bool HeuristicAnalyzer::HasLoaderPattern(const std::vector<std::string>& imports) {
    // Minimal import pattern: only LoadLibrary + GetProcAddress
    if (imports.size() > 5) return false;

    bool hasLoadLibrary = false;
    bool hasGetProcAddress = false;

    for (const auto& imp : imports) {
        if (imp.find("LoadLibrary") != std::string::npos) hasLoadLibrary = true;
        if (imp.find("GetProcAddress") != std::string::npos) hasGetProcAddress = true;
    }

    return hasLoadLibrary && hasGetProcAddress;
}

HeuristicAnalysis HeuristicAnalyzer::Analyze(
    const std::vector<uint8_t>& fileData,
    const std::vector<std::string>& sections,
    int importCount,
    const std::vector<std::string>& imports)
{
    HeuristicAnalysis result = {};

    // Calculate overall entropy (simplified - would need PE parsing for accurate section entropy)
    result.codeEntropy = CalculateEntropy(fileData.data(), std::min(fileData.size(), size_t(10000)));
    result.dataEntropy = result.codeEntropy;  // Simplified

    result.importCount = importCount;
    result.exportCount = 0;  // Would need export parsing
    result.sectionCount = static_cast<int>(sections.size());

    // Analyze indicators
    result.hasHighEntropy = (result.codeEntropy > m_entropyThreshold);
    result.hasFewImports = (importCount < m_importThreshold);
    result.hasSuspiciousImports = HasSuspiciousImports(imports);
    result.hasWeirdSections = (sections.size() < 2 || sections.size() > 20);
    result.hasOverlay = false;  // Would need file size analysis
    result.hasSizeDiscrepancy = false;  // Would need section size analysis
    result.hasUnusualEntryPoint = false;  // Would need entry point analysis

    // Calculate suspicion score
    result.suspicionScore = 0;

    if (result.hasHighEntropy) result.suspicionScore += 35;
    if (result.hasFewImports) result.suspicionScore += 20;
    if (result.hasSuspiciousImports) result.suspicionScore += 25;
    if (result.hasWeirdSections) result.suspicionScore += 10;
    if (HasLoaderPattern(imports)) result.suspicionScore += 15;

    result.suspicionScore = std::min(result.suspicionScore, 100);

    return result;
}

// ============================================================================
// PackerDetector Implementation
// ============================================================================

PackerDetector::PackerDetector() {
}

PackerDetector::~PackerDetector() {
}

bool PackerDetector::Initialize(const std::string& signaturePath) {
    if (!signaturePath.empty()) {
        return m_signatureDB.LoadFromFile(signaturePath);
    }

    // Use built-in signatures
    return true;
}

PackerDetectionResult PackerDetector::QuickDetect(
    const std::vector<std::string>& sectionNames,
    const std::vector<uint8_t>& entryPointData)
{
    PackerDetectionResult result;
    result.isPacked = false;
    result.confidence = 0;
    result.detectionMethod = "signature";

    // Try signature match
    std::vector<std::string> emptyStrings;
    auto* signature = m_signatureDB.FindMatch(sectionNames, entryPointData, emptyStrings);

    if (signature) {
        result.isPacked = true;
        result.packerName = signature->name;
        result.confidence = 85;  // High confidence for signature match
        result.indicators.push_back("Section name match: " + signature->sectionNames[0]);
        result.detectionMethod = "signature";
    }

    return result;
}

PackerDetectionResult PackerDetector::Detect(
    const uint8_t* fileData,
    size_t fileSize,
    const std::vector<std::string>& sectionNames,
    int importCount,
    const std::vector<std::string>& imports)
{
    PackerDetectionResult result;
    result.isPacked = false;
    result.confidence = 0;

    // Phase 1: Signature detection
    std::vector<uint8_t> fileVec(fileData, fileData + std::min(fileSize, size_t(1024)));
    std::vector<std::string> emptyStrings;  // Would extract from file in full implementation

    auto* signature = m_signatureDB.FindMatch(sectionNames, fileVec, emptyStrings);

    if (signature && signature->name != "") {
        result.packerName = signature->name;
        result.confidence = 90;
        result.detectionMethod = "signature";
        result.isPacked = true;

        for (const auto& secName : sectionNames) {
            for (const auto& sigSecName : signature->sectionNames) {
                if (secName.find(sigSecName) != std::string::npos) {
                    result.indicators.push_back("Section: " + secName);
                }
            }
        }

        return result;
    }

    // Phase 2: Heuristic analysis
    HeuristicAnalysis heur = m_heuristics.Analyze(fileVec, sectionNames, importCount, imports);

    if (heur.suspicionScore >= 50) {
        result.isPacked = true;
        result.packerName = "Unknown Packer";
        result.confidence = heur.suspicionScore;
        result.detectionMethod = "heuristic";

        if (heur.hasHighEntropy) {
            result.indicators.push_back("High entropy: " + std::to_string(heur.codeEntropy));
        }
        if (heur.hasFewImports) {
            result.indicators.push_back("Few imports: " + std::to_string(importCount));
        }
        if (heur.hasSuspiciousImports) {
            result.indicators.push_back("Suspicious import pattern");
        }
    }

    return result;
}

PackerDetectionResult PackerDetector::CombineResults(
    const PackerDetectionResult& sigResult,
    const HeuristicAnalysis& heurResult)
{
    PackerDetectionResult combined = sigResult;

    // Boost confidence if heuristics agree
    if (sigResult.isPacked && heurResult.suspicionScore >= 50) {
        combined.confidence = std::min(95, combined.confidence + 10);
        combined.detectionMethod = "combined";
    }

    return combined;
}

} // namespace Scylla
