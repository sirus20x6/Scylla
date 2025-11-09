/*
 * Scylla Packer Detection System
 *
 * Hybrid approach combining:
 * - Signature-based detection (fast, accurate for known packers)
 * - Heuristic analysis (catches unknown/modified packers)
 */

#pragma once

#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <cstdint>

namespace Scylla {

// Packer detection result
struct PackerDetectionResult {
    std::string packerName;
    std::string packerVersion;
    int confidence;  // 0-100
    std::string detectionMethod;  // "signature", "heuristic", "combined"
    std::vector<std::string> indicators;  // Why we think it's this packer
    bool isPacked;
};

// Packer signature
struct PackerSignature {
    std::string name;
    std::vector<std::string> sectionNames;
    std::vector<std::string> stringSignatures;
    std::vector<uint8_t> entryPointPattern;
    std::vector<uint8_t> entryPointMask;  // 0xFF = must match, 0x00 = wildcard
    double minEntropy;
    double maxEntropy;
    int minImportCount;
    int maxImportCount;
    std::vector<std::string> commonImports;  // LoadLibraryA, GetProcAddress, etc.
    std::unordered_map<std::string, std::string> versions;  // Version-specific patterns
};

// Heuristic analysis results
struct HeuristicAnalysis {
    double codeEntropy;
    double dataEntropy;
    int importCount;
    int exportCount;
    int sectionCount;
    bool hasHighEntropy;
    bool hasFewImports;
    bool hasSuspiciousImports;
    bool hasWeirdSections;
    bool hasOverlay;
    bool hasSizeDiscrepancy;
    bool hasUnusualEntryPoint;
    int suspicionScore;  // 0-100
};

/*
 * Signature Database
 *
 * Manages packer signatures loaded from JSON
 */
class SignatureDatabase {
public:
    SignatureDatabase();
    ~SignatureDatabase();

    // Load signatures from JSON file
    bool LoadFromFile(const std::string& jsonPath);

    // Load built-in signatures
    void LoadBuiltinSignatures();

    // Find matching signature
    PackerSignature* FindMatch(
        const std::vector<std::string>& sectionNames,
        const std::vector<uint8_t>& entryPointData,
        const std::vector<std::string>& strings
    );

    // Get all signatures
    const std::vector<PackerSignature>& GetSignatures() const { return m_signatures; }

    // Add custom signature
    void AddSignature(const PackerSignature& signature);

private:
    std::vector<PackerSignature> m_signatures;

    void AddUPX();
    void AddVMProtect();
    void AddThemida();
    void AddASPack();
    void AddPECompact();
    void AddArmadillo();
    void AddEnigma();
    void AddObsidium();
    void AddMPRESS();
    void AddPEtite();
};

/*
 * Heuristic Analyzer
 *
 * Detects packing through behavioral analysis
 */
class HeuristicAnalyzer {
public:
    HeuristicAnalyzer();

    // Analyze PE file for packing indicators
    HeuristicAnalysis Analyze(
        const std::vector<uint8_t>& fileData,
        const std::vector<std::string>& sections,
        int importCount,
        const std::vector<std::string>& imports
    );

    // Calculate entropy of data
    static double CalculateEntropy(const uint8_t* data, size_t size);

    // Set thresholds
    void SetEntropyThreshold(double threshold) { m_entropyThreshold = threshold; }
    void SetImportThreshold(int threshold) { m_importThreshold = threshold; }

private:
    double m_entropyThreshold;
    int m_importThreshold;

    bool HasSuspiciousImports(const std::vector<std::string>& imports);
    bool HasLoaderPattern(const std::vector<std::string>& imports);
    double CalculateSectionEntropy(const uint8_t* data, size_t offset, size_t size);
};

/*
 * Packer Detector
 *
 * Main detection engine combining signatures and heuristics
 */
class PackerDetector {
public:
    PackerDetector();
    ~PackerDetector();

    // Initialize with signature database
    bool Initialize(const std::string& signaturePath = "");

    // Detect packer in PE file
    PackerDetectionResult Detect(
        const uint8_t* fileData,
        size_t fileSize,
        const std::vector<std::string>& sectionNames,
        int importCount,
        const std::vector<std::string>& imports
    );

    // Quick detection (signature only)
    PackerDetectionResult QuickDetect(
        const std::vector<std::string>& sectionNames,
        const std::vector<uint8_t>& entryPointData
    );

    // Get signature database
    SignatureDatabase& GetSignatureDatabase() { return m_signatureDB; }

    // Get heuristic analyzer
    HeuristicAnalyzer& GetHeuristicAnalyzer() { return m_heuristics; }

private:
    SignatureDatabase m_signatureDB;
    HeuristicAnalyzer m_heuristics;

    PackerDetectionResult CombineResults(
        const PackerDetectionResult& sigResult,
        const HeuristicAnalysis& heurResult
    );

    int CalculateConfidence(
        const PackerSignature& signature,
        int matchCount,
        const HeuristicAnalysis& heuristics
    );
};

} // namespace Scylla
