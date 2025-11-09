/*
 * Scylla Security Analysis Module
 *
 * Detects and analyzes security mitigations in PE files
 */

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <filesystem>
#include <map>

namespace Scylla {
namespace Security {

/*
 * Security mitigation flags
 */
struct SecurityMitigations {
    // DEP (Data Execution Prevention)
    bool depEnabled;
    bool depPermanent;
    std::string depMode;  // "Always On", "Opt In", "Opt Out", "Off"

    // ASLR (Address Space Layout Randomization)
    bool aslrEnabled;
    bool highEntropyVA;          // 64-bit ASLR
    bool dynamicBaseEnabled;     // Can be relocated
    bool forceIntegrity;         // Force integrity checks

    // Control Flow Guard (CFG)
    bool cfgEnabled;
    bool cfgInstrumented;        // Has CFG checks
    bool cfgFunctionTable;       // Has CFG function table

    // Safe SEH (Structured Exception Handling)
    bool safeSEH;
    bool sehTablePresent;
    size_t sehHandlerCount;

    // Stack protection
    bool gsEnabled;              // /GS buffer security checks
    bool stackCookiePresent;

    // Code signing
    bool authenticodePresent;
    bool signatureValid;
    std::string signerName;
    std::string signatureAlgorithm;

    // Additional mitigations
    bool noSEH;                  // IMAGE_DLLCHARACTERISTICS_NO_SEH
    bool noBindFlag;             // IMAGE_DLLCHARACTERISTICS_NO_BIND
    bool wdmDriver;              // WDM driver
    bool terminalServerAware;
    bool stripDebugInfo;

    // Advanced features (Windows 10+)
    bool cetCompatible;          // Control-flow Enforcement Technology
    bool guardRF;                // Return Flow Guard
    bool retpolinePresent;       // Retpoline mitigation
};

/*
 * Security assessment result
 */
struct SecurityAssessment {
    SecurityMitigations mitigations;

    // Overall security score (0-100)
    int securityScore;

    // Risk level
    enum class RiskLevel {
        Critical,    // No protections
        High,        // Minimal protections
        Medium,      // Some protections
        Low,         // Good protections
        Minimal      // Excellent protections
    };
    RiskLevel riskLevel;

    // Detailed findings
    std::vector<std::string> strengths;
    std::vector<std::string> weaknesses;
    std::vector<std::string> recommendations;

    // Compliance
    std::map<std::string, bool> compliance;  // e.g., "Microsoft SDL" -> true/false
};

/*
 * Certificate information
 */
struct CertificateInfo {
    std::string subjectName;
    std::string issuerName;
    std::string serialNumber;
    std::string thumbprint;
    std::string signatureAlgorithm;
    std::string digestAlgorithm;
    std::string validFrom;
    std::string validTo;
    bool isValid;
    bool isTrusted;
    bool isExpired;
    bool isRevoked;
    std::vector<std::string> chain;  // Certificate chain
};

/*
 * Security Analyzer
 *
 * Analyzes PE files for security mitigations
 */
class SecurityAnalyzer {
public:
    SecurityAnalyzer();
    ~SecurityAnalyzer();

    // Analyze PE file
    SecurityAssessment Analyze(const std::filesystem::path& filePath);

    // Individual checks
    bool CheckDEP(const std::filesystem::path& filePath);
    bool CheckASLR(const std::filesystem::path& filePath);
    bool CheckCFG(const std::filesystem::path& filePath);
    bool CheckSafeSEH(const std::filesystem::path& filePath);
    bool CheckGS(const std::filesystem::path& filePath);

    // Code signing
    CertificateInfo AnalyzeCertificate(const std::filesystem::path& filePath);
    bool VerifySignature(const std::filesystem::path& filePath);

    // Scoring
    int CalculateSecurityScore(const SecurityMitigations& mitigations);
    SecurityAssessment::RiskLevel AssessRiskLevel(int score);

    // Recommendations
    std::vector<std::string> GenerateRecommendations(const SecurityMitigations& mitigations);

private:
    // PE parsing helpers
    struct PEInfo {
        bool is64Bit;
        uint16_t dllCharacteristics;
        uint32_t loadConfigRVA;
        uint32_t loadConfigSize;
        uint32_t securityDirRVA;
        uint32_t securityDirSize;
        uint32_t exceptionDirRVA;
        uint32_t exceptionDirSize;
    };

    PEInfo ParsePEHeaders(const std::filesystem::path& filePath);

    // DLL Characteristics flags
    bool HasDLLCharacteristic(uint16_t characteristics, uint16_t flag);

    // Load Config parsing
    struct LoadConfigInfo {
        uint32_t guardCFCheckFunctionPointer;
        uint32_t guardCFFunctionTable;
        uint32_t guardCFFunctionCount;
        uint32_t guardFlags;
        uint32_t sehHandlerTable;
        uint32_t sehHandlerCount;
        uint64_t securityCookie;
    };

    LoadConfigInfo ParseLoadConfig(const std::filesystem::path& filePath,
                                   const PEInfo& peInfo);

    // SEH analysis
    std::vector<uint32_t> ParseSEHTable(const std::filesystem::path& filePath,
                                        const LoadConfigInfo& loadConfig);

    // Certificate validation
    bool ValidateCertificateChain(const CertificateInfo& cert);
    bool CheckCertificateRevocation(const CertificateInfo& cert);

    // Compliance checking
    bool CheckMicrosoftSDL(const SecurityMitigations& mitigations);
    bool CheckCIS(const SecurityMitigations& mitigations);  // CIS Benchmarks
};

/*
 * Security Comparer
 *
 * Compare security postures of multiple files
 */
class SecurityComparer {
public:
    struct ComparisonResult {
        std::vector<std::filesystem::path> files;
        std::vector<SecurityAssessment> assessments;

        // Comparative analysis
        std::string mostSecure;
        std::string leastSecure;
        std::vector<std::string> commonWeaknesses;
        std::vector<std::string> commonStrengths;
    };

    ComparisonResult Compare(const std::vector<std::filesystem::path>& files);

    // Difference analysis
    struct SecurityDiff {
        std::vector<std::string> added;      // Mitigations in B but not A
        std::vector<std::string> removed;    // Mitigations in A but not B
        std::vector<std::string> common;     // Mitigations in both
        int scoreDifference;
    };

    SecurityDiff ComputeDifference(const SecurityAssessment& a,
                                   const SecurityAssessment& b);
};

/*
 * Security Report Generator
 */
class SecurityReportGenerator {
public:
    // Generate detailed report
    void GenerateReport(const SecurityAssessment& assessment,
                       const std::filesystem::path& outputPath,
                       const std::string& format = "text");

    // Report formats
    void GenerateTextReport(const SecurityAssessment& assessment, std::ostream& out);
    void GenerateJSONReport(const SecurityAssessment& assessment, std::ostream& out);
    void GenerateHTMLReport(const SecurityAssessment& assessment, std::ostream& out);

    // Summary
    void GenerateSummary(const SecurityAssessment& assessment, std::ostream& out);

    // Compliance report
    void GenerateComplianceReport(const SecurityAssessment& assessment,
                                 const std::string& standard,
                                 std::ostream& out);
};

/*
 * Mitigation Checker
 *
 * Check for specific exploit mitigations
 */
class MitigationChecker {
public:
    // Modern mitigations (Windows 10+)
    struct ModernMitigations {
        bool arbitraryCodeGuard;     // ACG
        bool blockNonSystemFonts;
        bool blockRemoteImages;
        bool blockLowIntegrity;
        bool codeIntegrityGuard;
        bool disableExtensionPoints;
        bool disableWin32kCalls;
        bool exportAddressFilter;    // EAF
        bool importAddressFilter;    // IAF
        bool prohibitDynamicCode;
        bool validateAPIInvocation;
        bool validateStackIntegrity;
    };

    ModernMitigations CheckModernMitigations(const std::filesystem::path& filePath);

    // Exploit mitigation effectiveness
    struct ExploitResistance {
        double bufferOverflowResistance;   // 0.0-1.0
        double ropResistance;               // Return-Oriented Programming
        double jopResistance;               // Jump-Oriented Programming
        double heapSprayResistance;
        double useAfterFreeResistance;
    };

    ExploitResistance AssessExploitResistance(const SecurityMitigations& mitigations);

    // Check for known bypass techniques
    std::vector<std::string> CheckKnownBypasses(const SecurityMitigations& mitigations);
};

} // namespace Security
} // namespace Scylla
